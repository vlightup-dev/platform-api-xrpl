"""
XRPL conditional escrow API (client creates transaction).
Server prepares condition/fulfillment; client builds/signs/submits EscrowCreate; server releases via EscrowFinish.
Multi-sig: request-release (return fulfillment), submit-first-signatures (store bundle), pending-releases (list), get-bundle-for-signing (location-gated), complete-release (submit Create then Finish).
"""
import json
import logging
from datetime import datetime, timedelta, timezone

from firebase_admin import firestore
from robyn.robyn import Request, Response

from server.dependencies import db, redis_client
from server.security import jwt_required, verify_hmac
from server.services import xrpl_escrow, xrpl_sbt
from server.services import xrpl_multisig
from server.services.dashboard import (
    build_error_geoauth_response,
    build_exception_geoauth_response,
    build_success_geoauth_response,
    build_unauthorized_geoauth_response,
)
from server.services.redis import (
    redis_key_prefix_escrow_destination,
    redis_key_prefix_escrow_fulfillment,
)

logger = logging.getLogger(__name__)

BUNDLE_TTL_SEC = 86400 * 30  # 30 days for pending multisig bundle


def _request_body_dict(request: Request) -> tuple[dict | None, Response | None]:
    """Parse request body to a dict. Returns (body_dict, None) or (None, error_response) if invalid."""
    try:
        raw = request.json()
    except Exception as exc:
        logger.error("escrow: request.json() failed: %s", exc)
        return None, build_error_geoauth_response(request, f"Invalid JSON: {str(exc)}")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.error("escrow: json.loads(body) failed: %s", exc)
            return None, build_error_geoauth_response(request, f"Invalid JSON: {str(exc)}")
    if not isinstance(raw, dict):
        logger.error("escrow: body is not a dict, type=%s", type(raw).__name__)
        return None, build_error_geoauth_response(request, "Request body must be a JSON object")
    return raw, None


def _parse_location_body(request: Request, body, require_owner=True):
    """Return (condition_hex, error_response) or (condition_hex, None). Validates location fields."""
    if not isinstance(body, dict):
        return None, build_error_geoauth_response(
            request, f"Location body must be a dict, got {type(body).__name__}"
        )
    owner = body.get("owner")
    condition = body.get("condition") or body.get("pending_id")
    digital_id = body.get("digital_id")
    timestamp = body.get("timestamp")
    nonce = body.get("nonce")
    location_signature = body.get("location_signature")
    required = [("condition", condition)]
    if require_owner:
        required.append(("owner", owner))
    for name, val in required:
        if not val and val != 0:
            return None, build_error_geoauth_response(request, f"Missing required field: {name}")
    for name, val in [("digital_id", digital_id), ("timestamp", timestamp), ("nonce", nonce), ("location_signature", location_signature)]:
        if not val and val != 0:
            return None, build_error_geoauth_response(request, f"Missing required field for location verification: {name}")
    ts_str = str(timestamp).strip()
    if len(ts_str) > 12 or not ts_str.isdigit():
        return None, build_error_geoauth_response(request, "timestamp must be a Unix time in seconds (numeric, up to 12 digits)")
    try:
        ts = int(ts_str)
    except (TypeError, ValueError):
        return None, build_error_geoauth_response(request, "timestamp must be an integer")
    if ts <= 0 or ts > 2147483647 * 2:
        return None, build_error_geoauth_response(request, "timestamp must be a valid Unix time in seconds")
    try:
        if not verify_hmac(f"{digital_id}:{ts}:{nonce}", str(location_signature).strip()):
            return None, build_unauthorized_geoauth_response(request, "Location verification failed")
    except ValueError as exc:
        return None, build_unauthorized_geoauth_response(request, str(exc))
    return str(condition).strip().upper(), None


def _ensure_tx_dict(tx) -> dict | None:
    """Return tx as a dict. If tx is a JSON string, parse it. Otherwise return None if not a dict."""
    if isinstance(tx, dict):
        return tx
    if isinstance(tx, str):
        try:
            parsed = json.loads(tx)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            return None
    return None


def _signer_addresses_from_tx(tx_json):
    """Return list of signer Account addresses from tx_json.Signers."""
    if not isinstance(tx_json, dict):
        tx_json = _ensure_tx_dict(tx_json) or {}
    signers = tx_json.get("Signers") or []
    out = []
    for s in signers:
        signer = s.get("Signer") if isinstance(s, dict) else None
        if signer and signer.get("Account"):
            out.append(str(signer["Account"]).strip())
    return out


def _get_user_id_and_wallet_from_request(request: Request):
    """
    Resolve user_id from request.identity and wallet address from the user doc.
    Returns (user_id, wallet_address) or (None, None) if identity missing or user has no xrpl_wallet_address.
    """
    identity = getattr(request, "identity", None)
    if not identity:
        return None, None
    user_id = getattr(identity, "user_id", None) or (getattr(identity, "claims", None) or {}).get("user_id")
    if not user_id:
        return None, None
    user_doc = db.collection("users").document(user_id).get()
    user_data = user_doc.to_dict() if user_doc.exists else {}
    wallet_address = (user_data.get("xrpl_wallet_address") or "").strip()
    return user_id, wallet_address if wallet_address else None


def register_escrow_routes(app) -> None:
    """Register XRPL escrow routes."""

    @app.get("/api/v1/xrpl")
    async def escrow_info(request: Request) -> Response:
        """No-auth check that the XRPL escrow API is available (e.g. for debugging 404s)."""
        return build_success_geoauth_response(request, data={"service": "xrpl-escrow", "status": "ok"})

    @app.post("/api/v1/xrpl/escrow/prepare")
    @jwt_required
    async def prepare_escrow(request: Request) -> Response:
        """
        Prepare a conditional escrow: return condition and params for client to build EscrowCreate.
        Client (wallet) builds/signs/submits EscrowCreate with their XRP; server stores fulfillment
        and will submit EscrowFinish after location verification.

        Body:
            destination (str): XRPL address to receive escrowed funds.
            amount_drops (str): Amount in drops (e.g. "1000000" for 1 XRP).
            cancel_after_seconds (int, optional): Seconds until escrow expires (default 30 days).
            finish_after_seconds (int, optional): Seconds before escrow can be finished (optional).

        Returns:
            condition, cancel_after, finish_after (optional), destination, amount_drops. No fulfillment.
        """
        try:
            body = request.json()
        except Exception as exc:
            return build_error_geoauth_response(request, f"Invalid JSON: {str(exc)}")
        if not body:
            return build_error_geoauth_response(request, "Empty request body")

        destination = body.get("destination") or body.get("destination_address")
        amount_drops = body.get("amount_drops") or body.get("amount")
        cancel_after_seconds = body.get("cancel_after_seconds", 86400 * 30)
        finish_after_seconds = body.get("finish_after_seconds")

        if not destination:
            return build_error_geoauth_response(request, "Missing required field: destination")
        if not amount_drops:
            return build_error_geoauth_response(request, "Missing required field: amount_drops")

        try:
            cancel_sec = int(cancel_after_seconds)
        except (TypeError, ValueError):
            return build_error_geoauth_response(request, "cancel_after_seconds must be an integer")
        finish_sec = None
        if finish_after_seconds is not None:
            try:
                finish_sec = int(finish_after_seconds)
                if finish_sec < 0:
                    finish_sec = None
            except (TypeError, ValueError):
                finish_sec = None

        result = xrpl_escrow.prepare_conditional_escrow(
            destination=destination,
            amount_drops=str(amount_drops).strip(),
            cancel_after_seconds=cancel_sec,
            finish_after_seconds=finish_sec,
        )
        if result.get("error"):
            return build_error_geoauth_response(request, result["error"])

        condition_hex = (result["condition"] or "").strip().upper()
        fulfillment_hex = result["fulfillment"]
        redis_key = f"{redis_key_prefix_escrow_fulfillment}{condition_hex}"
        dest_key = f"{redis_key_prefix_escrow_destination}{condition_hex}"
        try:
            redis_client.setex(redis_key, cancel_sec, fulfillment_hex)
            redis_client.setex(dest_key, cancel_sec, (result.get("destination") or "").strip())
        except Exception as e:
            logger.exception("Failed to store escrow fulfillment in Redis, destination=%s, error=%s", result.get("destination"), str(e))
            return build_exception_geoauth_response(request, e, "Failed to prepare escrow")

        user_id, wallet_address = _get_user_id_and_wallet_from_request(request)
        now_prepare = datetime.now(timezone.utc)
        expires_at_prepare = now_prepare + timedelta(seconds=cancel_sec)
        escrow_doc = {
            "state": "prepared",
            "condition": condition_hex,
            "destination": (result.get("destination") or "").strip(),
            "amount_drops": result["amount_drops"],
            "cancel_after": result["cancel_after"],
            "created_at": firestore.SERVER_TIMESTAMP,
            "updated_at": firestore.SERVER_TIMESTAMP,
            "expires_at": expires_at_prepare,
        }
        if result.get("finish_after") is not None:
            escrow_doc["finish_after"] = result["finish_after"]
        if user_id:
            escrow_doc["user_id"] = user_id
        # For multisig: set signer_addresses and awaiting_signer_addresses from multisig_config (owner = multisig account).
        owner_prepare = (body.get("owner") or body.get("multisig_account") or (wallet_address or "")).strip()
        if owner_prepare:
            multisig_doc = db.collection("multisig_config").document(owner_prepare).get()
            if multisig_doc.exists:
                multisig_data = multisig_doc.to_dict() or {}
                raw_signers = multisig_data.get("signer_addresses")
                signer_addresses_prepare = [str(s).strip() for s in (raw_signers if isinstance(raw_signers, list) else []) if s]
                quorum_prepare = multisig_data.get("signer_quorum")
                try:
                    quorum_prepare = int(quorum_prepare)
                except (TypeError, ValueError):
                    return build_error_geoauth_response(request, "Invalid signer_quorum")
                if signer_addresses_prepare:
                    owner_lower = owner_prepare.strip().lower()
                    # Awaiting = all signers except the multisig account (no one has signed yet).
                    awaiting_prepare = [s for s in signer_addresses_prepare if s and s.strip().lower() != owner_lower]
                    escrow_doc["owner"] = owner_prepare
                    escrow_doc["signer_addresses"] = signer_addresses_prepare
                    escrow_doc["signer_quorum"] = quorum_prepare
                    escrow_doc["awaiting_signer_addresses"] = awaiting_prepare
        try:
            db.collection("pending_escrow_bundles").document(condition_hex).set(escrow_doc, merge=True)
        except Exception as e:
            logger.error("Failed to store escrow state in Firestore: %s", e)

        payload = {
            "condition": condition_hex,
            "cancel_after": result["cancel_after"],
            "destination": result["destination"],
            "amount_drops": result["amount_drops"],
        }
        if result.get("finish_after") is not None:
            payload["finish_after"] = result["finish_after"]
        return build_success_geoauth_response(request, data=payload)


    @app.post("/api/v1/xrpl/escrow/finish")
    @jwt_required
    async def finish_escrow(request: Request) -> Response:
        """
        Release a client-created conditional escrow by submitting EscrowFinish.
        Fulfillment is looked up from server storage (set at prepare). Body: owner, offer_sequence, condition.
        """
        try:
            body = request.json()
        except Exception as exc:
            return build_error_geoauth_response(request, f"Invalid JSON: {str(exc)}")
        if not body:
            return build_error_geoauth_response(request, "Empty request body")

        owner = body.get("owner")
        offer_sequence = body.get("offer_sequence")
        condition = body.get("condition")
        digital_id = body.get("digital_id")
        timestamp = body.get("timestamp")
        nonce = body.get("nonce")
        location_signature = body.get("location_signature")

        for name, val in [("owner", owner), ("offer_sequence", offer_sequence), ("condition", condition)]:
            if not val:
                return build_error_geoauth_response(request, f"Missing required field: {name}")
        for name, val in [("digital_id", digital_id), ("timestamp", timestamp), ("nonce", nonce), ("location_signature", location_signature)]:
            if not val and val != 0:
                return build_error_geoauth_response(request, f"Missing required field for location verification: {name}")

        # timestamp must be Unix seconds (integer or numeric string), not an identifier (e.g. hex digital_id)
        ts_str = str(timestamp).strip()
        if len(ts_str) > 12 or not ts_str.isdigit():
            return build_error_geoauth_response(request, "timestamp must be a Unix time in seconds (numeric, up to 12 digits). Check that request body uses 'timestamp' for Unix time and 'digital_id' for the identifier.")

        try:
            ts = int(ts_str)
        except (TypeError, ValueError):
            return build_error_geoauth_response(request, "timestamp must be a Unix time integer (seconds)")
        if ts <= 0 or ts > 2147483647 * 2:  # sanity: not before 1970, not far future
            return build_error_geoauth_response(request, "timestamp must be a valid Unix time in seconds")
        location_sig_str = str(location_signature).strip()
        logger.info(
            "escrow/finish location verification: digital_id=%s timestamp=%s nonce=%s location_signature_from_client=%s",
            (str(digital_id)[:24] + "..." if len(str(digital_id)) > 24 else str(digital_id)),
            ts,
            nonce[:16] if nonce else "",
            location_sig_str,
        )
        try:
            if not verify_hmac(f"{digital_id}:{ts}:{nonce}", location_sig_str):
                return build_unauthorized_geoauth_response(request, "Location verification failed")
        except ValueError as exc:
            return build_unauthorized_geoauth_response(request, str(exc))

        condition_hex = str(condition).strip().upper()
        redis_key = f"{redis_key_prefix_escrow_fulfillment}{condition_hex}"
        dest_key = f"{redis_key_prefix_escrow_destination}{condition_hex}"
        fulfillment_hex = redis_client.get(redis_key)
        destination = (redis_client.get(dest_key) or "").strip()
        if not fulfillment_hex:
            return build_error_geoauth_response(request, "Escrow not found or expired. Prepare again and submit EscrowCreate first.")
        if not destination:
            return build_error_geoauth_response(request, "Escrow destination not found or expired. Prepare again and submit EscrowCreate first.")

        owner_addr = str(owner).strip()
        sender_has_sbt = await xrpl_sbt.account_holds_mpt_sbt(owner_addr)
        receiver_has_sbt = await xrpl_sbt.account_holds_mpt_sbt(destination)
        if not sender_has_sbt or not receiver_has_sbt:
            who = []
            if not sender_has_sbt:
                who.append("sender")
            if not receiver_has_sbt:
                who.append("receiver")
            return build_error_geoauth_response(request, "Sender and receiver must both hold the platform MPT SBT.", data={"missing_sbt": who})

        # Update escrow state to submitted (EscrowCreate was submitted by client; we're about to release)
        try:
            db.collection("pending_escrow_bundles").document(condition_hex).set({
                "state": "submitted",
                "owner": owner_addr,
                "offer_sequence": str(offer_sequence).strip(),
                "updated_at": firestore.SERVER_TIMESTAMP,
            }, merge=True)
        except Exception as e:
            logger.warning("Failed to update escrow state to submitted: %s", e)

        result = await xrpl_escrow.finish_conditional_escrow(
            owner=str(owner).strip(),
            offer_sequence=str(offer_sequence).strip(),
            condition_hex=condition_hex,
            fulfillment_hex=(fulfillment_hex or "").strip().upper(),
        )

        if result.get("error"):
            return build_error_geoauth_response(request, result["error"])
        try:
            redis_client.delete(redis_key)
            redis_client.delete(dest_key)
        except Exception:
            pass
        # Update escrow state to released after successful EscrowFinish
        try:
            db.collection("pending_escrow_bundles").document(condition_hex).set({
                "state": "released",
                "tx_hash_finish": result["tx_hash"],
                "updated_at": firestore.SERVER_TIMESTAMP,
            }, merge=True)
        except Exception as e:
            logger.warning("Failed to update escrow state to released: %s", e)
        return build_success_geoauth_response(request, data={"tx_hash": result["tx_hash"], "released": True})

    # --- Multi-sig: register signer set, then Signer 1 requests release and submits first signatures ---

    @app.post("/api/v1/xrpl/escrow/register-multisig")
    @jwt_required
    async def register_multisig(request: Request) -> Response:
        """
        Store multisig config (multisig account -> signer addresses and quorum) for M-of-N multi-sig.
        Body: signer_addresses (array of N addresses) and signer_quorum (M, default 2).
        Legacy: signer1_wallet_address, signer2_wallet_address, signer3_wallet_address (optional) are still accepted.
        """
        try:
            body = request.json()
        except Exception as exc:
            logger.error("register-multisig: Invalid JSON body: %s", exc)
            return build_error_geoauth_response(request, f"Invalid JSON: {str(exc)}")
        if not body:
            return build_error_geoauth_response(request, "Empty request body")
        logger.info("register-multisig: body keys=%s", list(body.keys()) if isinstance(body, dict) else type(body).__name__)
        user_id, wallet_address = _get_user_id_and_wallet_from_request(request)
        if not user_id:
            return build_error_geoauth_response(request, "User identity not found")
        if not wallet_address:
            return build_error_geoauth_response(request, "No XRPL wallet linked. Register SBT with your wallet first.")
        account = wallet_address
        wallet_log = f"{wallet_address[:6]}...{wallet_address[-4:]}" if len(wallet_address) > 12 else "***"

        signer_addresses_raw = body.get("signer_addresses") or body.get("signerAddresses")
        if isinstance(signer_addresses_raw, list) and signer_addresses_raw:
            signer_list = [str(s).strip() for s in signer_addresses_raw if s]
        elif isinstance(signer_addresses_raw, str) and signer_addresses_raw.strip():
            try:
                parsed = json.loads(signer_addresses_raw)
                signer_list = [str(s).strip() for s in (parsed if isinstance(parsed, list) else []) if s]
            except (TypeError, ValueError, json.JSONDecodeError):
                signer_list = []
        
        if not signer_list:
            return build_error_geoauth_response(request, "Provide signer_addresses (array) or signer1_wallet_address and signer2_wallet_address")

        quorum_raw = body.get("signer_quorum") or body.get("signerQuorum")
        if quorum_raw is None:
            return build_error_geoauth_response(request, "Missing required field: signer_quorum")
        try:
            signer_quorum = int(quorum_raw)
        except (TypeError, ValueError):
            signer_quorum = 2
        if signer_quorum < 1 or signer_quorum > len(signer_list):
            return build_error_geoauth_response(request, "signer_quorum must be between 1 and the number of signers")

        logger.info(
            "register-multisig: user_id=%s account=%s signer_count=%d quorum=%d",
            user_id, wallet_log, len(signer_list), signer_quorum,
        )
        try:
            db.collection("multisig_config").document(account).set({
                "signer_addresses": signer_list,
                "signer_quorum": signer_quorum,
                "updated_at": firestore.SERVER_TIMESTAMP,
            }, merge=True)
        except Exception as e:
            logger.exception("Failed to store multisig_config: %s", e)
            return build_exception_geoauth_response(request, e, "Failed to store multisig config")
        logger.info("register-multisig: success for account=%s", wallet_log)
        return build_success_geoauth_response(request, data={"status": "ok", "account": account, "signer_quorum": signer_quorum})

    @app.get("/api/v1/xrpl/escrow/multisig-signers")
    @jwt_required
    async def get_multisig_signers(request: Request) -> Response:
        """
        Return signer_addresses for a multisig org account (for wallet-connect validation).
        Query: account=<multisig_account>. JWT required.
        """
        user_id, _ = _get_user_id_and_wallet_from_request(request)
        if not user_id:
            return build_error_geoauth_response(request, "User identity not found")
        account = (request.query_params.get("account", "") or "").strip()
        if not account:
            return build_error_geoauth_response(request, "Missing required query: account")
        try:
            multisig_doc = db.collection("multisig_config").document(account).get()
        except Exception as e:
            logger.exception("multisig-signers: failed to read doc: %s", e)
            return build_exception_geoauth_response(request, e, "Failed to get multisig signers")
        if not multisig_doc.exists:
            return build_success_geoauth_response(request, data={"signer_addresses": [], "signer_quorum": 2})
        data = multisig_doc.to_dict() or {}
        raw = data.get("signer_addresses")
        signer_addresses = [str(s).strip() for s in (raw if isinstance(raw, list) else []) if s]
        signer_quorum = data.get("signer_quorum")
        try:
            signer_quorum = int(signer_quorum)
        except (TypeError, ValueError):
            return build_error_geoauth_response(request, "Invalid signer_quorum")
        return build_success_geoauth_response(request, data={"signer_addresses": signer_addresses, "signer_quorum": signer_quorum})

    @app.post("/api/v1/xrpl/escrow/request-release")
    @jwt_required
    async def request_release(request: Request) -> Response:
        """
        Multi-sig Signer 1: validate location + SBT, return fulfillment so client can build EscrowFinish.
        Body: owner, offer_sequence, condition, digital_id, timestamp, nonce, location_signature.
        """
        try:
            body = request.json()
        except Exception as exc:
            return build_error_geoauth_response(request, f"Invalid JSON: {str(exc)}")
        if not body:
            return build_error_geoauth_response(request, "Empty request body")

        condition_hex, err_resp = _parse_location_body(request, body)
        if err_resp is not None:
            return err_resp

        owner = str(body.get("owner", "")).strip()
        offer_sequence = body.get("offer_sequence")
        if not offer_sequence and offer_sequence != 0:
            return build_error_geoauth_response(request, "Missing required field: offer_sequence")
        redis_key = f"{redis_key_prefix_escrow_fulfillment}{condition_hex}"
        dest_key = f"{redis_key_prefix_escrow_destination}{condition_hex}"
        fulfillment_hex = redis_client.get(redis_key)
        destination = (redis_client.get(dest_key) or "").strip()
        if not fulfillment_hex:
            return build_error_geoauth_response(request, "Escrow not found or expired. Prepare again and submit EscrowCreate first.")
        if not destination:
            return build_error_geoauth_response(request, "Escrow destination not found or expired.")

        sender_has_sbt = await xrpl_sbt.account_holds_mpt_sbt(owner)
        receiver_has_sbt = await xrpl_sbt.account_holds_mpt_sbt(destination)
        if not sender_has_sbt or not receiver_has_sbt:
            who = ["sender"] if not sender_has_sbt else []
            if not receiver_has_sbt:
                who.append("receiver")
            return build_error_geoauth_response(request, "Sender and receiver must both hold the platform MPT SBT.", data={"missing_sbt": who})

        return build_success_geoauth_response(request, data={"fulfillment": (fulfillment_hex or "").strip().upper(), "destination": destination})

    @app.post("/api/v1/xrpl/escrow/submit-first-signatures")
    @jwt_required
    async def submit_first_signatures(request: Request) -> Response:
        """
        Multi-sig Signer 1: store escrow bundle (EscrowCreate + EscrowFinish each with 1 sig) for Signer 2.
        Body: condition, escrow_create_tx_json, escrow_finish_tx_json.
        """
        try:
            body = request.json()
        except Exception as exc:
            return build_error_geoauth_response(request, f"Invalid JSON: {str(exc)}")
        if not body:
            return build_error_geoauth_response(request, "Empty request body")

        condition = body.get("condition")
        create_tx = body.get("escrow_create_tx_json") or body.get("escrowCreateTxJson")
        finish_tx = body.get("escrow_finish_tx_json") or body.get("escrowFinishTxJson")
        if not condition:
            return build_error_geoauth_response(request, "Missing required field: condition")
        # Accept dict or JSON string (client may send decoded tx as object or string)
        if create_tx is not None and isinstance(create_tx, str):
            try:
                create_tx = json.loads(create_tx)
            except (TypeError, ValueError):
                create_tx = None
        if finish_tx is not None and isinstance(finish_tx, str):
            try:
                finish_tx = json.loads(finish_tx)
            except (TypeError, ValueError):
                finish_tx = None
        if not create_tx or not isinstance(create_tx, dict):
            return build_error_geoauth_response(request, "Missing or invalid escrow_create_tx_json")
        if not finish_tx or not isinstance(finish_tx, dict):
            return build_error_geoauth_response(request, "Missing or invalid escrow_finish_tx_json")

        signers_create = _signer_addresses_from_tx(create_tx)
        signers_finish = _signer_addresses_from_tx(finish_tx)
        if len(signers_create) != 1 or len(signers_finish) != 1:
            return build_error_geoauth_response(request, "Each tx must have exactly one signer (first signature)")

        account = (create_tx.get("Account") or finish_tx.get("Account") or "").strip()
        if not account:
            return build_error_geoauth_response(request, "Could not determine account from tx")

        condition_hex = str(condition).strip().upper()
        dest_key = f"{redis_key_prefix_escrow_destination}{condition_hex}"
        destination = (redis_client.get(dest_key) or "").strip()
        amount_drops = create_tx.get("Amount") or create_tx.get("amount_drops") or ""

        signer_1_address = (signers_create[0] if signers_create else (signers_finish[0] if signers_finish else "")).strip()
        account_lower = account.strip().lower()
        signer_1_lower = signer_1_address.lower() if signer_1_address else ""
        # Use awaiting_signer_addresses from prepare (set from multisig_config); remove first signer who just signed.
        existing_doc = db.collection("pending_escrow_bundles").document(condition_hex).get()
        existing = existing_doc.to_dict() if existing_doc.exists else {}
        existing_awaiting = existing.get("awaiting_signer_addresses")
        if isinstance(existing_awaiting, list) and existing_awaiting:
            all_signers = existing.get("signer_addresses") or existing_awaiting
            if not isinstance(all_signers, list):
                all_signers = [str(s).strip() for s in existing_awaiting if s]
            else:
                all_signers = [str(s).strip() for s in all_signers if s]
            awaiting_signer_addresses = [
                s for s in existing_awaiting
                if s and str(s).strip().lower() != signer_1_lower and str(s).strip().lower() != account_lower
            ]
            signer_quorum = existing.get("signer_quorum")
            try:
                signer_quorum = int(signer_quorum)
            except (TypeError, ValueError):
                return build_error_geoauth_response(request, "Invalid signer_quorum")
        else:
            return build_error_geoauth_response(request, "Could not determine awaiting signers: set multisig_config via register-multisig or call prepare with owner for multisig")
        if not awaiting_signer_addresses and all_signers:
            awaiting_signer_addresses = [
                s for s in all_signers
                if s and s.strip().lower() != signer_1_lower and s.strip().lower() != account_lower
            ]
        if not awaiting_signer_addresses:
            return build_error_geoauth_response(request, "Could not determine awaiting signers: set multisig_config via register-multisig or call prepare with owner for multisig")

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=BUNDLE_TTL_SEC)
        bundle_data = {
            "state": "pending_signatures",
            "signer_quorum": signer_quorum,
            "signer_1_address": signer_1_address,
            "signer_addresses": all_signers,
            "awaiting_signer_addresses": awaiting_signer_addresses,
            "destination": destination,
            "amount_drops": str(amount_drops),
            "owner": account,
            "escrow_create_tx_json": create_tx,
            "escrow_finish_tx_json": finish_tx,
            "created_at": now,
            "expires_at": expires_at,
            "updated_at": firestore.SERVER_TIMESTAMP,
        }
        try:
            db.collection("pending_escrow_bundles").document(condition_hex).set(bundle_data, merge=True)
        except Exception as e:
            logger.exception("Failed to store escrow bundle in Firestore: %s", e)
            return build_exception_geoauth_response(request, e, "Failed to store bundle")

        return build_success_geoauth_response(request, data={"pending_id": condition_hex, "status": "awaiting_second_signer"})

    @app.get("/api/v1/xrpl/escrow/pending-releases")
    @jwt_required
    async def pending_releases(request: Request) -> Response:
        """
        Multi-sig Signer 2: list pending releases. Uses optional query param account (e.g. connected GemWallet);
        if absent, uses the authenticated user's linked wallet from the user doc.
        """
        user_id, linked_wallet = _get_user_id_and_wallet_from_request(request)
        if not user_id:
            return build_error_geoauth_response(request, "User identity not found")
        account_param = (request.query_params.get("account", "") or "").strip()
        wallet_address = account_param if account_param else linked_wallet
        if not wallet_address:
            logger.info("pending-releases: user_id=%s has no xrpl_wallet_address and no account param", user_id)
            return build_success_geoauth_response(request, data={"pending": [], "error": "no_wallet_linked"})

        now = datetime.now(timezone.utc)
        pending = []
        try:
            query = (
                db.collection("pending_escrow_bundles")
                .where("state", "==", "pending_signatures")
                .where("awaiting_signer_addresses", "array_contains", wallet_address)
            )
            for doc in query.stream():
                data = doc.to_dict() or {}
                expires_at = data.get("expires_at")
                if expires_at and hasattr(expires_at, "timestamp"):
                    if expires_at.timestamp() < now.timestamp():
                        continue
                create_tx = data.get("escrow_create_tx_json") or {}
                owner = (create_tx.get("Account") or "").strip()
                signer_quorum = data.get("signer_quorum")
                if signer_quorum is None:
                    return build_error_geoauth_response(request, "Invalid signer_quorum")
                try:
                    signer_quorum = int(signer_quorum)
                except (TypeError, ValueError):
                    return build_error_geoauth_response(request, "Invalid signer_quorum")
                pending.append({
                    "pending_id": doc.id,
                    "condition": doc.id,
                    "owner": owner,
                    "destination": data.get("destination", ""),
                    "amount_drops": data.get("amount_drops", ""),
                    "signer_quorum": signer_quorum,
                    "signer_addresses": data.get("signer_addresses"),
                })
        except Exception as e:
            logger.exception("pending-releases: Firestore query failed: %s", e)
            return build_exception_geoauth_response(request, e, "Failed to list pending releases")

        logger.info("pending-releases: returning pending_count=%s for user_id=%s", len(pending), user_id)
        return build_success_geoauth_response(request, data={"pending": pending})


    @app.post("/api/v1/xrpl/escrow/get-bundle-for-signing")
    @jwt_required
    async def get_bundle_for_signing(request: Request) -> Response:
        """
        Multi-sig Signer 2: validate location, then return full bundle (tx_json) so client can sign.
        Caller's wallet is taken from the user doc (no client-supplied signer_address).
        Body: pending_id, digital_id, timestamp, nonce, location_signature.
        """
        logger.info("get_bundle_for_signing: request received")
        body, err_resp = _request_body_dict(request)
        if err_resp is not None:
            return err_resp
        if not body:
            return build_error_geoauth_response(request, "Empty request body")

        user_id, wallet_address = _get_user_id_and_wallet_from_request(request)
        logger.info("get_bundle_for_signing: user_id=%s wallet_address=%s", user_id, (wallet_address[:8] + "..." if wallet_address and len(wallet_address) > 8 else wallet_address))
        if not user_id:
            return build_error_geoauth_response(request, "User identity not found")
        if not wallet_address:
            return build_error_geoauth_response(request, "No XRPL wallet linked. Register SBT with your wallet first.")

        pending_id = (body.get("pending_id") or body.get("condition") or "").strip().upper()
        if not pending_id:
            return build_error_geoauth_response(request, "Missing required field: pending_id or condition")
        # Ensure condition field is set for location validation
        if not body.get("condition"):
            body = {**body, "condition": pending_id}

        condition_hex, err_resp = _parse_location_body(request, body, require_owner=False)
        if err_resp is not None:
            return err_resp
        if condition_hex != pending_id:
            return build_error_geoauth_response(request, "condition in location body must match pending_id")

        bundle_doc = db.collection("pending_escrow_bundles").document(pending_id).get()
        if not bundle_doc.exists:
            return build_error_geoauth_response(request, "Pending release not found or expired")
        bundle = bundle_doc.to_dict() or {}
        if bundle.get("state") != "pending_signatures":
            return build_error_geoauth_response(request, "Pending release not found or already completed")

        signer_2_address = wallet_address
        signer_1_address = (bundle.get("signer_1_address") or "").strip()
        if signer_2_address == signer_1_address:
            return build_error_geoauth_response(request, "You cannot sign again as the first signer; use a different co-signer wallet.")
        raw = bundle.get("awaiting_signer_addresses") or []
        awaiting = [str(a).strip() for a in (raw if isinstance(raw, list) else []) if a]
        if signer_2_address not in awaiting:
            return build_unauthorized_geoauth_response(request, "This pending release is not for your linked wallet")

        signer_quorum = bundle.get("signer_quorum")
        if signer_quorum is None:
            return build_error_geoauth_response(request, "signer_quorum should be set in the bundle")
        try:
            signer_quorum = int(signer_quorum)
        except (TypeError, ValueError):
            return build_error_geoauth_response(request, "Invalid signer_quorum")
        return build_success_geoauth_response(request, data={
            "escrow_create_tx_json": bundle.get("escrow_create_tx_json"),
            "escrow_finish_tx_json": bundle.get("escrow_finish_tx_json"),
            "signer_quorum": signer_quorum,
        })

    @app.post("/api/v1/xrpl/escrow/submit-additional-signatures")
    @jwt_required
    async def submit_additional_signatures(request: Request) -> Response:
        """
        M-of-N: a co-signer adds their signature to the bundle without submitting to XRPL.
        Use when current signature count + 1 < signer_quorum. When you have M signatures, call complete-release.
        Body: pending_id, digital_id, timestamp, nonce, location_signature, escrow_create_tx_json, escrow_finish_tx_json.
        """
        body, err_resp = _request_body_dict(request)
        if err_resp is not None:
            return err_resp
        if not body:
            return build_error_geoauth_response(request, "Empty request body")
        user_id, wallet_address = _get_user_id_and_wallet_from_request(request)
        if not user_id:
            return build_error_geoauth_response(request, "User identity not found")
        if not wallet_address:
            return build_error_geoauth_response(request, "No XRPL wallet linked. Register SBT with your wallet first.")
        pending_id = (body.get("pending_id") or body.get("condition") or "").strip().upper()
        if not pending_id:
            return build_error_geoauth_response(request, "Missing required field: pending_id or condition")
        if not body.get("condition"):
            body = {**body, "condition": pending_id}
        condition_hex, err_resp = _parse_location_body(request, body, require_owner=False)
        if err_resp is not None:
            return err_resp
        if condition_hex != pending_id:
            return build_error_geoauth_response(request, "pending_id must match condition")
        create_tx = _ensure_tx_dict(body.get("escrow_create_tx_json"))
        finish_tx = _ensure_tx_dict(body.get("escrow_finish_tx_json"))
        if not create_tx or not finish_tx:
            return build_error_geoauth_response(request, "Missing or invalid escrow_create_tx_json or escrow_finish_tx_json")
        bundle_doc = db.collection("pending_escrow_bundles").document(pending_id).get()
        if not bundle_doc.exists:
            return build_error_geoauth_response(request, "Pending release not found or expired")
        bundle = bundle_doc.to_dict() or {}
        if bundle.get("state") != "pending_signatures":
            return build_error_geoauth_response(request, "Pending release not found or already completed")
        raw = bundle.get("awaiting_signer_addresses") or []
        awaiting = [str(a).strip() for a in (raw if isinstance(raw, list) else []) if a]
        if wallet_address not in awaiting:
            return build_unauthorized_geoauth_response(request, "This pending release is not for your linked wallet or you have already signed")
        # Check the *stored* bundle: if caller already signed, reject duplicate. (Incoming payload includes their new sig.)
        stored_create = bundle.get("escrow_create_tx_json") or {}
        stored_finish = bundle.get("escrow_finish_tx_json") or {}
        stored_signers_create = _signer_addresses_from_tx(stored_create)
        stored_signers_finish = _signer_addresses_from_tx(stored_finish)
        wallet_lower = wallet_address.strip().lower()
        if any(s and s.strip().lower() == wallet_lower for s in stored_signers_create) or any(
            s and s.strip().lower() == wallet_lower for s in stored_signers_finish
        ):
            return build_error_geoauth_response(request, "Your signature is already in the bundle")
        signers_create = _signer_addresses_from_tx(create_tx)
        signers_finish = _signer_addresses_from_tx(finish_tx)
        if len(signers_create) < 1 or len(signers_finish) < 1:
            return build_error_geoauth_response(request, "Bundle must contain at least one existing signature")
        all_signer_addresses = bundle.get("signer_addresses") or []
        if not isinstance(all_signer_addresses, list):
            all_signer_addresses = []
        collected = list(set(signers_create) | set(signers_finish))
        awaiting_next = [a for a in all_signer_addresses if a and a not in collected]
        signer_quorum = bundle.get("signer_quorum")
        try:
            signer_quorum = int(signer_quorum)
        except (TypeError, ValueError):
            return build_error_geoauth_response(request, "Invalid signer_quorum")
        try:
            db.collection("pending_escrow_bundles").document(pending_id).set({
                "escrow_create_tx_json": create_tx,
                "escrow_finish_tx_json": finish_tx,
                "awaiting_signer_addresses": awaiting_next,
                "updated_at": firestore.SERVER_TIMESTAMP,
            }, merge=True)
        except Exception as e:
            logger.exception("submit-additional-signatures: Failed to update bundle: %s", e)
            return build_exception_geoauth_response(request, e, "Failed to store additional signatures")
        quorum_reached = len(signers_create) >= signer_quorum and len(signers_finish) >= signer_quorum
        return build_success_geoauth_response(request, data={
            "status": "additional_signatures_stored",
            "signature_count": len(signers_create),
            "signer_quorum": signer_quorum,
            "quorum_reached": quorum_reached,
        })

    @app.post("/api/v1/xrpl/escrow/complete-release")
    @jwt_required
    async def complete_release(request: Request) -> Response:
        """
        M-of-N: submit EscrowCreate then EscrowFinish when bundle has at least signer_quorum signatures.
        Body: pending_id, digital_id, timestamp, nonce, location_signature, escrow_create_tx_json, escrow_finish_tx_json.
        """
        logger.info("complete_release: request received")
        body, err_resp = _request_body_dict(request)
        if err_resp is not None:
            logger.error("complete_release: invalid body, returning error")
            return err_resp
        if not body:
            return build_error_geoauth_response(request, "Empty request body")
        pending_id_from_body = (body.get("pending_id") or body.get("condition") or "").strip().upper()
        logger.info("complete_release: pending_id=%s", pending_id_from_body)
        # _parse_location_body accepts condition from body.condition or body.pending_id
        condition_hex, err_resp = _parse_location_body(request, body, require_owner=False)
        if err_resp is not None:
            logger.error("complete_release: location verification failed")
            return err_resp

        pending_id = pending_id_from_body
        if pending_id != condition_hex:
            return build_error_geoauth_response(request, "pending_id must match condition")

        create_tx_raw = body.get("escrow_create_tx_json")
        finish_tx_raw = body.get("escrow_finish_tx_json")
        if not create_tx_raw or not finish_tx_raw:
            return build_error_geoauth_response(request, "Missing escrow_create_tx_json or escrow_finish_tx_json")
        create_tx = _ensure_tx_dict(create_tx_raw)
        finish_tx = _ensure_tx_dict(finish_tx_raw)
        if not create_tx or not finish_tx:
            return build_error_geoauth_response(
                request,
                "escrow_create_tx_json and escrow_finish_tx_json must be JSON objects (or JSON strings)",
            )

        bundle_doc = db.collection("pending_escrow_bundles").document(pending_id).get()
        if not bundle_doc.exists:
            return build_error_geoauth_response(request, "Pending release not found or expired")
        bundle = bundle_doc.to_dict() or {}
        if bundle.get("state") != "pending_signatures":
            return build_error_geoauth_response(request, "Pending release not found or already completed")

        signer_1_address = (bundle.get("signer_1_address") or "").strip()
        signer_quorum = bundle.get("signer_quorum")
        try:
            signer_quorum = int(signer_quorum)
        except (TypeError, ValueError):
            return build_error_geoauth_response(request, "Invalid signer_quorum")
        signers_create = _signer_addresses_from_tx(create_tx)
        signers_finish = _signer_addresses_from_tx(finish_tx)
        if len(signers_create) < signer_quorum or len(signers_finish) < signer_quorum:
            return build_error_geoauth_response(
                request,
                f"Both txs must have at least {signer_quorum} signature(s) (M-of-N multi-sig). Got {len(signers_create)} and {len(signers_finish)}.",
            )

        if signer_1_address and signer_1_address not in signers_create:
            return build_error_geoauth_response(request, "First signer must be one of the signers")

        # Log full tx_json for both Create and Finish before submitting
        logger.info(
            "complete_release: EscrowCreate tx_json=%s",
            json.dumps(create_tx, indent=2, default=str),
        )
        logger.info(
            "complete_release: EscrowFinish tx_json=%s",
            json.dumps(finish_tx, indent=2, default=str),
        )

        # Submit Create first, then Finish (do not delete bundle until both succeed)
        result_create = await xrpl_multisig.submit_multisigned_tx(create_tx)
        logger.info("complete_release: EscrowCreate result=%s", result_create)
        if result_create.get("error") or not result_create.get("tx_hash"):
            logger.error("complete_release: EscrowCreate submit failed pending_id=%s error=%s", pending_id, result_create.get("error"))
            return build_error_geoauth_response(request, f"EscrowCreate submit failed: {result_create.get('error') or 'No tx hash'}")

        result_finish = await xrpl_multisig.submit_multisigned_tx(finish_tx)
        logger.info("complete_release: EscrowFinish result=%s", result_finish)
        if result_finish.get("error") or not result_finish.get("tx_hash"):
            logger.error(
                "complete_release: EscrowFinish submit failed pending_id=%s tx_hash_create=%s error=%s engine_result=%s",
                pending_id,
                result_create.get("tx_hash"),
                result_finish.get("error"),
                result_finish.get("engine_result"),
            )
            return build_error_geoauth_response(
                request,
                f"EscrowFinish submit failed: {result_finish.get('error') or 'No tx hash'}. EscrowCreate already applied (tx: {result_create.get('tx_hash')}); you can retry complete release.",
            )

        owner_from_bundle = (bundle.get("escrow_create_tx_json") or {}).get("Account") or ""
        try:
            db.collection("pending_escrow_bundles").document(pending_id).set({
                "state": "submitted",
                "owner": owner_from_bundle,
                "tx_hash_create": result_create.get("tx_hash"),
                "tx_hash_finish": result_finish.get("tx_hash"),
                "updated_at": firestore.SERVER_TIMESTAMP,
            }, merge=True)
        except Exception as e:
            logger.warning("Failed to update escrow state to submitted: %s", e)

        logger.info(
            "complete_release: success pending_id=%s tx_hash_create=%s tx_hash_finish=%s",
            pending_id,
            result_create.get("tx_hash"),
            result_finish.get("tx_hash"),
        )
        return build_success_geoauth_response(request, data={
            "released": True,
            "tx_hash_create": result_create.get("tx_hash"),
            "tx_hash_finish": result_finish.get("tx_hash"),
        })
