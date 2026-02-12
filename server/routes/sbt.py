import base64
import logging
import os
import secrets
import uuid

from robyn import jsonify
from robyn.robyn import Request, Response

from firebase_admin import firestore

from server.services.dashboard import build_error_geoauth_response, build_success_geoauth_response, build_exception_geoauth_response

from ..dependencies import (
    admin_account,
    contract,
    db,
    kms_helper,
    w3,
    xrpl_issuer_wallet,
    XRPL_MPT_ISSUANCE_ID,
)
from ..security import generate_jwt, jwt_required
from ..services.main import calculate_geohash_hmac, get_organization_id_from_request
from ..services import xrpl_sbt

logger = logging.getLogger(__name__)


def register_sbt_routes(app) -> None:
    """Register routes responsible for SBT issuance and retrieval."""

    @app.post("/mint-sbt")
    @jwt_required
    async def mint_sbt(request: Request):
        try:
            organization_id = get_organization_id_from_request(request)
            if not organization_id:
                return build_error_geoauth_response(request, message="No organization info")
            
            try:
                geoprecision = int(os.getenv('GEOHASH2_PRECISION', 8))
                body = request.json()
                if not body:
                    return build_error_geoauth_response(request, message="Empty request body")

            except Exception as exc:
                return build_error_geoauth_response(request, message=f"Invalid JSON format: {str(exc)}")

            required_fields = ["user_id", "nickname", "latitude", "longitude"]
            missing_fields = [field for field in required_fields if field not in body]
            if missing_fields:
                return build_error_geoauth_response(request, message="Missing required fields", data={"missing_fields": missing_fields})

            user_id = body["user_id"]
            nickname = body["nickname"]
            partner_id = body.get("partner_id", "")
            partner_user_id = body.get("partner_user_id", "")

            try:
                latitude = int(float(body["latitude"]) * (10**geoprecision))
                longitude = int(float(body["longitude"]) * (10**geoprecision))
            except (TypeError, ValueError):
                return build_error_geoauth_response(request, message="Invalid latitude/longitude format")

            salt = secrets.token_hex(16)
            secret = os.urandom(32)
            secret_str = base64.b64encode(secret).decode("utf-8")
            geo_secret = kms_helper.encrypt_secret(secret)

            try:
                location_hash = calculate_geohash_hmac(
                    latitude / (10**geoprecision),
                    longitude / (10**geoprecision),
                    salt=salt,
                    secret_key=secret,
                )
            except Exception as exc:
                return build_exception_geoauth_response(request, exc, message=f"HMAC calculation failed: {str(exc)}")

            chain = body.get("chain", "evm")

            if chain == "xrpl":
                xrpl_destination = body.get("xrpl_destination") or body.get("wallet_address")
                if not xrpl_destination:
                    return Response(
                        status_code=400,
                        description=jsonify({"error": "Missing required field for XRPL: xrpl_destination or wallet_address"}),
                        headers={"Content-Type": "application/json"},
                    )
                logger.info(
                    "XRPL mint_sbt: sending MPT",
                    extra={
                        "issuance_id": (XRPL_MPT_ISSUANCE_ID or "").strip(),
                        "issuer_address": xrpl_issuer_wallet.classic_address,
                        "destination": xrpl_destination,
                        "organization_id": organization_id,
                    },
                )
                tx_hash, err = await xrpl_sbt.send_mpt_to_user(xrpl_destination)
                if err:
                    logger.error(
                        "XRPL mint_sbt: MPT send failed",
                        extra={
                            "issuance_id": (XRPL_MPT_ISSUANCE_ID or "").strip(),
                            "destination": xrpl_destination,
                            "error": err,
                        },
                    )
                    return Response(
                        status_code=500,
                        description=jsonify({"error": f"XRPL MPT send failed: {err}"}),
                        headers={"Content-Type": "application/json"},
                    )
                logger.info(
                    "XRPL mint_sbt: MPT sent successfully",
                    extra={
                        "tx_hash": tx_hash,
                        "issuance_id": (XRPL_MPT_ISSUANCE_ID or "").strip(),
                        "destination": xrpl_destination,
                    },
                )
                try:
                    user_data = {
                        "nickname": nickname,
                        "partner_id": partner_id,
                        "organization_id": organization_id,
                        "partner_user_id": partner_user_id,
                        "updated_at": firestore.SERVER_TIMESTAMP,
                    }
                    db.collection("users").document(user_id).set(user_data, merge=True)
                    auth_data = {
                        "digital_id": tx_hash,
                        "digital_secret": salt,
                        "geo_secret": geo_secret,
                    }
                    db.collection("users").document(user_id).collection("auth_tokens").document(user_id).set(auth_data)
                    location_data = {
                        "location_hmac": location_hash,
                        "timestamp": firestore.SERVER_TIMESTAMP,
                    }
                    db.collection("users").document(user_id).collection("auth_locations").add(location_data)
                    access_token_value = generate_jwt(user_id)
                    return Response(
                        status_code=200,
                        headers={"Content-Type": "application/json"},
                        description=jsonify(
                            {
                                "status": "success",
                                "message": "SBT minted successfully",
                                "transaction_hash": tx_hash,
                                "digital_id": tx_hash,
                                "digital_secret": salt,
                                "geoauth_secret": secret_str,
                                "location_hash": location_hash,
                                "access_token": access_token_value,
                                "chain": "xrpl",
                            }
                        ),
                    )
                except Exception as exc:
                    return Response(
                        status_code=500,
                        description=jsonify({"error": f"Failed to persist or JWT: {str(exc)}"}),
                        headers={"Content-Type": "application/json"},
                    )

            try:
                nonce = w3.eth.get_transaction_count(admin_account.address)
                mint_txn = contract.functions.mint(
                    admin_account.address,
                    nickname,
                    partner_id,
                    partner_user_id,
                    location_hash,
                ).build_transaction(
                    {
                        "chainId": int(os.getenv("CHAIN_ID")),
                        "gas": 3000000,
                        "gasPrice": w3.to_wei("5", "gwei"),
                        "nonce": nonce,
                    }
                )
            except Exception as exc:
                return build_exception_geoauth_response(request, exc, message=f"Transaction build failed: {str(exc)}")

            try:
                signed_txn = admin_account.sign_transaction(mint_txn)
                tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
                tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

                if tx_receipt["status"] != 1:
                    error_msg = f"Transaction failed. Hash: {tx_hash.hex()}"
                    if "logs" in tx_receipt and tx_receipt["logs"]:
                        error_msg += f" | Logs: {tx_receipt['logs']}"

                    return build_exception_geoauth_response(request, error=None, message=error_msg)

                try:
                    mint_events = contract.events.MintSBT().process_receipt(tx_receipt)
                    if not mint_events:
                        return build_exception_geoauth_response(request, error=None, message="", data={"error": "No MintSBT event found in transaction", "logs": str(tx_receipt["logs"])})

                    mint_event = mint_events[0]
                    if "args" not in mint_event or "tokenID" not in mint_event["args"]:
                        return build_exception_geoauth_response(request, error=None, message="Invalid MintSBT event structure", data={"event_data": str(mint_event)})

                    token_id = mint_event["args"]["tokenID"]
                    if not isinstance(token_id, int) or token_id <= 0:
                        return build_exception_geoauth_response(
                            request, 
                            error=None, 
                            message="Invalid tokenID from contract event", 
                            data={"token_id": str(token_id)}
                        )
                        
                except Exception as exc:
                    return build_exception_geoauth_response(
                        request, 
                        exc, 
                        message=f"Failed to process MintSBT event: {str(exc)}", 
                        data={"exception_details": str(exc.__dict__)}
                    )

                try:
                    user_data = {
                        "nickname": nickname,
                        "partner_id": partner_id,
                        "organization_id": organization_id,
                        "partner_user_id": partner_user_id,
                        "created_at": firestore.SERVER_TIMESTAMP,
                        "updated_at": firestore.SERVER_TIMESTAMP,
                    }
                    db.collection("users").document(user_id).set(user_data, merge=True)

                    auth_data = {
                        "digital_id": str(token_id),
                        "digital_secret": salt,
                        "geo_secret": geo_secret,
                    }
                    db.collection("users").document(user_id).collection("auth_tokens").document(user_id).set(auth_data)

                    location_data = {
                        "location_hmac": location_hash,
                        "timestamp": firestore.SERVER_TIMESTAMP,
                    }
                    db.collection("users").document(user_id).collection("auth_locations").add(location_data)

                    access_token_value = generate_jwt(user_id)

                    return build_success_geoauth_response(request, data={
                                "status": "success",
                                "message": "SBT minted successfully",
                                "transaction_hash": tx_hash.hex(),
                                "digital_id": str(token_id),
                                "digital_secret": salt,
                                "geoauth_secret": secret_str,
                                "location_hash": location_hash,
                                "access_token": access_token_value,
                            })
                except Exception as exc:
                    return build_exception_geoauth_response(request, exc, message=f"Failed to generate JWT token: {str(exc)}")

            except Exception as exc:
                return build_exception_geoauth_response(request, exc, message=f"Transaction execution failed: {str(exc)}")

        except Exception as exc:
            return build_exception_geoauth_response(request, exc, message=f"Unexpected error: {str(exc)}")

    @app.post("/register-sbt")
    @jwt_required
    async def register_sbt(request: Request):
        try:
            organization_id = get_organization_id_from_request(request)
            if not organization_id:
                return build_error_geoauth_response(request, message="No organization info")

            try:
                geoprecision = int(os.getenv('GEOHASH2_PRECISION', 8))
                body = request.json()
                if not body:
                    return build_error_geoauth_response(request, message="Empty request body")

            except Exception as exc:
                return build_error_geoauth_response(request, message=f"Invalid JSON format: {str(exc)}")

            required_fields = ["nickname", "latitude", "longitude"]
            missing_fields = [field for field in required_fields if field not in body]
            if missing_fields:
                return build_error_geoauth_response(request, message="Missing required fields", data={"missing_fields": missing_fields})

            nickname = body["nickname"]
            partner_id = body.get("partner_id", "")
            partner_user_id = body.get("partner_user_id", "")

            try:
                latitude = int(float(body["latitude"]) * (10**geoprecision))
                longitude = int(float(body["longitude"]) * (10**geoprecision))
            except (TypeError, ValueError):
                return build_error_geoauth_response(request, message="Invalid latitude/longitude format")

            salt = secrets.token_hex(16)
            secret = os.urandom(32)
            secret_str = base64.b64encode(secret).decode("utf-8")
            geo_secret = kms_helper.encrypt_secret(secret)

            try:
                location_hash = calculate_geohash_hmac(
                    latitude / (10**geoprecision),
                    longitude / (10**geoprecision),
                    salt=salt,
                    secret_key=secret,
                )
            except Exception as exc:
                return build_exception_geoauth_response(request, exc)

            chain = body.get("chain", "evm")

            if chain == "xrpl":
                xrpl_destination = body.get("xrpl_destination") or body.get("wallet_address")
                if not xrpl_destination:
                    return Response(
                        status_code=400,
                        description=jsonify({"error": "Missing required field for XRPL: xrpl_destination or wallet_address"}),
                        headers={"Content-Type": "application/json"},
                    )
                logger.info(
                    "XRPL register_sbt: sending MPT",
                    extra={
                        "issuance_id": (XRPL_MPT_ISSUANCE_ID or "").strip(),
                        "issuer_address": xrpl_issuer_wallet.classic_address,
                        "destination": xrpl_destination,
                        "organization_id": organization_id,
                    },
                )
                tx_hash, err = await xrpl_sbt.send_mpt_to_user(xrpl_destination)
                if err:
                    logger.error(
                        "XRPL register_sbt: MPT send failed",
                        extra={
                            "issuance_id": (XRPL_MPT_ISSUANCE_ID or "").strip(),
                            "destination": xrpl_destination,
                            "error": err,
                        },
                    )
                    return Response(
                        status_code=500,
                        description=jsonify({"error": f"XRPL MPT send failed: {err}"}),
                        headers={"Content-Type": "application/json"},
                    )
                logger.info(
                    "XRPL register_sbt: MPT sent successfully",
                    extra={
                        "tx_hash": tx_hash,
                        "issuance_id": (XRPL_MPT_ISSUANCE_ID or "").strip(),
                        "destination": xrpl_destination,
                    },
                )

                try:
                    user_id = str(uuid.uuid4())
                    user_data = {
                        "nickname": nickname,
                        "partner_id": partner_id,
                        "organization_id": organization_id,
                        "partner_user_id": partner_user_id,
                        "created_at": firestore.SERVER_TIMESTAMP,
                        "updated_at": firestore.SERVER_TIMESTAMP,
                    }
                    # XRPL: wallet address is required; persist for audit and future use
                    user_data["xrpl_wallet_address"] = str(xrpl_destination).strip()
                    db.collection("users").document(user_id).set(user_data)
                    auth_data = {
                        "digital_id": tx_hash,
                        "digital_secret": salt,
                        "geo_secret": geo_secret,
                    }
                    db.collection("users").document(user_id).collection("auth_tokens").document(user_id).set(auth_data)
                    location_data = {
                        "location_hmac": location_hash,
                        "timestamp": firestore.SERVER_TIMESTAMP,
                    }
                    db.collection("users").document(user_id).collection("auth_locations").add(location_data)
                    access_token_value = generate_jwt(user_id)
                    return Response(
                        status_code=200,
                        headers={"Content-Type": "application/json"},
                        description=jsonify(
                            {
                                "status": "success",
                                "message": "SBT minted successfully",
                                "transaction_hash": tx_hash,
                                "user_id": user_id,
                                "digital_id": tx_hash,
                                "digital_secret": salt,
                                "geoauth_secret": secret_str,
                                "location_hash": location_hash,
                                "access_token": access_token_value,
                                "chain": "xrpl",
                            }
                        ),
                    )
                except Exception as exc:
                    return Response(
                        status_code=500,
                        description=jsonify({"error": f"Failed to persist user or JWT: {str(exc)}"}),
                        headers={"Content-Type": "application/json"},
                    )

            try:
                nonce = w3.eth.get_transaction_count(admin_account.address)
                mint_txn = contract.functions.mint(
                    admin_account.address,
                    nickname,
                    partner_id,
                    partner_user_id,
                    location_hash,
                ).build_transaction(
                    {
                        "chainId": int(os.getenv("CHAIN_ID")),
                        "gas": 3000000,
                        "gasPrice": w3.to_wei("5", "gwei"),
                        "nonce": nonce,
                    }
                )
            except Exception as exc:
                return build_exception_geoauth_response(request, error=exc)

            try:
                signed_txn = admin_account.sign_transaction(mint_txn)
                tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
                tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

                if tx_receipt["status"] != 1:
                    error_msg = f"Transaction failed. Hash: {tx_hash.hex()}"
                    if "logs" in tx_receipt and tx_receipt["logs"]:
                        error_msg += f" | Logs: {tx_receipt['logs']}"

                    return build_exception_geoauth_response(request, error=None, message=error_msg)

                try:
                    mint_events = contract.events.MintSBT().process_receipt(tx_receipt)
                    if not mint_events:
                        return build_exception_geoauth_response(request, error=None, message="No MintSBT event found in transaction", data={
                            "logs": str(tx_receipt["logs"])
                        })

                    mint_event = mint_events[0]
                    if "args" not in mint_event or "tokenID" not in mint_event["args"]:
                        return build_exception_geoauth_response(request, error=None, message="Invalid MintSBT event structure", data={
                            "event_data": str(mint_event)
                        })


                    token_id = mint_event["args"]["tokenID"]
                    if not isinstance(token_id, int) or token_id <= 0:
                        return build_exception_geoauth_response(
                            request,
                            error=None,
                            message="Invalid tokenID from contract event",
                            data={"token_id": str(token_id)},
                        )
                except Exception as exc:
                    return build_exception_geoauth_response(
                        request,
                        error=exc,
                        message="Failed to process MintSBT event",
                        data={"exception_details": str(getattr(exc, "__dict__", {}))},
                    )

                try:
                    user_id = str(uuid.uuid4())

                    user_data = {
                        "nickname": nickname,
                        "partner_id": partner_id,
                        "organization_id": organization_id,
                        "partner_user_id": partner_user_id,
                        "created_at": firestore.SERVER_TIMESTAMP,
                        "updated_at": firestore.SERVER_TIMESTAMP,
                    }
                    db.collection("users").document(user_id).set(user_data)

                    auth_data = {
                        "digital_id": str(token_id),
                        "digital_secret": salt,
                        "geo_secret": geo_secret,
                    }
                    db.collection("users").document(user_id).collection("auth_tokens").document(user_id).set(auth_data)

                    location_data = {
                        "location_hmac": location_hash,
                        "timestamp": firestore.SERVER_TIMESTAMP,
                    }
                    db.collection("users").document(user_id).collection("auth_locations").add(location_data)

                    access_token_value = generate_jwt(user_id)

                    return build_success_geoauth_response(request, data={
                                "status": "success",
                                "message": "SBT minted successfully",
                                "transaction_hash": tx_hash.hex(),
                                "user_id": user_id,
                                "digital_id": str(token_id),
                                "digital_secret": salt,
                                "geoauth_secret": secret_str,
                                "location_hash": location_hash,
                                "access_token": access_token_value,
                            })
                except Exception as exc:
                    return build_exception_geoauth_response(
                        request,
                        exc,
                        message=f"Failed to generate JWT token: {str(exc)}",
                    )

            except Exception as exc:
                return build_exception_geoauth_response(
                    request,
                    exc,
                    message=f"Transaction execution failed: {str(exc)}",
                )

        except Exception as exc:
            return build_exception_geoauth_response(
                request,
                exc,
                message=f"Unexpected error: {str(exc)}",
            )

    @app.get("/sbt-data/:user_id/:sbt_id")
    @jwt_required
    async def get_sbt_data(request: Request):
        try:
            sbt_id = request.path_params.get("sbt_id", "")
            if not sbt_id or not sbt_id.isdigit():
                return build_error_geoauth_response(request, message="Invalid sbt_id")

            token_id = int(sbt_id)
            sbt_data = contract.functions.getSBTData(token_id).call()
            return build_success_geoauth_response(request, data={
                        "nickname": sbt_data[0].hex(),
                        "risk_score": sbt_data[1],
                        "partner_id": sbt_data[2].hex(),
                        "partner_user_id": sbt_data[3].hex(),
                        "location_hash": sbt_data[4].hex(),
                        "last_updated": sbt_data[5],
                    })
        except Exception as exc:
            return build_exception_geoauth_response(request, exc)
