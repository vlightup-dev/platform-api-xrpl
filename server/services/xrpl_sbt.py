"""
XRPL MPT SBT: send 1 unit of the platform MPT (issuance ID from dependencies) to a destination address.
Uses xrpl-py async API (submit_and_wait) so it can be awaited from async route handlers.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Optional

from xrpl.asyncio.transaction import submit_and_wait

logger = logging.getLogger(__name__)
from xrpl.asyncio.transaction import XRPLReliableSubmissionException
from xrpl.models.requests import Request as XrplRequest
from xrpl.models.transactions import Payment
from xrpl.utils import encode_mptoken_metadata

from server.dependencies import XRPL_MPT_ISSUANCE_ID, xrpl_async_client, xrpl_issuer_wallet

# XRPL classic address: r + base58 (25 chars). X-address: X + base58 (47 chars).
_CLASSIC_PATTERN = re.compile(r"^r[1-9A-HJ-NP-Za-km-z]{24,33}$")
_XADDRESS_PATTERN = re.compile(r"^X[1-9A-HJ-NP-Za-km-z]{46,47}$")


def _encode_sbt_metadata_hex(issuer_name: str = "TrustAuthy") -> str:
    """XLS-89 metadata for SBT MPT. Returns hex-encoded string (compact keys)."""
    try:
        metadata = {
            "ticker": "SBT",
            "name": "Soulbound Token",
            "desc": "Platform credential token; non-transferable.",
            "icon": "https://trustauthy.example.com/sbt-icon.png",
            "asset_class": "other",
            "issuer_name": issuer_name,
        }
        return encode_mptoken_metadata(metadata)
    except ImportError:
        metadata = {
            "t": "SBT",
            "n": "Soulbound Token",
            "d": "Platform credential token; non-transferable.",
            "i": "https://trustauthy.example.com/sbt-icon.png",
            "ac": "other",
            "in": issuer_name,
        }
        json_str = json.dumps(metadata, separators=(",", ":"))
        return json_str.encode("utf-8").hex().upper()


def is_valid_xrpl_address(address: str) -> bool:
    """Return True if address looks like a valid XRPL classic or X-address."""
    if not address or not isinstance(address, str):
        return False
    return bool(_CLASSIC_PATTERN.match(address) or _XADDRESS_PATTERN.match(address))


async def account_holds_mpt_sbt(account: str) -> bool:
    """
    Return True if the given XRPL account holds at least 1 unit of the platform MPT SBT
    (XRPL_MPT_ISSUANCE_ID from dependencies). Uses xrpl_async_client and account_objects with type MPToken.
    """
    mpt_issuance_id = XRPL_MPT_ISSUANCE_ID or ""
    if not is_valid_xrpl_address(account) or not mpt_issuance_id:
        return False
    issuance_upper = str(mpt_issuance_id).strip().upper()
    try:
        req_cls = XrplRequest.get_method("account_objects")
        req = req_cls(account=account, type="mptoken", ledger_index="validated")
        resp = await xrpl_async_client.request(req)
    except Exception as e:
        logger.error(
            "account_holds_mpt_sbt: request failed for %s: type=%s repr=%s",
            account[:16],
            type(e).__name__,
            repr(e),
            exc_info=True,
        )
        return False
    logger.info("account_holds_mpt_sbt: response for %s: %s", account[:16], resp)
    result = getattr(resp, "result", resp) if not isinstance(resp, dict) else resp.get("result", resp)
    if not result:
        logger.error("account_holds_mpt_sbt: no result for %s", account[:16])
        return False
    # RPC can return error in result (e.g. actNotFound)
    if isinstance(result, dict) and result.get("error"):
        logger.info(
            "account_holds_mpt_sbt: RPC error for %s: %s",
            account[:16],
            result.get("error"),
        )
        return False
    objects = result.get("account_objects") or []
    for obj in objects:
        if obj.get("LedgerEntryType") != "MPToken":
            continue
        obj_issuance = (obj.get("MPTokenIssuanceID") or "").strip().upper()
        if obj_issuance != issuance_upper:
            continue
        try:
            amount = int(obj.get("MPTAmount") or "0", 10)
        except (TypeError, ValueError):
            amount = 0
        if amount >= 1:
            return True
    return False


async def send_mpt_to_user(destination: str) -> tuple[str, Optional[str]]:
    """
    Send 1 unit of the platform SBT MPT to the destination XRPL address.
    Uses XRPL_MPT_ISSUANCE_ID, xrpl_async_client, and xrpl_issuer_wallet from dependencies.
    """
    wallet = xrpl_issuer_wallet
    mpt_issuance_id = (XRPL_MPT_ISSUANCE_ID or "").strip()
    if not mpt_issuance_id:
        logger.error("XRPL send_mpt_to_user: issuance_id not set")
        return "", "XRPL_MPT_ISSUANCE_ID is not set"
    issuer_address = getattr(wallet, "classic_address", str(wallet))
    logger.info(
        "XRPL send_mpt_to_user: attempting Payment",
        extra={
            "issuance_id": mpt_issuance_id,
            "issuer_address": issuer_address,
            "destination": destination,
        },
    )
    if not is_valid_xrpl_address(destination):
        logger.error("XRPL send_mpt_to_user: invalid destination", extra={"destination": destination})
        return "", "Invalid XRPL destination address"
    # MPT amount: { "mpt_issuance_id": "<hex>", "value": "1" } (see xrpl.org docs for Payment tx)
    mpt_amount = {
        "mpt_issuance_id": mpt_issuance_id,
        "value": "1",
    }

    payment = Payment(
        account=wallet.classic_address,
        destination=destination,
        amount=mpt_amount,
    )
    try:
        response = await submit_and_wait(payment, xrpl_async_client, xrpl_issuer_wallet)
    except XRPLReliableSubmissionException as e:
        err_msg = str(e)
        logger.error(
            "XRPL send_mpt_to_user: submit exception",
            extra={
                "issuance_id": mpt_issuance_id,
                "destination": destination,
                "error": err_msg,
            },
        )
        if "tecNO_AUTH" in err_msg or "tecNO_AUTH" in (getattr(e, "message", "") or ""):
            return "", (
                "Destination has not authorized this MPT. "
                "The recipient must submit an MPTokenAuthorize transaction for this issuance before they can receive the SBT."
            )
        return "", f"Submit failed: {e}"
    except Exception as e:
        logger.error(
            "XRPL send_mpt_to_user: unexpected error",
            extra={"issuance_id": mpt_issuance_id, "destination": destination},
        )
        return "", str(e)

    if not response.is_successful():
        raw = response.result.get("error_message") or response.result.get("engine_result") or "Transaction failed"
        logger.error(
            "XRPL send_mpt_to_user: transaction not successful",
            extra={
                "issuance_id": mpt_issuance_id,
                "destination": destination,
                "result": raw,
            },
        )
        if raw == "tecNO_AUTH" or "tecNO_AUTH" in str(raw):
            return "", (
                "Destination has not authorized this MPT. "
                "The recipient must submit an MPTokenAuthorize transaction for this issuance before they can receive the SBT."
            )
        return "", raw

    tx_hash = response.result.get("hash")
    if not tx_hash:
        logger.error("XRPL send_mpt_to_user: no hash in response", extra={"destination": destination})
        return "", "No hash in response"
    logger.info(
        "XRPL send_mpt_to_user: Payment succeeded",
        extra={
            "tx_hash": tx_hash,
            "issuance_id": mpt_issuance_id,
            "issuer_address": issuer_address,
            "destination": destination,
        },
    )
    return tx_hash, None
