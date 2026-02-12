"""
XRPL conditional escrow: create EscrowCreate with PREIMAGE-SHA256 condition.
Follows: https://xrpl.org/docs/tutorials/how-tos/use-specialized-payment-types/use-escrows/send-a-conditional-escrow
Uses cryptoconditions.PreimageSha256 (same as XRPL Python tutorial).
Uses xrpl-py async API; call from async route handlers.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from os import urandom
from typing import Any

from cryptoconditions import PreimageSha256
from xrpl.asyncio.transaction import submit_and_wait
from xrpl.asyncio.transaction import XRPLReliableSubmissionException
from xrpl.models.requests import AccountInfo
from xrpl.models.transactions import EscrowCreate, EscrowFinish
from xrpl.utils import datetime_to_ripple_time

from server.dependencies import xrpl_async_client, xrpl_issuer_wallet
from server.services.xrpl_sbt import is_valid_xrpl_address

logger = logging.getLogger(__name__)


def _error_result(message: str) -> dict[str, Any]:
    return {"tx_hash": None, "offer_sequence": None, "condition": None, "fulfillment": None, "error": message}


def _generate_condition_fulfillment() -> tuple[str, str]:
    """
    Generate PREIMAGE-SHA256 condition and fulfillment (hex) for XRPL conditional escrow.
    Uses cryptoconditions.PreimageSha256 (same as XRPL tutorial).
    Returns (condition_hex, fulfillment_hex).
    """
    preimage = urandom(32)
    fulfillment = PreimageSha256(preimage=preimage)
    condition_hex = fulfillment.condition_binary.hex().upper()
    fulfillment_hex = fulfillment.serialize_binary().hex().upper()
    return condition_hex, fulfillment_hex


def prepare_conditional_escrow(
    destination: str,
    amount_drops: str,
    cancel_after_seconds: int = 86400 * 30,
    finish_after_seconds: int | None = None,
) -> dict[str, Any]:
    """
    Prepare a conditional escrow: generate condition and fulfillment only (no ledger submit).
    Client will build/sign/submit EscrowCreate; server stores fulfillment for later EscrowFinish.

    Returns:
        Dict with: condition, fulfillment, cancel_after (ripple time), finish_after (optional), destination, amount_drops, error.
    """
    if not is_valid_xrpl_address(destination):
        return _error_result("Invalid XRPL destination address")
    try:
        amount_int = int(amount_drops, 10)
        if amount_int <= 0:
            return _error_result("amount_drops must be a positive integer")
    except (TypeError, ValueError):
        return _error_result("amount_drops must be a string of integer drops")
    if cancel_after_seconds < 60:
        return _error_result("cancel_after_seconds must be at least 60")

    condition_hex, fulfillment_hex = _generate_condition_fulfillment()
    now = datetime.now(timezone.utc)
    cancel_after = datetime_to_ripple_time(now + timedelta(seconds=cancel_after_seconds))
    finish_after = None
    if finish_after_seconds is not None and finish_after_seconds >= 0:
        finish_after = datetime_to_ripple_time(now + timedelta(seconds=finish_after_seconds))

    return {
        "condition": condition_hex,
        "fulfillment": fulfillment_hex,
        "cancel_after": cancel_after,
        "finish_after": finish_after,
        "destination": destination,
        "amount_drops": str(amount_drops).strip(),
        "error": None,
    }


async def create_conditional_escrow(
    destination: str,
    amount_drops: str,
    cancel_after_seconds: int = 86400 * 30,
    finish_after_seconds: int | None = None,
) -> dict[str, Any]:
    """
    Create a conditional (PREIMAGE-SHA256) escrow on XRPL.
    Uses xrpl_async_client and xrpl_issuer_wallet from dependencies.

    Args:
        destination: XRPL classic or X-address to receive escrowed funds.
        amount_drops: Amount in drops (string, e.g. "1000000" for 1 XRP).
        cancel_after_seconds: Seconds from now when escrow expires (mandatory for conditional).
        finish_after_seconds: Optional seconds from now before escrow can be finished (can be 0 or None).

    Returns:
        Dict with keys: tx_hash, offer_sequence, condition, fulfillment, error.
        On success error is None. On failure error is set and other keys may be None.
    """
    if not is_valid_xrpl_address(destination):
        return _error_result("Invalid XRPL destination address")

    try:
        amount_int = int(amount_drops, 10)
        if amount_int <= 0:
            return _error_result("amount_drops must be a positive integer")
    except (TypeError, ValueError):
        return _error_result("amount_drops must be a string of integer drops")

    condition_hex, fulfillment_hex = _generate_condition_fulfillment()
    now = datetime.now(timezone.utc)
    cancel_after = datetime_to_ripple_time(now + timedelta(seconds=cancel_after_seconds))
    finish_after = None
    if finish_after_seconds is not None:
        finish_after = datetime_to_ripple_time(now + timedelta(seconds=finish_after_seconds))

    account = getattr(xrpl_issuer_wallet, "classic_address", str(xrpl_issuer_wallet))

    # Obtain the account's next sequence for EscrowFinish (tutorial: "record the sequence number when you create the escrow").
    account_info = await xrpl_async_client.request(AccountInfo(account=account, ledger_index="validated"))
    result = getattr(account_info, "result", None) or (account_info if isinstance(account_info, dict) else {}).get("result", {})
    account_data = result.get("account_data", {})
    next_sequence = int(account_data.get("Sequence", 0))

    logger.info(
        "XRPL create_conditional_escrow: submitting EscrowCreate",
        extra={"account": account, "destination": destination, "amount_drops": amount_drops, "offer_sequence": next_sequence},
    )

    tx_kw: dict = {
        "account": account,
        "amount": amount_drops,
        "destination": destination,
        "cancel_after": cancel_after,
        "condition": condition_hex,
    }
    if finish_after is not None:
        tx_kw["finish_after"] = finish_after
    tx = EscrowCreate(**tx_kw)

    try:
        response = await submit_and_wait(tx, xrpl_async_client, xrpl_issuer_wallet)
    except XRPLReliableSubmissionException as e:
        err_msg = str(e)
        logger.error(
            "XRPL create_conditional_escrow: submit exception",
            extra={"destination": destination, "error": err_msg},
        )
        return _error_result(f"Submit failed: {err_msg}")
    except Exception as e:
        logger.exception("XRPL create_conditional_escrow: unexpected error")
        return _error_result(str(e))

    if not response.is_successful():
        raw = (
            response.result.get("error_message")
            or response.result.get("engine_result")
            or "Transaction failed"
        )
        logger.error(
            "XRPL create_conditional_escrow: transaction not successful",
            extra={"destination": destination, "result": raw},
        )
        return _error_result(raw)

    tx_hash = response.result.get("hash")
    # Use the sequence we recorded before submit; it's the EscrowCreate transaction's sequence (OfferSequence for EscrowFinish).
    offer_sequence = response.result.get("Sequence")
    if offer_sequence is None:
        offer_sequence = next_sequence

    logger.info(
        "XRPL create_conditional_escrow: succeeded",
        extra={"tx_hash": tx_hash, "destination": destination, "offer_sequence": offer_sequence},
    )
    return {
        "tx_hash": tx_hash,
        "offer_sequence": str(offer_sequence),
        "condition": condition_hex,
        "fulfillment": fulfillment_hex,
        "error": None,
    }


async def finish_conditional_escrow(
    owner: str,
    offer_sequence: str,
    condition_hex: str,
    fulfillment_hex: str,
) -> dict[str, Any]:
    """
    Submit EscrowFinish to release a conditional escrow.
    Uses xrpl_async_client and xrpl_issuer_wallet from dependencies.

    Returns:
        Dict with keys: tx_hash, error. On success error is None.
    """
    if not is_valid_xrpl_address(owner):
        return {"tx_hash": None, "error": "Invalid owner address"}

    try:
        seq = int(offer_sequence, 10)
        if seq <= 0:
            return {"tx_hash": None, "error": "Invalid offer_sequence"}
    except (TypeError, ValueError):
        return {"tx_hash": None, "error": "offer_sequence must be an integer string"}

    if not condition_hex or not fulfillment_hex:
        return {"tx_hash": None, "error": "condition and fulfillment are required"}

    account = getattr(xrpl_issuer_wallet, "classic_address", str(xrpl_issuer_wallet))
    logger.info(
        "XRPL finish_conditional_escrow: submitting EscrowFinish",
        extra={"owner": owner, "offer_sequence": offer_sequence},
    )

    finish_tx = EscrowFinish(
        account=account,
        owner=owner,
        offer_sequence=seq,
        condition=condition_hex,
        fulfillment=fulfillment_hex,
    )

    try:
        response = await submit_and_wait(finish_tx, xrpl_async_client, xrpl_issuer_wallet)
    except XRPLReliableSubmissionException as e:
        err_msg = str(e)
        logger.error(
            "XRPL finish_conditional_escrow: submit exception",
            extra={"owner": owner, "error": err_msg},
        )
        return {"tx_hash": None, "error": f"Submit failed: {err_msg}"}
    except Exception as e:
        logger.exception("XRPL finish_conditional_escrow: unexpected error")
        return {"tx_hash": None, "error": str(e)}

    if not response.is_successful():
        raw = (
            response.result.get("error_message")
            or response.result.get("engine_result")
            or "Transaction failed"
        )
        logger.error(
            "XRPL finish_conditional_escrow: transaction not successful",
            extra={"owner": owner, "result": raw},
        )
        return {"tx_hash": None, "error": raw}

    tx_hash = response.result.get("hash")
    logger.info(
        "XRPL finish_conditional_escrow: succeeded",
        extra={"tx_hash": tx_hash, "owner": owner},
    )
    return {"tx_hash": tx_hash, "error": None}
