"""
XRPL multi-signed transaction submission.
Submit a fully-signed tx (with Signers array and SigningPubKey "") via submit_multisigned.
Uses xrpl-py models: converts the plain dict to a Transaction model via from_xrpl(),
then submits with SubmitMultisigned request through xrpl_async_client.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any

from xrpl.models.requests import SubmitMultisigned
from xrpl.models.transactions import Transaction

from server.dependencies import xrpl_async_client

logger = logging.getLogger(__name__)

_EMPTY: dict[str, Any] = {"tx_hash": None, "error": None, "engine_result": None, "engine_result_message": None}


async def submit_multisigned_tx(tx_json: dict[str, Any]) -> dict[str, Any]:
    """
    Submit a multi-signed transaction to the XRPL via submit_multisigned.
    tx_json must contain SigningPubKey "" and a Signers array with enough weight for quorum.

    Returns:
        Dict with keys: tx_hash (or None), error (or None), engine_result, engine_result_message.
    """
    if not tx_json or not isinstance(tx_json, dict):
        return {**_EMPTY, "error": "tx_json is required"}
    if tx_json.get("SigningPubKey") != "" and tx_json.get("SigningPubKey") is not None:
        return {**_EMPTY, "error": "Multi-signed tx must have SigningPubKey empty"}
    signers = tx_json.get("Signers") or []
    if not signers:
        return {**_EMPTY, "error": "Signers array is required"}

    # Convert the plain dict (XRPL wire format / PascalCase) to an xrpl-py Transaction model.
    try:
        tx_model = Transaction.from_xrpl(tx_json)
    except Exception as e:
        logger.error("submit_multisigned: failed to parse tx_json into Transaction model: %s", e)
        return {**_EMPTY, "error": f"Failed to parse tx_json: {e}"}

    logger.info(
        "submit_multisigned: tx_json before submit: %s",
        tx_json,
    )

    try:
        req = SubmitMultisigned(tx_json=tx_model)
        response = await xrpl_async_client.request(req)
    except Exception as e:
        logger.error("submit_multisigned request failed: %s", e)
        return {**_EMPTY, "error": str(e)}

    result = getattr(response, "result", None)
    if result is None and isinstance(response, dict):
        result = response.get("result")
    if not result:
        return {**_EMPTY, "error": "No result from submit_multisigned"}

    # Support both dict and object-style result (e.g. xrpl-py response)
    def _get(obj, key: str, default=None):
        if obj is None:
            return default
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    # Result may be an error payload (error, error_code, error_message, request) instead of success (engine_result, tx_json, hash)
    rpl_error = _get(result, "error")
    rpl_error_message = _get(result, "error_message")
    if rpl_error or rpl_error_message:
        err_msg = rpl_error_message or str(rpl_error) or "Unknown RPC error"
        logger.error("submit_multisigned RPC error: %s (error=%s)", err_msg, rpl_error)
        return {**_EMPTY, "error": err_msg}

    engine_result = _get(result, "engine_result") or _get(result, "result")
    engine_result_message = _get(result, "engine_result_message") or ""
    tx_json_result = _get(result, "tx_json")
    tx_hash = _get(result, "hash") or (_get(tx_json_result, "hash") if tx_json_result is not None else None)
    tx_blob = _get(result, "tx_blob")

    if engine_result and engine_result != "tesSUCCESS" and "tesSUCCESS" not in str(engine_result):
        logger.error("submit_multisigned not success: %s %s", engine_result, engine_result_message)
        return {"tx_hash": tx_hash, "error": engine_result_message or engine_result, "engine_result": engine_result, "engine_result_message": engine_result_message}

    if not tx_hash and tx_blob:
        try:
            # XRPL transaction ID = first 32 bytes of SHA-512(tx_blob), hex
            blob_bytes = bytes.fromhex(tx_blob)
            tx_hash = hashlib.sha512(blob_bytes).digest()[:32].hex().upper()
        except Exception as e:
            logger.error("submit_multisigned: could not derive hash from tx_blob: %s", e)

    if not tx_hash:
        logger.error("submit_multisigned: no tx hash in result; result keys=%s", list(result.keys()) if isinstance(result, dict) else "n/a")
        return {"tx_hash": None, "error": "Submit succeeded but no transaction hash returned", "engine_result": engine_result, "engine_result_message": engine_result_message}

    return {"tx_hash": tx_hash, "error": None, "engine_result": engine_result, "engine_result_message": engine_result_message}
