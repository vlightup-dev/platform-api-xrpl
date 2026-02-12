#!/usr/bin/env python3
"""
Optional one-time script to create the platform SBT MPT issuance on XRPL.
Creates an MPT with flags=0: non-transferable (no tfMPTCanTransfer) and
no holder authorization required (do NOT set tfMPTRequireAuth), so recipients
can receive the SBT without submitting MPTokenAuthorize first.

Requires: XRPL_NETWORK_URL, XRPL_ISSUER_SECRET (issuer account must be funded).
Example: python scripts/create_xrpl_sbt_mpt.py .env.stg
"""
import json
import os
import sys
from xrpl.clients import JsonRpcClient
from xrpl.transaction import submit_and_wait
from xrpl.wallet import Wallet

# Add project root for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

# Optional: python create_xrpl_sbt_mpt.py [.env.stg]
_env_file = (sys.argv[1] if len(sys.argv) > 1 else None)
if _env_file and os.path.isfile(_env_file):
    load_dotenv(_env_file, override=True)
else:
    load_dotenv(override=False)

try:
    from xrpl.models.transactions import MPTokenIssuanceCreate
except ImportError:
    print("xrpl-py may not support MPTokenIssuanceCreate; need xrpl-py >= 3.0", file=sys.stderr)
    sys.exit(1)

def _xls89_metadata_hex() -> str:
    """XLS-89 compact JSON metadata for SBT MPT. Returns hex-encoded string."""
    metadata = {
        "t": "SBT",
        "n": "Soulbound Token",
        "d": "Platform credential token; non-transferable.",
        "i": "https://trustauthy.example.com/sbt-icon.png",
        "ac": "other",
        "in": os.getenv("XRPL_ISSUER_NAME", "TrustAuthy"),
    }
    json_str = json.dumps(metadata, separators=(",", ":"))
    return json_str.encode("utf-8").hex().upper()


def main() -> None:
    url = os.getenv("XRPL_NETWORK_URL")
    secret = os.getenv("XRPL_ISSUER_SECRET")
    if not url or not secret:
        print("Set XRPL_NETWORK_URL and XRPL_ISSUER_SECRET", file=sys.stderr)
        sys.exit(1)

    try:
        wallet = Wallet.from_seed(secret)
    except Exception:
        try:
            wallet = Wallet.from_secret(secret)
        except Exception as e:
            print(f"Wallet from seed/secret failed: {e}", file=sys.stderr)
            sys.exit(1)

    client = JsonRpcClient(url)


    # flags=0: non-transferable (no tfMPTCanTransfer=32), and no auth required
    # (do NOT set tfMPTRequireAuth=4) so recipients can receive without MPTokenAuthorize.
    metadata_hex = _xls89_metadata_hex()
    if len(metadata_hex) // 2 > 1024:
        print("Metadata exceeds 1024 bytes", file=sys.stderr)
        sys.exit(1)

    # Omit transfer_fee when flags=0 (non-transferable); xrpl-py forbids it otherwise.
    tx = MPTokenIssuanceCreate(
        account=wallet.classic_address,
        asset_scale=0,
        flags=0,
        mptoken_metadata=metadata_hex,
        maximum_amount="1000000000",
    )

    print("Submitting MPTokenIssuanceCreate...")
    response = submit_and_wait(tx, client, wallet)
    if not response.is_successful():
        print(f"Transaction failed: {response}", file=sys.stderr)
        sys.exit(1)

    # Issuance ID is the LedgerIndex of the created MPTokenIssuance entry (in tx metadata).
    result = response.result
    tx_hash = result.get("hash")
    meta = result.get("meta")
    if not meta:
        print("No metadata in result; cannot derive issuance ID", file=sys.stderr)
        print("Transaction hash:", tx_hash)
        sys.exit(1)

    # Prefer direct mpt_issuance_id in meta; else parse AffectedNodes.
    issuance_id = meta.get("mpt_issuance_id")
    if not issuance_id:
        affected = meta.get("AffectedNodes", [])
        for node in affected:
            created = node.get("CreatedNode")
            if not created:
                continue
            entry = created.get("NewFields", {})
            if entry.get("LedgerEntryType") == "MPTokenIssuance":
                issuance_id = created.get("LedgerIndex")
                break

    if not issuance_id:
        print("MPTokenIssuance created node not found in metadata", file=sys.stderr)
        print("Transaction hash:", tx_hash)
        print("Metadata keys:", list(meta.keys()))
        sys.exit(1)

    print("MPT issuance created successfully.")
    print("Transaction hash:", tx_hash)
    print("XRPL_MPT_ISSUANCE_ID=" + issuance_id)
    print("\nAdd to your .env or deployment config:")
    print("XRPL_MPT_ISSUANCE_ID=" + issuance_id)


if __name__ == "__main__":
    main()
