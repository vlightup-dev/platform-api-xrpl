# platform-api-xrpl

XRPL integration services for TrustAuthy — conditional escrow with multi-signature release, gated by location verification and Soul-Bound Token (SBT) ownership. (This repo only includes server files related to XRPL functionalities)

---

## Multi-Sig + Escrow Flow

The system uses **XRPL conditional escrows** (PREIMAGE-SHA-256 crypto-conditions) combined with **multi-signature** transactions. Signers must independently verify their location before funds can be released. The server never holds user keys — it only holds the escrow fulfillment secret and coordinates the signing ceremony.

### Step-by-Step Flow for 2-2 Multi-sig signing with conditional escrow

```
 Signer 1                     Server                      Signer 2
    │                            │                            │
    │  1. POST /escrow/prepare   │                            │
    │  (destination, amount)     │                            │
    │ ──────────────────────────>│                            │
    │                            │  generate condition +      │
    │                            │  fulfillment (random       │
    │                            │  preimage → SHA-256)       │
    │                            │  store fulfillment         │
    │                            │  (keyed by condition)      │
    │  <condition, cancel_after> │                            │
    │ <──────────────────────────│                            │
    │                            │                            │
    │  2. POST /escrow/          │                            │
    │     request-release        │                            │
    │  (owner, offer_sequence,   │                            │
    │   condition, location sig) │                            │
    │ ──────────────────────────>│                            │
    │                            │  3. verify location (HMAC) │
    │                            │  verify sender + receiver  │
    │                            │  both hold MPT SBT         │
    │     <fulfillment>          │                            │
    │ <──────────────────────────│                            │
    │                            │                            │
    │  4. Build EscrowCreate +   │                            │
    │     EscrowFinish tx_json   │                            │
    │     (with fulfillment),    │                            │
    │     sign both (1st sig)    │                            │
    │                            │                            │
    │  5. POST /escrow/          │                            │
    │     submit-first-signatures│                            │
    │  (condition, create_tx,    │                            │
    │   finish_tx — each w/ 1    │                            │
    │   signature)               │                            │
    │ ──────────────────────────>│                            │
    │                            │  store bundle in DB        │
    │                            │  (pending_escrow_bundles)  │
    │                            │  record awaiting signers   │
    │  <pending_id, status>      │                            │
    │ <──────────────────────────│                            │
    │                            │                            │
    │                            │  6. GET /escrow/           │
    │                            │     pending-releases       │
    │                            │ <──────────────────────────│
    │                            │  query bundles where       │
    │                            │  signer 2 is in            │
    │                            │  awaiting_signer_addresses │
    │                            │     <list of pending>      │
    │                            │ ──────────────────────────>│
    │                            │                            │
    │                            │  7. POST /escrow/          │
    │                            │     get-bundle-for-signing │
    │                            │  (pending_id, location sig)│
    │                            │ <──────────────────────────│
    │                            │  verify location (HMAC)    │
    │                            │  verify signer 2 ≠ signer 1│
    │                            │  verify signer 2 is in     │
    │                            │  awaiting list             │
    │                            │  <create_tx, finish_tx>    │
    │                            │ ──────────────────────────>│
    │                            │                            │
    │                            │                            │  8. Signer 2 adds 2nd
    │                            │                            │     signature to both
    │                            │                            │     EscrowCreate and
    │                            │                            │     EscrowFinish tx_json
    │                            │                            │
    │                            │  9. POST /escrow/          │
    │                            │     complete-release       │
    │                            │  (pending_id, location sig,│
    │                            │   create_tx, finish_tx     │
    │                            │   — each w/ 2 signatures)  │
    │                            │ <──────────────────────────│
    │                            │  verify location (HMAC)    │
    │                            │  verify both txs have ≥2   │
    │                            │  signatures                │
    │                            │                            │
    │                            │  submit EscrowCreate       │
    │                            │  (submit_multisigned)      │
    │                            │          ↓                 │
    │                            │  submit EscrowFinish       │
    │                            │  (submit_multisigned)      │
    │                            │                            │
    │                            │  <released: true,          │
    │                            │   tx_hash_create,          │
    │                            │   tx_hash_finish>          │
    │                            │ ──────────────────────────>│
```

### Prerequisites / Gates

Before any escrow can be released, the server enforces:

1. **SBT Ownership** — Both the sender (`owner`) and the `destination` must hold the platform's MPT Soul-Bound Token. Checked via `account_holds_mpt_sbt()` in `xrpl_sbt.py`.
2. **Location Verification** — Each signer must pass an HMAC-based location proof (`digital_id`, `timestamp`, `nonce`, `location_signature`) at every sensitive step (request-release, get-bundle-for-signing, complete-release).
3. **Multi-Sig Quorum** — Both EscrowCreate and EscrowFinish must carry signatures from at least 2 signers before on-chain submission.


## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/xrpl` | None | Health check |
| POST | `/api/v1/xrpl/escrow/prepare` | JWT | Generate escrow condition (client builds EscrowCreate) |
| POST | `/api/v1/xrpl/escrow/finish` | JWT | Release escrow (single-signer path) |
| POST | `/api/v1/xrpl/escrow/register-multisig` | JWT | Store signer addresses for a multisig account |
| GET | `/api/v1/xrpl/escrow/multisig-signers` | JWT | Get registered signer addresses |
| POST | `/api/v1/xrpl/escrow/request-release` | JWT | Signer 1: verify location + SBT, get fulfillment |
| POST | `/api/v1/xrpl/escrow/submit-first-signatures` | JWT | Signer 1: store partially-signed bundle |
| GET | `/api/v1/xrpl/escrow/pending-releases` | JWT | Signer 2: list bundles awaiting your signature |
| POST | `/api/v1/xrpl/escrow/get-bundle-for-signing` | JWT | Signer 2: verify location, get tx_json to co-sign |
| POST | `/api/v1/xrpl/escrow/complete-release` | JWT | Signer 2: submit fully-signed Create + Finish |

---

## File Structure (This repo includes server files related to just XRPL for submission)

```
platform-api-xrpl/
├── scripts/
│   └── create_xrpl_sbt_mpt.py   # One-time MPT issuance creation script
└── server/
    ├── routes/
    │   ├── escrow.py             # Escrow + multi-sig HTTP route handlers
    │   └── sbt.py                # SBT minting / registration routes
    └── services/
        ├── xrpl_escrow.py        # Condition/fulfillment generation, EscrowCreate & EscrowFinish
        ├── xrpl_multisig.py      # submit_multisigned — submit fully multi-signed tx to XRPL
        └── xrpl_sbt.py           # MPT Soul-Bound Token issuance & ownership checks
```

| File | Purpose |
|---|---|
| `server/services/xrpl_escrow.py` | Generates PREIMAGE-SHA-256 condition/fulfillment pairs. Builds and submits `EscrowCreate` and `EscrowFinish` transactions via `xrpl-py` async API. |
| `server/services/xrpl_multisig.py` | Accepts a fully-signed transaction dict (with `Signers` array and empty `SigningPubKey`), converts it to an xrpl-py `Transaction` model, and submits via `SubmitMultisigned`. |
| `server/services/xrpl_sbt.py` | Sends 1 unit of the platform MPT to a destination address (`send_mpt_to_user`). Checks whether an account holds the MPT SBT (`account_holds_mpt_sbt`). |
| `server/routes/escrow.py` | All escrow and multi-sig HTTP endpoints. Handles JSON parsing, location verification (HMAC), SBT gate checks, Redis/Firestore persistence, and orchestrates the two-phase multi-sig signing ceremony. |
| `server/routes/sbt.py` | `/mint-sbt` and `/register-sbt` endpoints for issuing SBTs XRPL chains. |
| `scripts/create_xrpl_sbt_mpt.py` | CLI script to create the MPT issuance on XRPL (run once per environment). |

---
