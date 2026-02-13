# platform-api-xrpl

XRPL integration services for TrustAuthy — conditional escrow with M-of-N multi-signature release, gated by location verification and Soul-Bound Token (SBT) ownership.

---

## Multi-Sig + Escrow Flow

The system uses **XRPL conditional escrows** (PREIMAGE-SHA-256 crypto-conditions) combined with **M-of-N multi-signature** transactions. M signers (out of N registered) must independently verify their location before funds can be released. The server never holds user keys — it only holds the escrow fulfillment secret and coordinates the signing ceremony.

### Actors

| Actor | Role |
|---|---|
| **Server** | Generates escrow condition/fulfillment, stores fulfillment, validates location + SBT, tracks escrow state in Firestore, submits final multi-signed transactions |
| **Signer 1** | Initiates the escrow release — proves location, receives fulfillment, builds & signs EscrowCreate + EscrowFinish, submits first signature |
| **Signers 2..M** | Co-sign the release — each proves location independently, adds their signature to both transactions. The Mth signer triggers on-chain submission |

### Step-by-Step Flow (M-of-N)

```
 Signer 1                     Server                      Signer 2..M
    │                            │                            │
    │  1. POST /escrow/prepare   │                            │
    │  (destination, amount,     │                            │
    │   owner/multisig_account)  │                            │
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
    │                            │  update DB pending bundle  │
    │                            │  (state: "pending_sigs",   │
    │                            │   remove signer 1 from     │
    │                            │   awaiting list)           │
    │  <pending_id, status>      │                            │
    │ <──────────────────────────│                            │
    │                            │                            │
    │                            │  6. GET /escrow/           │
    │                            │     pending-releases       │
    │                            │ <──────────────────────────│
    │                            │  query bundles where       │
    │                            │  state="pending_signatures"│
    │                            │  and signer is in          │
    │                            │  awaiting_signer_addresses │
    │                            │     <list of pending>      │
    │                            │ ──────────────────────────>│
    │                            │                            │
    │                            │  7. POST /escrow/          │
    │                            │     get-bundle-for-signing │
    │                            │  (pending_id, location sig)│
    │                            │ <──────────────────────────│
    │                            │  verify location (HMAC)    │
    │                            │  verify signer is in       │
    │                            │  awaiting list             │
    │                            │  <create_tx, finish_tx,    │
    │                            │   signer_quorum>           │
    │                            │ ──────────────────────────>│
    │                            │                            │
    │                            │                            │  8. Signer adds their
    │                            │                            │     signature to both
    │                            │                            │     EscrowCreate and
    │                            │                            │     EscrowFinish tx_json
    │                            │                            │
    │                            │  ── if sigs < quorum ───   │
    │                            │                            │
    │                            │  9a. POST /escrow/         │
    │                            │   submit-additional-sigs   │
    │                            │  (store updated bundle,    │
    │                            │   update awaiting list)    │
    │                            │ <──────────────────────────│
    │                            │  <sig_count, quorum_reached│
    │                            │   = false>                 │
    │                            │ ──────────────────────────>│
    │                            │                            │
    │                            │  (repeat 6-9a for next     │
    │                            │   signer until M reached)  │
    │                            │                            │
    │                            │  ── if sigs >= quorum ──   │
    │                            │                            │
    │                            │  9b. POST /escrow/         │
    │                            │      complete-release      │
    │                            │  (pending_id, location sig,│
    │                            │   create_tx, finish_tx     │
    │                            │   — each w/ M signatures)  │
    │                            │ <──────────────────────────│
    │                            │  verify location (HMAC)    │
    │                            │  verify both txs have ≥M   │
    │                            │  signatures (quorum)       │
    │                            │                            │
    │                            │  submit EscrowCreate       │
    │                            │  (submit_multisigned)      │
    │                            │          ↓                 │
    │                            │  submit EscrowFinish       │
    │                            │  (submit_multisigned)      │
    │                            │          ↓                 │
    │                            │  update state: "submitted" │
    │                            │                            │
    │                            │  <released: true,          │
    │                            │   tx_hash_create,          │
    │                            │   tx_hash_finish>          │
    │                            │ ──────────────────────────>│
```

### Prerequisites / Gates

Before any escrow can be released, the server enforces:

1. **SBT Ownership** — Both the sender (`owner`) and the `destination` must hold the platform's MPT Soul-Bound Token. Checked via `account_holds_mpt_sbt()` in `xrpl_sbt.py`.
2. **Location Verification** — Each signer must pass an HMAC-based location proof (`digital_id`, `timestamp`, `nonce`, `location_signature`) at every sensitive step (request-release, get-bundle-for-signing, submit-additional-signatures, complete-release).
3. **Multi-Sig Quorum** — Both EscrowCreate and EscrowFinish must carry at least `signer_quorum` (M) signatures before on-chain submission.

---

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/xrpl` | None | Health check |
| POST | `/api/v1/xrpl/escrow/prepare` | JWT | Generate escrow condition; creates Firestore doc with signer info from `multisig_config` |
| POST | `/api/v1/xrpl/escrow/finish` | JWT | Release escrow (single-signer path) |
| POST | `/api/v1/xrpl/escrow/register-multisig` | JWT | Store signer addresses and quorum for an M-of-N multisig account |
| GET | `/api/v1/xrpl/escrow/multisig-signers` | JWT | Get registered signer addresses and quorum |
| POST | `/api/v1/xrpl/escrow/request-release` | JWT | Signer 1: verify location + SBT, get fulfillment |
| POST | `/api/v1/xrpl/escrow/submit-first-signatures` | JWT | Signer 1: store partially-signed bundle (state → `pending_signatures`) |
| GET | `/api/v1/xrpl/escrow/pending-releases` | JWT | List bundles in `pending_signatures` state awaiting your signature |
| POST | `/api/v1/xrpl/escrow/get-bundle-for-signing` | JWT | Verify location, get tx_json + `signer_quorum` to co-sign |
| POST | `/api/v1/xrpl/escrow/submit-additional-signatures` | JWT | Add signature to bundle without submitting (for M > 2) |
| POST | `/api/v1/xrpl/escrow/complete-release` | JWT | Submit fully-signed Create + Finish when quorum is reached |

---

## File Structure (This repo includes server files related to just XRPL for submission)

```
platform-api-xrpl/
├── scripts/
│   └── create_xrpl_sbt_mpt.py   # One-time MPT issuance creation script
└── server/
    ├── routes/
    │   ├── escrow.py             # Escrow + M-of-N multi-sig HTTP route handlers
    │   └── sbt.py                # SBT minting / registration routes (XRPL)
    └── services/
        ├── xrpl_escrow.py        # Condition/fulfillment generation, EscrowCreate & EscrowFinish
        ├── xrpl_multisig.py      # submit_multisigned — submit fully multi-signed tx to XRPL
        └── xrpl_sbt.py           # MPT Soul-Bound Token issuance & ownership checks
```

| File | Purpose |
|---|---|
| `server/services/xrpl_escrow.py` | Generates PREIMAGE-SHA-256 condition/fulfillment pairs. Builds and submits `EscrowCreate` and `EscrowFinish` transactions via `xrpl-py` async API. |
| `server/services/xrpl_multisig.py` | Accepts a fully-signed transaction dict (with `Signers` array and empty `SigningPubKey`), converts it to an xrpl-py `Transaction` model, and submits via `SubmitMultisigned`. |
| `server/services/xrpl_sbt.py` | Sends 1 unit of the platform MPT to a destination address (`send_mpt_to_user`). Checks whether an account holds the MPT SBT (`account_holds_mpt_sbt`). Validates XRPL addresses. |
| `server/routes/escrow.py` | All escrow and multi-sig HTTP endpoints. Handles JSON parsing, location verification (HMAC), SBT gate checks, Redis/Firestore persistence, escrow state machine, and orchestrates M-of-N signing ceremony. |
| `server/routes/sbt.py` | `/mint-sbt` and `/register-sbt` endpoints for issuing SBTs on XRPL chains. `/sbt-data` for reading on-chain SBT data. |
| `scripts/create_xrpl_sbt_mpt.py` | CLI script to create the MPT issuance on XRPL (run once per environment). Outputs `XRPL_MPT_ISSUANCE_ID` for `.env` config. |

---
