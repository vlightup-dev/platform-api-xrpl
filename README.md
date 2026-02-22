# platform-api-xrpl

XRPL integration services for TrustAuthy.

This service coordinates:
- Conditional escrow (PREIMAGE-SHA-256)
- Multi-signer release flow
- Location verification (HMAC)
- SBT gate checks

The server does **not** hold user private keys. It coordinates bundle state and submits multisigned XRPL transactions when release conditions are met.

---

## Current Multi-Sig Model (Weighted)

The multi-sig release flow is **weighted**.

- Signers and weights are registered per multisig account in Firestore `multisig_config`.
- Quorum is evaluated by **sum of signer weights**, not by signature count alone.
- For security, quorum/weights are resolved from server-side `multisig_config` (trusted source), not from client payload.

### Important behavior

- `submit-additional-signatures` stores updated signatures.
- If weighted quorum is reached, `submit-additional-signatures` can also submit `EscrowCreate` + `EscrowFinish` immediately.
- `complete-release` remains available as finalize/retry path.

---

### Step-by-Step Flow (M-of-N)

```
 Signer 1                     Server                       Signers 2..N
    │                            │                             │
    │ 1) POST /escrow/prepare    │                             │
    │───────────────────────────>│ create condition/fulfillment│
    │<───────────────────────────│ store pending + signer meta │
    │                            │                             │
    │ 2) POST /escrow/request-   │                             │
    │    release (location+SBT)  │                             │
    │───────────────────────────>│ verify gates                │
    │<───────────────────────────│ return fulfillment          │
    │                            │                             │
    │ 3) Build + sign Create/    │                             │
    │    Finish (first signatures)                             │
    │                            │                             │
    │ 4) POST /escrow/submit-    │                             │
    │    first-signatures        │                             │
    │───────────────────────────>│ state=pending_signatures    │
    │<───────────────────────────│ pending_id                  │
    │                            │                             │
    │                            │ 5) GET /pending-releases    │
    │                            │<────────────────────────────│
    │                            │────────────────────────────>│ list
    │                            │                             │
    │                            │ 6) POST /get-bundle-for-    │
    │                            │    signing (location)       │
    │                            │<────────────────────────────│
    │                            │────────────────────────────>│ bundle
    │                            │                             │
    │                            │ 7) POST /submit-additional- │
    │                            │    signatures               │
    │                            │<────────────────────────────│
    │                            │ verify weighted quorum from │
    │                            │ trusted multisig_config     │
    │                            │                             │
    │                            │ if quorum not reached:      │
    │                            │   store bundle, update      │
    │                            │   awaiting signers          │
    │                            │                             │
    │                            │ if quorum reached:          │
    │                            │   submit EscrowCreate then  │
    │                            │   EscrowFinish              │
    │                            │────────────────────────────>│ released
    │                            │                             │
    │                            │ 8) Optional retry:          │
    │                            │    POST /complete-release   │
    │                            │    (fallback/finalize path) │
```

1. `POST /api/v1/xrpl/escrow/prepare`
- Server creates condition/fulfillment.
- Stores pending state and signer metadata for multisig owner.

2. `POST /api/v1/xrpl/escrow/request-release` (Signer 1)
- Verifies location + SBT gate.
- Returns fulfillment for transaction construction.

3. Signer 1 creates/signs `EscrowCreate` + `EscrowFinish` (first signatures).

4. `POST /api/v1/xrpl/escrow/submit-first-signatures`
- Stores bundle in `pending_signatures`.
- Builds awaiting signer list.
- Uses trusted signer/weight/quorum config.

5. Co-signers fetch work:
- `GET /api/v1/xrpl/escrow/pending-releases`
- `POST /api/v1/xrpl/escrow/get-bundle-for-signing`

6. Co-signer submits additional signatures:
- `POST /api/v1/xrpl/escrow/submit-additional-signatures`
- Server checks weighted quorum from `multisig_config`.
- If quorum reached, server submits both transactions and marks bundle submitted.

7. Optional finalize/retry:
- `POST /api/v1/xrpl/escrow/complete-release`

---

## Security Gates

Before release actions are accepted:

1. SBT ownership check
- Sender (`owner`) and destination must hold required platform SBT/MPT.

2. Location verification
- HMAC proof using `digital_id`, `timestamp`, `nonce`, `location_signature`.

3. Weighted quorum validation
- Signer weights + quorum are loaded from Firestore `multisig_config` for the account.

---

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/xrpl` | None | Health check |
| POST | `/api/v1/xrpl/escrow/prepare` | JWT | Generate escrow condition and create pending record |
| POST | `/api/v1/xrpl/escrow/finish` | JWT | Single-signer finish path |
| POST | `/api/v1/xrpl/escrow/register-multisig` | JWT | Register signer addresses, signer weights, quorum |
| GET | `/api/v1/xrpl/escrow/multisig-signers` | JWT | Read registered signer addresses/weights/quorum |
| POST | `/api/v1/xrpl/escrow/request-release` | JWT | Signer 1 gets fulfillment after location + SBT checks |
| POST | `/api/v1/xrpl/escrow/submit-first-signatures` | JWT | Store first signed bundle |
| GET | `/api/v1/xrpl/escrow/pending-releases` | JWT | List releases awaiting caller signature |
| POST | `/api/v1/xrpl/escrow/get-bundle-for-signing` | JWT | Return tx bundle for co-signing |
| POST | `/api/v1/xrpl/escrow/submit-additional-signatures` | JWT | Store co-signer signatures; can auto-submit when weighted quorum reached |
| POST | `/api/v1/xrpl/escrow/complete-release` | JWT | Finalize/retry submission path |

---

## Data Model Notes

### `multisig_config/{account}`

Expected fields:
- `signer_addresses: string[]`
- `signer_weights: number[]`
- `signer_weight_by_address: Record<string, number>`
- `signer_quorum: number`

### `pending_escrow_bundles/{condition}`

Typical fields:
- `state` (`prepared`, `pending_signatures`, `submitted`, `released`)
- `owner`, `destination`, `amount_drops`
- `signer_addresses`, `signer_weights`, `signer_weight_by_address`, `signer_quorum`
- `awaiting_signer_addresses`
- `escrow_create_tx_json`, `escrow_finish_tx_json`
- `tx_hash_create`, `tx_hash_finish`

---

## Relevant Files

- `server/routes/escrow.py`: Escrow + multisig HTTP handlers and state machine
- `server/routes/sbt.py`: SBT registration/mint routes
- `server/services/xrpl_escrow.py`: Condition/fulfillment + escrow helpers
- `server/services/xrpl_multisig.py`: Multisigned tx submission to XRPL
- `server/services/xrpl_sbt.py`: SBT ownership checks and related helpers
- `scripts/create_xrpl_sbt_mpt.py`: One-time MPT issuance setup

---
