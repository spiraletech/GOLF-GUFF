# L17 — Authority Ledger / Replay + Revocation

L17 separates **cryptographic authenticity** from **current authority**.

A valid L15 signature proves that a signer created a receipt. It does not prove the receipt is still usable now. `AuthorityLedger` is the cold, append-only state machine that decides whether a signed receipt remains authorized at the moment a privileged boundary is crossed.

## Receipt schema v2

Privileged operations require authority-envelope schema v2. The signed envelope adds:

- `signer_key_id`
- `issued_at_unix_ms`
- `expires_at_unix_ms`
- `max_uses`

These fields are part of the canonical signed envelope and therefore cannot be changed without invalidating the receipt.

Schema v1 remains readable/verifiable for L15 compatibility, but L17 refuses to consume schema-v1 receipts at privileged gates because they have no cryptographically bound lifetime/use policy.

## Trusted signer keys

The ledger stores only public trust metadata:

- signer ID
- key ID
- algorithm ID
- issuance-valid-from time
- optional issuance-valid-until time
- optional hard-revocation time

Private signing material never enters the ledger.

Key rotation is modeled by trusting a new key and retiring the old key's issuance window. A receipt issued by the old key before retirement may continue until its own expiry. Hard key revocation invalidates receipts from that key immediately once the revocation time is reached.

## Replay defense

Two independent limits are enforced:

1. **Receipt use count** — the immutable receipt ID may be consumed only up to its signed `max_uses`.
2. **Signer-key nonce binding** — `(signer_id, key_id, nonce)` becomes bound to the first consumed receipt ID. A different receipt reusing the same signer/key/nonce is refused as `NONCE_REPLAY`.

This means a deliberately two-use receipt can be used twice, while a newly forged/re-signed envelope cannot evade replay controls by copying its nonce.

## Revocation and expiry

A receipt is refused when:

- its signature/content identity is invalid;
- its purpose, subject or scope does not match the requested operation;
- its signer key is unknown;
- it was issued outside the key's issuance window;
- the signer key is hard-revoked;
- the receipt is not yet valid;
- the receipt has expired;
- the receipt ID has been explicitly revoked;
- the signer-key nonce is bound to another receipt;
- its signed use limit has been reached;
- the authority journal cannot durably append the consumption event;
- the authority journal hash chain is corrupt.

## Durable-before-side-effect law

A successful consumption is appended to the authority journal **before** `AuthorityGate` returns `ALLOWED`.

If the journal cannot record the use, the privileged operation does not execute. This prevents a crash/storage failure from creating unrecorded authority use.

## Cold audit journal

Every authority event is append-only and globally hash chained:

```text
sequence | previous_record_sha256 | event... | record_sha256
```

Event families:

- `K` — trust signer key
- `T` — retire signer key issuance
- `R` — hard-revoke signer key
- `X` — revoke receipt
- `U` — consume receipt use

Replay reconstructs trusted keys, receipt use counts, nonce bindings and revocations. Sequence discontinuity, previous-hash mismatch, record-hash mismatch or invalid event transitions make the ledger unhealthy and block future authority mutations/consumption.

## SpiralOS barcode relationship

Spiral Barcode remains transport only:

```text
BARCODE SCAN
    ↓
transport integrity
    ↓
resolve L15 receipt
    ↓
verify signature/content
    ↓
L17 authority ledger
    ├─ signer key active?
    ├─ not expired/revoked?
    ├─ nonce valid?
    └─ uses remaining?
    ↓
ALLOW / REFUSE
```

A copied barcode therefore does not imply reusable permission. Even a bit-perfect scan of a legitimately signed receipt can be rejected because the receipt was already consumed, revoked or expired.

## Recovery interaction

Recovery performs structural checks (interrupted parent, fresh child correlation, child template) before consuming a bounded receipt. Invalid recovery requests therefore do not burn one-shot authority. Once the request is structurally valid, receipt consumption is durable before the recovery journal mutation is attempted.
