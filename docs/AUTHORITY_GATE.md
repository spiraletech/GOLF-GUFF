# L16 — Authority Gate

L15 made authority receipts verifiable. L16 makes them operationally mandatory at privileged boundaries.

## Law

A trusted signer is not enough. A privileged operation must present a valid receipt whose:

1. purpose matches the operation class,
2. subject matches the exact target identity,
3. scope SHA-256 matches the exact operation contract,
4. signer/algorithm/signature pass the configured `AuthorityVerifier`.

`AuthorityGate` is the common verifier. It never signs, never creates authority, and never interprets a SpiralOS barcode as authority. A barcode may transport a receipt reference, but the resolved GUFF receipt must still pass this gate.

## Privileged boundaries

### Recovery

`RecoveryDecisionProtocol` no longer accepts `approved=true` as authority. `RecoveryAuthorization` carries an L15 receipt. Its scope digest binds:

- DISMISS vs RETRY_AS_NEW_SESSION,
- parent session identity,
- exact parent BEGIN record SHA-256,
- fresh child correlation identity,
- newly granted child retry authority.

A missing, forged, wrong-purpose, wrong-subject or wrong-scope receipt is rejected before the recovery journal mutates.

### Destructive execution

`AuthorityGatedExecutionSession` wraps the L12 execution orchestrator. For `TaskSignal::destructive=true`, it requires a `DESTRUCTIVE_EXECUTION` receipt bound to:

- the immutable execution session ID,
- the complete execution-request digest,
- slot/capability/STRATA contract,
- input SHA-256 and payload byte contract.

If the gate fails, the inner orchestrator and executor are never called.

Non-destructive requests do not require this receipt at the L16 boundary.

### Persistent symbiosis

`AuthorityGatedSymbiosis` requires a `PERSISTENT_SYMBIOSIS` receipt whenever a grant requests any durable/learning behavior:

- `persist_grant`,
- `persist_observation_stamps`, or
- `allow_memory_promotion`.

The signed scope covers the complete source + retention contract and issue/expiry window. Ephemeral session-local grants remain receipt-free.

## SpiralOS barcode relationship

```text
SPIRAL BARCODE
      |
      v
resolve receipt reference
      |
      v
L15 AuthorityReceipt
      |
      v
L16 AuthorityGate
 purpose + subject + scope + signature
      |
   +--+--+
   |     |
 ALLOW REFUSE
```

Transport integrity is not permission. CRC/parity/barcode readability never bypasses cryptographic receipt verification.

## Design laws added

41. **A receipt must match the operation.** Trusted signature alone is insufficient; purpose, subject and scope are mandatory.
42. **Privileged failure is side-effect free.** Rejected authority cannot reach an executor, recovery mutation or persistent grant creation.
43. **Recovery has no boolean authority.** Human approval is represented by a signed receipt, not an `approved` flag.
44. **Persistence requires durable authority.** Ephemeral observation is distinct from permission to retain or learn.
45. **Barcodes transport proof; they do not create it.** SpiralOS scan success is never an authorization decision.
