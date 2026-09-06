# L22 — Runtime Identity Store

L22 turns short-lived L21 attestation evidence into bounded cold identity continuity without turning identity into authorization.

## Stored identity classes

### Device identity

`guff:identity-device:sha256:<digest>` binds the L21 attestation provider ID to the provider-produced hashed device ID. The same device measurement from a different provider is intentionally a different identity because provider semantics are part of the evidence chain.

### Executable image identity

`guff:identity-image:sha256:<digest>` is derived only from the executable SHA-256. Executable identity is therefore content-based and provider-independent.

### Process identity

`guff:identity-process:sha256:<digest>` binds provider ID to the L20/L21 process-instance SHA-256. The process record also preserves its device/image lineage plus PID and OS process-start identity for collision detection.

### Attestation observation

Each L21 `guff:attestation:sha256:<digest>` is stored as compact metadata linking device/image/process records to slot, immutable session, STRATA layer, observation/expiry times and executable-locator digest.

The raw challenge nonce is **not persisted**. Only `SHA256(challenge)` is kept.

## Append-only journal

`RuntimeIdentityStore` uses a dependency-free append-only journal with global sequence numbers, previous-record SHA-256 and current-record SHA-256.

Events:

- `O` — record a canonical attestation observation
- `D` — revoke a device identity
- `E` — revoke an executable image identity
- `P` — revoke a process identity

Replay reconstructs compact identity state. Sequence breaks, hash mismatch, impossible record IDs, duplicate attestation IDs, malformed revocations, identity collisions or configured-capacity overflow make the store unhealthy and fail closed.

## Bounded state

Default cold limits are intentionally finite:

- 256 devices
- 2,048 executable images
- 4,096 process instances
- 8,192 attestation observations

Callers can provide stricter limits. Crossing a limit refuses the new observation rather than silently evicting identity history or growing without bound.

## Attestation-provider integration

`IdentityTrackingRuntimeAttestationProvider` decorates any L21 `RuntimeAttestationProvider`.

```text
L21 native attestor
        |
        v
L22 identity store
  record / revoke / collision / bounds
        |
        v
L21 attested lease gate
        |
        v
L20 runtime lease
        |
        v
L19/L18 authority
```

Evidence is durably recorded before the decorated provider returns it to the privileged gate. A revoked identity, corrupt store, collision, capacity failure or storage failure therefore becomes `EvidenceInvalid` before L20/L19/L18 authority can be consumed.

## Revocation semantics

Device, image and process revocations are independent facts. Revoking a device or executable does not mutate every process record; `identity_active()` evaluates the complete lineage, so any revoked component makes the observed identity inactive.

Revocation is durable and survives restart.

## What L22 does not do

L22 does **not** decide whether a known process may build code, mutate a world, access a repository or generate audio. It records what identity was observed and whether that identity has been revoked or contradicted.

L23 policy is the layer that should map identity facts + authority + capability + STRATA context into an allow/refuse decision.

## Doctrine

1. **Identity is evidence, not permission.** Seeing the same process repeatedly grants nothing by itself.
2. **Provider semantics are part of device/process identity.** Measurements from different attestors are not silently conflated.
3. **Executable identity is content identity.** Image bytes, not filenames, define the executable record.
4. **One process can appear in many sessions without becoming many process identities.** Slot/session belong to observations, not the immutable process entity.
5. **Challenges are transient.** Cold state keeps only their digest.
6. **Identity continuity is bounded.** Capacity exhaustion refuses new evidence instead of becoming unbounded memory.
7. **Revocation is durable.** A previously observed identity can become unusable later.
8. **Corruption fails closed.** A broken identity journal never becomes trusted evidence.
9. **Persistence precedes privileged use.** Tracking failure blocks the decorated attestation path.
10. **Policy stays separate.** L22 records identity facts; L23 decides what those facts permit.
