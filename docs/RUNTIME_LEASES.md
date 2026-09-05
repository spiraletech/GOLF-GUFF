# L20 — Runtime Binding / Capability Leases

L20 prevents a valid delegated session-key packet from becoming portable authority.

A session key may possess a capability, but a runtime lease says **where that capability may actually be exercised**.

## Runtime coordinate

Every lease binds the exact tuple:

- `device_id` — immutable `guff:hardware:sha256:<digest>` identity.
- `executable_sha256` — exact executable image identity supplied by the trusted runtime observer.
- `process_instance_sha256` — SHA-256 over device + executable + process ID + process start time + a runtime nonce. PID alone is intentionally insufficient because operating systems reuse PIDs.
- `slot_id` — exact CLUBHOUSE cartridge/slot.
- `session_id` — immutable `guff:session:sha256:<digest>` transaction/session identity.
- `RealityLayer` — the STRATA layer in which the capability is permitted.

The complete coordinate has its own SHA-256 digest.

## Lease

A delegated L19 session key signs a `RuntimeCapabilityLease` containing:

- the backing session-key receipt and handoff certificate IDs,
- signer/key/fingerprint identity,
- purpose, subject, scope and one capability,
- the complete runtime coordinate,
- issue/expiry timestamps,
- a bounded use count,
- nonce and canonical SHA-256.

The immutable lease identity is:

`guff:lease:sha256:<digest>`

A lease can only reduce the L19 branch. Its capability must already exist in the session-key receipt, its expiry must not outlive that receipt, and its use budget cannot exceed the session-key budget.

## Authorization order

`RuntimeLeaseAuthorityGate` uses this order:

1. Verify the lease's signed identity and exact session-key branch.
2. Verify the lease is durably registered and still live.
3. Compare observed device, executable, process instance, slot, session and STRATA layer.
4. Check the lease use budget.
5. Ask the L19 `SessionKeyAuthorityGate` to consume the session-key + backing L18 authority.
6. Durably append the runtime lease use.
7. Only then may the caller permit side effects.

Coordinate failure occurs before step 5, so a stolen packet does not burn legitimate authority merely by being presented from the wrong runtime.

If step 6 fails after backing authority was consumed, the result is still refused and the caller must block side effects. Safety wins over availability.

## Durable lease journal

`RuntimeLeaseLedger` is append-only and SHA-256 chained.

- `L` — register a lease.
- `U` — consume one lease use.
- `X` — revoke a lease.

Replay reconstructs registrations, use counts and revocation state. Sequence/hash corruption makes the ledger unhealthy and authorization fails closed.

## What L20 does not claim

L20 is a **runtime binding contract**, not remote attestation by itself.

The observed coordinate must come from a trusted local observer. An untrusted request must never be allowed to self-report "I am this executable/device/process" and thereby satisfy the lease.

A later attestation layer may obtain device/process/image measurements directly from the operating system, TPM/Secure Enclave, signed launcher, or another trusted local provider. L20 defines the coordinate and enforcement contract that such an attestor feeds.

## Laws

1. **A key is not portable authority.** A valid session key may still be unusable outside its leased runtime.
2. **PID is not process identity.** Process instance identity includes executable, start time, device and nonce.
3. **Runtime mismatch burns nothing upstream.** Coordinate checks precede L19/L18 consumption.
4. **Lease authority only narrows.** Capability, lifetime and use budget fit inside the session-key branch.
5. **Lease state is durable.** Use/revocation survives restart.
6. **Side effects follow both durable consumptions.** L19 backing authority and L20 lease use must both succeed.
7. **Observation must be trusted.** Runtime coordinates are evidence inputs, not self-asserted request fields.
