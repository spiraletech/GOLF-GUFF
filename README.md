# GOLF GUFF

**Codename:** The Ring  
**Mission:** a memory-light, recursive, reality-aware AI development console for solo developers.

GOLF GUFF is not a single GGUF. It is the routing, benchmarking, reality-model, verification, capability-bus, governed-execution and transaction layer that decides which local model or deterministic tool may act on which layer of a developer's reality.

## L0 — Ring Foundation

- `RealityStack` — explicit physical, OS, runtime, project, application, simulation, semantic, memory, meta and representation coordinates.
- `Caddy` — routes work toward tiny/core/deep local inference, deterministic tools or human review.
- `Recursor` — bounded recursive refinement with hard depth/step/confidence stops.

## L1 — Pristine Model Identity

- cryptographic model manifests, provenance, licensing and hardware contracts.
- immutable `guff:model:sha256:<digest>` identities and streaming SHA-256 verification.

## L2 — SCORECARD Foundation

- immutable hardware identity plus task-specific quality, latency, memory, reliability and optional energy telemetry.

## L3 — CADDY × SCORECARD Fusion

- measured, verified, hardware-compatible club selection with explicit refusal states.

## L4 — Persistent SCORECARD + Route Trace

- append-only cold benchmark journal, bounded strongest-N hydration and explainable route traces.

## L5 — DATA LEECH + Context Slices

- permissioned file/repo/tool-output observation, SHA-256 deltas and disposable bounded context arenas.

## L6 — SYMBIOSIS LEDGER

- grant lifecycle, revocation/expiry, bounded observation stamps and explicit reversible ORGANIC-facing memory promotion.

## L7 — ZENKAI Verification Loop

- bounded attempt → evidence → verification → retry/stop orchestration.
- retries after attempt zero require explicit bounded retry authority.

## L8 — DOJO Trace Store

- content-addressed compact learning episodes from CADDY + ZENKAI outcomes.
- raw candidate state and route traces are represented by hashes, not retained bodies.

## L9 — CLUBHOUSE Slot Capability Bus

- content-addressed `SlotManifest` cartridges with typed capabilities, STRATA layers, permission requirements and payload ceilings.
- `READY` means a slot invocation is eligible for execution, not that execution occurred.

## L10 — FORGE Execution Adapter

- re-verifies transient payload bytes + SHA-256 against the CLUBHOUSE invocation.
- enforces wall-time/output contracts and turns executor outcomes into typed ZENKAI evidence.
- retains hashes/counters rather than raw tool transcripts.

## L11 — Native Local-Process Executor

- registry-bound absolute executables and fixed argv contracts.
- direct POSIX `fork` + `execve` and Windows `CreateProcessW`; no shell interpolation.
- canonical working-root confinement, bounded explicit environment and stdout/stderr streaming into FORGE.
- timeout/output budget exhaustion terminates the child.

## L12 — Execution Session / Transaction Orchestrator

- one opaque correlation ID and immutable `guff:session:sha256:<digest>` identity across CADDY → CLUBHOUSE → FORGE → executor → ZENKAI → DOJO.
- retries may mutate payload identity but cannot switch slot, capability or STRATA layer.
- lifecycle events and artifact metadata promotion are bounded.
- verified artifact bodies remain external; sessions retain name, locator, SHA-256 and byte count only.
- a task is not reported as completed if its terminal DOJO episode cannot be committed.

## L13 — Durable Transaction Journal / Crash Recovery

- append-only `BEGIN`, `COMMIT` and `ABORT` transaction records.
- `BEGIN` must commit before journaled execution can reach side effects.
- global sequence + SHA-256 chaining detects corruption and blocks future appends.
- interrupted sessions expose inspection metadata only; recovery never auto-replays them.

## L14 — Recovery Decision Protocol

- only `DISMISS` and `RETRY_AS_NEW_SESSION` are allowed.
- retry creates a fresh correlation/session identity and never inherits prior retry authority.
- journal-enforced lineage binds parent → recovery authorization → reserved child → child session.

## L15 — Authority Receipts / Signer Interface

- pluggable `AuthoritySigner` / `AuthorityVerifier` contracts.
- content-addressed `guff:authority:sha256:<digest>` receipts bind purpose, subject, actor, signer, nonce and exact scope.
- private signing material is never persisted in GUFF receipts.
- SpiralOS barcode transport references receipts but does not grant authority itself.

## L16 — Authority Gate

- privileged boundaries consume signed receipts rather than raw approval booleans.
- recovery, destructive execution and persistent SYMBIOSIS are purpose/subject/scope gated.
- rejected receipts produce zero executor calls and zero durable grants.

## L17 — Authority Ledger / Replay + Revocation

- receipt schema v2 binds signer key ID, machine issue/expiry timestamps and signed `max_uses`.
- durable signer-key trust, rotation/retirement, hard key revocation, receipt revocation and nonce replay defense.
- authority events are append-only and globally SHA-256 chained.
- use is durably recorded before `AuthorityGate` returns `ALLOWED`.

## L18 — Authority Delegation / Attenuation

- receipt schema v3 adds signed hierarchical `scope_path`, capability sets, parent receipt lineage and bounded delegation depth.
- child scope, capabilities, lifetime, use count and future delegation depth may only stay equal or become narrower; at least one dimension must become stricter.
- delegation consumes one parent use and reserves the child's full signed use budget, so authority cannot be cloned by branching.
- unregistered delegated children are refused even if their signatures are valid.
- ancestor receipt revocation propagates to descendants.
- capability attenuation is enforced at `AuthorityGate`, not treated as documentation metadata.

## L19 — Delegation Key Handoff / Session Keys

- a normal L18 child receipt becomes a finite root-signed **backing voucher**.
- a parent-signed `guff:key-handoff:sha256:<digest>` certificate binds that voucher to a different ephemeral signer/key fingerprint.
- the ephemeral key signs its own `guff:session-key:sha256:<digest>` receipt for exactly the voucher's scope, capabilities, lifetime and use budget.
- ephemeral keys are never promoted into the root `AuthorityLedger` trust store.
- one ephemeral `(signer_id, key_id)` may back only one registered authority branch.
- each successful session-key crossing first consumes one backing voucher use through L17/L18, then durably records one child use in `SessionKeyLedger`.
- `SessionKeyLedger` is independently SHA-256 chained and persists handoff registration, child-use counts, key revocation and child-receipt revocation.
- capability/scope/fingerprint mismatches fail before backing voucher consumption.
- upstream key/receipt/ancestor revocation automatically invalidates the session key because the backing voucher must still cross the ordinary authority gate.

## L20 — Runtime Binding / Capability Leases

- a delegated L19 session key signs a content-addressed `guff:lease:sha256:<digest>` runtime capability lease.
- every lease binds the exact hardware identity, executable SHA-256, process-instance SHA-256, CLUBHOUSE slot, immutable session ID and STRATA layer.
- lease capability, expiry and use count must fit inside the backing session-key branch.
- `RuntimeLeaseAuthorityGate` validates runtime coordinates before spending any session-key or backing-voucher authority.
- wrong device, executable, process instance, slot, session or layer is refused without consuming upstream authority.
- `RuntimeLeaseLedger` durably records lease registration, use and revocation in its own SHA-256 chain.
- process identity uses device + executable + process ID + process start time + runtime nonce; PID alone is never treated as identity.
- runtime coordinates must come from a trusted local observer; L20 defines binding/enforcement, not remote attestation by itself.

```text
MASTER AUTHORITY
      |
      v
L18 BACKING VOUCHER
      |
      v
L19 EPHEMERAL SESSION KEY
      |
      | signs exact runtime coordinate
      v
L20 CAPABILITY LEASE
      |
      | device + image + process + slot + session + STRATA
      v
RUNTIME PREFLIGHT
      |
      v
L19/L18 AUTHORITY CONSUMPTION
      |
      v
L20 DURABLE LEASE USE
      |
      v
 ALLOW / REFUSE
```

## Design laws

1. **Reality has layers.** Context must declare what layer it belongs to.
2. **Memory is a cache, not the world.** Rehydrate permitted source data on demand.
3. **Recursion is bounded.** Every loop has depth, step and confidence stop conditions.
4. **Tools beat guessing.** Deterministic operations route to deterministic tools when possible.
5. **Symbiosis is permissioned.** User authority is the root authority.
6. **Aesthetics never corrupt semantics.** CHROMA/AURA/GLYPH remain presentation metadata.
7. **Model identity is cryptographic.** A filename never establishes trust.
8. **Benchmarks are contextual.** A score without task + hardware identity is not routing evidence.
9. **Routing requires evidence.** No benchmark, no invented club selection.
10. **Persistence stays cold by default.** Disk is the corpus; RAM holds only the current working slice.
11. **Every route is explainable.** Selection and refusal gates leave a bounded trace.
12. **Perception requires a grant.** DATA LEECH cannot create its own authority or escape its granted source boundary.
13. **Hot context is disposable.** Source bodies remain external; task-local slices have hard byte/count budgets.
14. **Observation is not memory.** Seeing a source never silently promotes it into ORGANIC.
15. **Authority has lifecycle.** Grants can be pending, revoked or expired and are checked at action time.
16. **Promotion is explicit and reversible.** Only permitted, stamped facts may be promoted, and promoted summaries can be forgotten.
17. **Retries require authority.** A failed attempt does not automatically grant another execution attempt.
18. **Verification requires evidence.** Success is not accepted solely because a model says it succeeded.
19. **Self-correction is budgeted.** Attempts, tools, evidence and traces all have hard ceilings.
20. **Learning traces are summaries, not surveillance.** DOJO stores compact outcomes and hashes, not raw working context.
21. **Training evidence is content-addressed.** Episode identity changes when its meaningful compact record changes.
22. **Replay is bounded.** Learning history remains cold until a specific query hydrates a finite slice.
23. **Programs are cartridges, not fused organs.** CLUBHOUSE defines a common capability contract while domain executors stay separate.
24. **A slot cannot mint authority.** Permission requirements must be satisfied by authority supplied from outside the slot bus.
25. **Eligibility is not execution.** A `READY` invocation has passed the bus contract only; executor evidence is still required.
26. **FORGE re-verifies input identity.** A transient payload cannot be executed if it differs from the invocation hash/byte contract.
27. **Execution output is bounded and disposable.** FORGE keeps compact hashes/counters/evidence rather than raw tool transcripts.
28. **Execution evidence follows execution.** Refused invocations never masquerade as tool runs.
29. **Native execution is registry-bound.** The request cannot choose an arbitrary executable.
30. **Shell syntax is data.** Native payloads are never interpolated through a shell.
31. **Process reality is scoped.** Working directories must remain inside the registered root and environment state is bounded.
32. **Budgets terminate work.** Native children are stopped when time/output authority is exhausted.
33. **One task has one transaction identity.** Correlation survives routing, execution, verification and learning-record commit.
34. **Retries cannot change the operation class.** Payloads may mutate, but slot, capability and STRATA remain fixed inside a session.
35. **Artifacts remain external.** A session promotes bounded content-addressed metadata, not artifact bodies.
36. **Completion includes the terminal record.** If DOJO cannot commit the terminal episode, the session is not fully completed.
37. **Durable intent precedes side effects.** A journaled session cannot execute until its BEGIN record exists.
38. **Journal integrity is global.** Sequence and hash-chain failure blocks further transaction appends.
39. **Recovery is observation, not authority.** Discovering interrupted work never grants replay or retry permission.
40. **Missing terminal state stays unresolved.** A failed terminal append leaves the BEGIN visible for human recovery instead of inventing closure.
41. **Recovery decisions require fresh human authority.** Inspection alone can never choose DISMISS or RETRY.
42. **Recovery retry creates a child transaction.** Parent correlation, session identity and execution state are never reused.
43. **Retry authority is non-inheritable.** A recovery child receives only the retry authority explicitly present in the new recovery authorization.
44. **Recovery lineage is journal-enforced.** Reserved child correlations can start only through the matching parent + authorization proof.
45. **A signature is not timeless authority.** Current key, expiry, revocation and use state are checked at every privileged boundary.
46. **Receipt policy is signed.** Key identity, expiry and use count cannot be changed without invalidating the receipt.
47. **Authority consumption is durable before side effects.** If the usage event cannot be recorded, execution is refused.
48. **Nonce reuse cannot mint fresh authority.** A signer-key nonce may bind to only one immutable receipt identity.
49. **Key rotation is explicit.** Retiring issuance and hard revocation are separate state transitions.
50. **Barcode transport is never the trust root.** Scan integrity only delivers a receipt reference; the Ring decides whether it remains authorized.
51. **Delegation attenuates; it never amplifies.** Child scope/capabilities/lifetime/uses/depth cannot exceed the parent.
52. **Delegation consumes a finite budget.** Parent use plus reserved descendant uses cannot exceed signed parent authority.
53. **Delegation lineage is durable.** A child that is not registered in the cold authority chain is not authorized.
54. **Ancestor revocation propagates.** A valid child signature cannot outlive revoked parent authority.
55. **Root signing material is never handed off.** Session keys use separate key identities.
56. **Ephemeral keys are branch-bound, not root-trusted.** Their authority exists only through an exact registered voucher handoff.
57. **Key identity includes key material.** A signer/key label without the signed SHA-256 fingerprint is insufficient.
58. **Every session-key use spends backing authority.** A child cannot create more uses than its L18 voucher owns.
59. **One ephemeral key cannot union branches.** Reusing one key for independent authority branches is refused.
60. **Session-key state is durable and fail-closed.** Broken replay, revocation or storage failure never becomes authorization.
61. **A session key is not portable runtime authority.** A valid key can still be unusable outside its leased environment.
62. **PID is not process identity.** Runtime identity includes executable, process start, device and nonce.
63. **Runtime mismatch burns no upstream authority.** Coordinate validation precedes L19/L18 consumption.
64. **Runtime leases attenuate session keys.** Capability, lifetime and uses cannot exceed the backing branch.
65. **Lease use is durable before side effects.** Both backing authority and runtime lease use must be recorded.
66. **Runtime observation is evidence.** Untrusted request fields cannot self-assert device/process identity.
67. **Lease revocation is independent.** A runtime lease can be killed without revoking the broader session key.

## Build

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Next

L21 should add a trusted runtime attestation provider interface that measures the local device, executable image and process instance instead of accepting those coordinates from application code, while preserving L20's exact lease contract.
