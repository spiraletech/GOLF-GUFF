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
- global sequence + SHA-256 chaining detects corruption and blocks further transaction appends.
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

## L21 — Trusted Runtime Attestation Provider

- `RuntimeAttestationProvider` separates trusted measurement from caller-supplied request context.
- native Windows/Linux providers measure a hashed local machine identity, actual executable SHA-256, OS process ID and process creation/start time.
- attestation evidence is challenge-bound, short-lived and content-addressed as `guff:attestation:sha256:<digest>`.
- requested CLUBHOUSE slot, immutable session and STRATA layer are bound into the evidence, while device/executable/process identity comes from the provider.
- raw machine identifiers remain inside the provider and are never returned.
- `AttestedRuntimeLeaseAuthorityGate` validates provider identity, evidence digest, challenge, context, trust and freshness before forwarding the measured L20 binding.
- this is OS-derived local attestation, not TPM/TEE remote attestation.

## L22 — Runtime Identity Store

- `RuntimeIdentityStore` turns valid L21 observations into bounded cold identity continuity without turning identity into permission.
- provider-bound devices use `guff:identity-device:sha256:<digest>`.
- executable images use provider-independent content identity `guff:identity-image:sha256:<digest>`.
- provider-bound process instances use `guff:identity-process:sha256:<digest>` and preserve device/image/PID/start lineage for collision detection.
- attestation observations link identity records to slot/session/STRATA context while retaining only `SHA256(challenge)`, never the raw challenge.
- device, image and process revocation are independently durable.
- capacity limits bound device/image/process/attestation state; overflow refuses new evidence instead of silently evicting history or growing without bound.
- `IdentityTrackingRuntimeAttestationProvider` persists and validates identity continuity before L21 evidence can reach the privileged L20/L19/L18 path.
- journal sequence/hash corruption, impossible lineage, revoked identities, collisions or storage failure fail closed.
- L22 records identity facts only; it does not grant capabilities.

## L23 — Declarative Policy Engine

- `PolicyDocument` is content-addressed as `guff:policy:sha256:<digest>` and rule order is non-semantic.
- individual rules are content-addressed as `guff:policy-rule:sha256:<digest>`.
- policy combines subject, CLUBHOUSE slot/capability, STRATA layer, L22 active identity state, validated L15-L21 authority facts, and deterministic operation risk.
- decisions are exactly `ALLOW`, `REFUSE`, or `HUMAN_REVIEW`.
- every valid policy is default-deny; default-allow documents are invalid.
- empty unconstrained `ALLOW` rules are invalid so an accidental allow-all declaration cannot validate.
- required identity, authority scope, capability, and runtime-binding failures are refused before permissive rules are considered.
- risk is derived from capability + uncertainty + persistence + external side effects + destructive intent; callers do not submit a self-selected risk label.
- matching-rule conflict precedence is `REFUSE > HUMAN_REVIEW > ALLOW`; numeric priority only resolves rules with the same effect.
- evaluation traces and matched rule IDs are bounded, and evaluation has no execution/authority-consumption side effects.

## L24 — Signed Policy Registry / Activation Protocol

- canonical L23 policy bodies are signed into content-addressed `guff:policy-package:sha256:<digest>` packages.
- policy-author signer trust and policy-control signer trust are separate verifier domains.
- signed controls are content-addressed as `guff:policy-control:sha256:<digest>` and permit only `ACTIVATE`, `ROLLBACK`, or `REVOKE`.
- every control signs the exact policy/package ID, expected current active policy, actor, timestamp, nonce and reason SHA-256.
- activation uses compare-and-swap semantics; stale processes cannot replace a policy using obsolete active-state knowledge.
- immutable control IDs plus `(control signer, nonce)` binding reject replay/collision.
- `ROLLBACK` targets only a policy that was previously active; it is not an alias for arbitrary activation.
- revoking the active policy clears active state and fails closed instead of choosing an automatic fallback.
- policy registry records are append-only and globally SHA-256 chained.
- policy bodies remain external while signed identity, activation history, revocation and active version persist cold.
- `RegistryBackedPolicyEngine` rechecks the registry on every evaluation, so stale cached policy documents lose authority immediately after activation change, rollback, revocation or registry corruption.

```text
SIGNED POLICY PACKAGE
        |
        v
L24 POLICY REGISTRY <----- signed ACTIVATE / ROLLBACK / REVOKE
        |
        | active policy identity
        v
L23 POLICY ENGINE
   ^             ^
   |             |
L22 IDENTITY   L15-L21 AUTHORITY
   |             |
   +------ CLUBHOUSE / STRATA / RISK
        |
        v
 ALLOW / REFUSE / HUMAN_REVIEW
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
68. **The requester cannot self-attest.** Device, executable and process measurements come from the trusted provider.
69. **Attestation is fresh evidence, not durable authority.** Challenge/context/freshness are checked before the lease gate.
70. **Raw machine identifiers stay inside the attestor.** The Ring receives a hashed device identity.
71. **OS-local attestation is not remote attestation.** Kernel/firmware/host compromise remains outside the L21 guarantee.
72. **Identity is evidence, not permission.** Repeated observation never creates capability authority.
73. **Identity continuity is bounded.** Cold identity state has explicit device/image/process/observation ceilings.
74. **Identity revocation survives restart.** A known identity can become unusable without deleting its history.
75. **Challenges are transient.** Identity persistence stores only the challenge digest, not the raw challenge.
76. **Provider semantics are part of device/process identity.** Different attestors are not silently conflated.
77. **Executable identity is content-based.** Image bytes define the executable identity independently of filename/provider.
78. **Identity corruption fails closed.** Broken sequence, hashes, lineage or impossible replay never becomes trusted evidence.
79. **Identity persistence precedes privileged use.** Tracking failure blocks evidence before downstream authority is consumed.
80. **Policy remains separate from identity.** L22 records facts; it does not decide what those facts authorize.
81. **Policy is explicit.** CADDY routing heuristics and executor behavior are not authorization policy.
82. **Every policy is default-deny.** No matching rule never becomes permission.
83. **Denial dominates.** `REFUSE` cannot be numerically outranked by `ALLOW`.
84. **Human review is not authority.** `HUMAN_REVIEW` requests a new decision; it does not approve work.
85. **Risk is derived from operation facts.** Callers cannot lower risk by choosing a label.
86. **Identity is checked at policy time.** L22 revocation defeats a previously matching allow rule.
87. **Authority validation precedes policy permission.** L23 consumes validated authority facts; it does not replace L15-L21 gates.
88. **Policy evaluation has no side effects.** Decisions consume no authority and execute no tools.
89. **Policy identity is content-addressed.** Reordering equivalent rules does not change the policy ID.
90. **Policy explanations are bounded.** Matched rules, trace entries and reason bytes have hard ceilings.
91. **Policy authorship is not policy activation.** Author and control trust domains are separate.
92. **A running evaluator cannot silently replace its rulebook.** Active policy changes require signed control state.
93. **Activation is compare-and-swap.** A stale expected-active value cannot overwrite current policy state.
94. **Control replay is bounded by identity and nonce.** A consumed control or signer/nonce collision is refused.
95. **Rollback returns only to prior active history.** It cannot mint an untested activation path.
96. **Revocation fails closed.** Revoking the active policy produces no active policy unless a separate signed activation follows.
97. **Policy bodies remain external.** The registry persists signed content identity and activation history rather than arbitrary source bodies.
98. **Every evaluation rechecks activation.** Cached policy objects lose authority when registry state changes.
99. **Registry corruption means no policy authority.** Broken history is never treated as permission.
100. **L24 chooses the rulebook; L23 interprets it.** Neither layer executes tools or mints execution authority.

## Build

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Next

L25 should add the operator control surface / policy inspection boundary: a compact, read-first console for active policy, signer provenance, pending human-review decisions, authority/identity state, transaction recovery and signed policy-control issuance without bypassing L23/L24 semantics.
