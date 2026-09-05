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
- recovery requires `RECOVERY` authority bound to the exact parent/decision scope.
- destructive execution requires `DESTRUCTIVE_EXECUTION` authority bound to the exact session/request/slot/input contract.
- persistent SYMBIOSIS requires `PERSISTENT_SYMBIOSIS` authority; ephemeral session-local grants remain receipt-free.
- rejected receipts produce zero executor calls and zero durable grants.

## L17 — Authority Ledger / Replay + Revocation

- receipt schema v2 cryptographically binds signer key ID, machine issue/expiry timestamps and signed `max_uses`.
- `AuthorityLedger` maintains durable trusted signer-key metadata, key retirement/rotation, hard key revocation and receipt revocation.
- `(signer, key, nonce)` is bound to the first consumed receipt ID; a different receipt reusing that nonce is rejected.
- immutable receipt IDs have persistent bounded-use counters, including one-shot receipts.
- authority events are append-only and globally SHA-256 chained.
- usage is durably recorded before `AuthorityGate` returns `ALLOWED`; storage/integrity failure blocks the privileged operation.
- schema-v1 receipts remain statically verifiable but cannot cross L17 privileged boundaries because they do not contain signed lifetime/use policy.

```text
SPIRAL BARCODE
      |
      v
L15 RECEIPT SIGNATURE
      |
      v
L16 PURPOSE / SUBJECT / SCOPE
      |
      v
L17 AUTHORITY LEDGER
  | key active?
  | not expired?
  | not revoked?
  | nonce valid?
  | uses remaining?
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

## Build

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Next

L18 should add authority delegation / attenuation: parent receipts may mint narrower child capabilities only when explicitly allowed, with monotonic scope reduction, shorter expiry, lower use budgets and auditable delegation lineage.
