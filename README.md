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

The Ring can now treat an autonomous task as one bounded, auditable transaction:

- `ExecutionSessionOrchestrator` owns the lifecycle from CADDY routing through CLUBHOUSE, FORGE, executor evidence, ZENKAI verification and terminal DOJO commit.
- every session has one opaque `correlation_id` plus immutable `guff:session:sha256:<digest>` identity.
- the base FORGE invocation and every retry must retain the correlation prefix.
- retries may mutate payload identity but cannot switch slot, capability or STRATA layer.
- lifecycle events are bounded by count and per-event detail bytes.
- verified artifacts are promoted as metadata only: name, locator, SHA-256 and byte count.
- artifact count and aggregate byte budgets are hard ceilings; rejected candidates are counted without retaining bodies.
- the result includes a compact `audit_sha256` over lifecycle metadata and the terminal DOJO identity.
- sessions that reach ZENKAI are committed to DOJO as success/failure/aborted learning evidence.
- a verified execution that cannot commit its DOJO terminal record is not labeled a fully completed session.

```text
CORRELATION ID
      |
      v
    CADDY
      |
      v
 CLUBHOUSE
      |
      v
    FORGE
      |
      v
NATIVE / SLOT EXECUTOR
      |
      v
   ZENKAI  <---- bounded retry mutation
      |
   VERIFIED
      |
      v
ARTIFACT METADATA PROMOTION
      |
      v
     DOJO
      |
      v
SESSION COMMIT + AUDIT SHA
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
36. **Completion includes the terminal record.** If DOJO cannot commit the terminal episode, L12 does not report a fully completed session.

## Build

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Next

L13 should add a durable transaction journal with explicit `BEGIN` / `COMMIT` / `ABORT` markers and crash-recovery inspection. Interrupted sessions should be discoverable without automatically replaying side effects or minting fresh retry authority.
