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

The Ring now records transaction authority before execution can begin:

- `SessionJournal` is an append-only cold journal with explicit `BEGIN`, `COMMIT` and `ABORT` records.
- the orchestrator must commit `BEGIN` before CADDY/CLUBHOUSE/FORGE can reach an executor when journaling is enabled.
- duplicate immutable session IDs are refused before execution, preventing accidental replay of the same transaction identity.
- every journal record carries a global sequence number, previous-record SHA-256 and its own content-derived SHA-256.
- recovery inspection validates the entire chain plus per-session BEGIN → terminal transitions before permitting new journal appends.
- an interrupted session is a valid `BEGIN` with no terminal record.
- interrupted sessions expose only compact identity/provenance metadata and always return `replay_authorized=false` and `requires_human_decision=true`.
- recovery inspection does not expose any API that can execute, resume or retry a transaction.
- `COMMIT` is written only for a completed verified session; every other journaled terminal state becomes `ABORT`.
- terminal records bind the session request digest, final session audit SHA-256 and optional DOJO episode identity.
- payloads, tool output, source slices and artifact bodies are absent from the transaction journal.
- if terminal journal append fails after work occurred, the session reports `JOURNAL_STORE_FAILED`; recovery therefore sees the durable BEGIN as interrupted rather than fabricating a successful close.

```text
SESSION REQUEST
      |
      v
 durable BEGIN
      |
      v
CADDY -> CLUBHOUSE -> FORGE -> EXECUTOR
                         |
                         v
                      ZENKAI
                         |
                         v
                       DOJO
                         |
                         v
                 SESSION AUDIT SHA
                         |
                 +-------+-------+
                 |               |
               COMMIT          ABORT

PROCESS CRASH AFTER BEGIN
          |
          v
RECOVERY INSPECTION
  session / correlation / request hash
  replay_authorized = false
  requires_human_decision = true
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

## Build

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Next

L14 should add an explicit recovery-decision protocol: human-authorized `DISMISS` / `RETRY_AS_NEW_SESSION` decisions over interrupted transaction metadata, with parent-session lineage and no reuse of the original session identity or retry authority.
