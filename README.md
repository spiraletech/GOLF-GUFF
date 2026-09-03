# GOLF GUFF

**Codename:** The Ring  
**Mission:** a memory-light, recursive, reality-aware AI development console for solo developers.

GOLF GUFF is not a single GGUF. It is the routing, benchmarking, reality-model, verification, capability-bus and execution-contract layer that decides which local model or deterministic tool may act on which layer of a developer's reality.

## L0 — Ring Foundation

- `RealityStack` — explicit physical, OS, runtime, project, application, simulation, semantic, memory, meta and representation coordinates.
- `Caddy` — routes work toward tiny/core/deep local inference, deterministic tools or human review.
- `Recursor` — bounded recursive refinement with hard depth/step/confidence stops.
- native C++20, no third-party runtime dependency.

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
- attempts, tool events, evidence and traces all have hard ceilings.

## L8 — DOJO Trace Store

- content-addressed compact learning episodes from CADDY + ZENKAI outcomes.
- raw candidate state and route traces are represented by hashes, not retained bodies.
- append-only cold persistence, bounded replay and compact JSONL export.

## L9 — CLUBHOUSE Slot Capability Bus

- content-addressed `SlotManifest` cartridges with typed capabilities, STRATA layers, permission requirements and payload ceilings.
- stable logical aliases such as `xenon` plus immutable `guff:slot:sha256:<digest>` identities.
- `READY` means a slot invocation is eligible for execution, not that execution occurred.

## L10 — FORGE Execution Adapter

The Ring now has a standardized execution boundary without fusing a shell or domain runtime into its core:

- `ForgeExecutionRequest` carries a CLUBHOUSE invocation, transient payload and explicit wall-time/output budgets.
- payload byte count and SHA-256 must exactly match the CLUBHOUSE invocation before any executor is called.
- FORGE resolves the invocation itself and refuses execution unless CLUBHOUSE returns `READY`.
- `ForgeOutputSink` retains at most the configured output byte ceiling and marks overflow explicitly.
- raw executor output is discarded after the call; the result retains only counters and a SHA-256 of the bounded captured output.
- callback wall time plus executor-reported elapsed time are checked against the wall-time budget.
- build execution emits `BUILD` evidence, test execution emits `TEST` evidence, and all other capabilities emit `TOOL` evidence for ZENKAI.
- pre-execution refusals emit no tool evidence because no tool actually ran.
- `ForgeExecutionResult` explicitly reports `COMPLETED`, `INVALID_REQUEST`, `INVOCATION_REJECTED`, `INPUT_MISMATCH`, `EXECUTOR_ERROR`, `TIMEOUT`, `OUTPUT_BUDGET` or `EXECUTION_FAILED`.
- FORGE remains an adapter contract; it does not yet own OS process launch or cancellation.

```text
CADDY / INTENT
      |
      v
 CLUBHOUSE
 capability / STRATA / permission
      |
    READY
      |
      v
    FORGE
 input hash / byte contract
 wall-time / output budgets
      |
      v
 EXECUTOR ADAPTER
 compiler / XENON / HAKUI / GitHub / model / etc.
      |
      v
 BUILD / TEST / TOOL EVIDENCE
      |
      v
   ZENKAI
      |
      v
    DOJO
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

## Build

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Next

L11 should add the first FORGE executor registry + native local-process backend: argv-based process launch without shell interpolation, granted working-directory constraints, bounded environment, stdout/stderr streaming into `ForgeOutputSink`, timeout termination and portable Windows/Linux process evidence.
