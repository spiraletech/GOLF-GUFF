# GOLF GUFF

**Codename:** The Ring  
**Mission:** a memory-light, recursive, reality-aware AI development console for solo developers.

GOLF GUFF is not a single GGUF. It is the routing, benchmarking, reality-model, verification and capability-bus layer that decides which local model or deterministic tool should act on which layer of a developer's reality.

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

The Ring can now run bounded self-correction attempts without hiding why another attempt was permitted:

- `ZenkaiLoop` orchestrates attempt → evidence → verification → retry/stop.
- the first attempt is always evaluable, but attempts after the first require explicit `RetryAuthority::Bounded`.
- evidence is typed as build, test, tool or verifier evidence.
- tool-event count, evidence-item count, evidence bytes, attempt count and trace length all have hard limits.
- evidence detail strings are clipped before accounting so giant logs cannot become a hidden memory sink.
- verifier success alone is insufficient; `passed=true` must also meet the configured confidence threshold.
- `NO_NEW_INFORMATION`, `FATAL_FAILURE`, `ATTEMPT_BUDGET`, `TOOL_BUDGET`, `EVIDENCE_BUDGET` and `RETRY_NOT_AUTHORIZED` are explicit stop reasons.
- ZENKAI does not execute commands by itself. The caller supplies an attempt function that returns bounded evidence and a verifier outcome.

```text
INITIAL CANDIDATE
       |
       v
   ATTEMPT #1
       |
       +---- build/test/tool evidence
       |
       v
    VERIFIER
       |
       +---- pass + confidence threshold ----> VERIFIED
       |
       +---- fatal / no-new-info / budget ---> STOP
       |
       +---- retry authority? no ------------> STOP
       |
       v yes
   ATTEMPT #2 ... bounded
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

## Build

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Next

L8 should add the first DOJO trace store: compact success/failure episodes from routes and ZENKAI runs, content-addressed outcomes and bounded replay data suitable for later SCORECARD learning, routing improvement and adapter training without retaining raw working context.
