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

- `ModelManifest` — architecture, family, parameter count, format, quantization, provenance, licensing, hardware requirements and capability metadata.
- immutable `guff:model:sha256:<digest>` model IDs derived from canonical manifest identity.
- streaming SHA-256 for multi-gigabyte weights without loading them into RAM.
- exact file-size + digest verification before trusted admission.
- `ModelRegistry` tracks validated manifests separately from cryptographically verified model files.

## L2 — SCORECARD Foundation

- `HardwareProfile` provides immutable machine identity.
- `BenchmarkRecord` captures task-specific latency, throughput, memory, quality, tool, verifier and retry telemetry.
- `ScorecardEvaluator` produces weighted quality/speed/memory/reliability/energy scores.

## L3 — CADDY × SCORECARD Fusion

- `CaddyRouter` selects only from eligible, measured, verified models.
- deterministic work stays with deterministic tools and risky destructive work still escalates to human review.
- absent evidence produces an explicit refusal state.

## L4 — Persistent SCORECARD + Route Trace

- `ScorecardStore` keeps the benchmark corpus cold in an append-only journal.
- selective hydration retains only the strongest bounded task/hardware/profile slice.
- `RouteTrace` explains routing gates with a hard 64-entry cap.

## L5 — DATA LEECH + Context Slices

- `SourceGrant` is the explicit permission contract for a source.
- grants distinguish file, repo-file and tool-output sources plus session/project/device-local scope.
- file grants resolve paths and prevent reads outside the permitted root.
- tool-output grants enforce an explicit logical locator prefix.
- `SourceObservation` stores only source identity, locator, STRATA layer, byte size and SHA-256 content digest.
- compact previous observations enable `FIRST_SEEN`, `UNCHANGED` and `MODIFIED` delta detection without retaining source bodies.
- `ContextSlice` rehydrates only requested bytes and carries content hash + offset provenance.
- `ContextArena` bounds hot slice count and aggregate bytes, rejects duplicates, and can be cleared at task end.

## L6 — SYMBIOSIS LEDGER

The Ring can now maintain an inspectable boundary between permission, observation and memory:

- `SymbiosisGrant` wraps a `SourceGrant` with issue/expiry timestamps and explicit retention policy.
- grant lifecycle is `PENDING`, `ACTIVE`, `REVOKED`, `EXPIRED` or `MISSING`.
- session-only grants may remain entirely ephemeral; persistent grants use an append-only ledger journal.
- observation stamps retain only grant ID, source ID, SHA-256, byte size, STRATA layer and observation time.
- per-grant stamp counts are bounded; old hot stamps are evicted instead of growing without limit.
- persistent observation stamps require a persistent grant.
- memory promotion is separately permissioned and stores only an explicit compact summary, never the original source body.
- promotion requires a matching prior observation stamp for the exact source identity + content hash.
- promoted memory receives an immutable `guff:memory:sha256:<digest>` identity.
- promotions are inspectable and can be explicitly forgotten; forgetting is also journaled when persistence is enabled.
- replay reconstructs only persistent authority/stamps/promotions from the compact event journal.

```text
USER AUTHORITY
      |
      v
 SYMBIOSIS GRANT
 issue / expiry / retention
      |
      +------ revoke / expire ------> INACTIVE
      |
      v
  DATA LEECH
      |
      v
 SOURCE OBSERVATION
 hash + size + layer
      |
      v
 OBSERVATION STAMP
 bounded / optionally persistent
      |
      +---- no promotion authority ----> STOP
      |
      v
 EXPLICIT PROMOTION
 compact summary only
      |
      v
 ORGANIC-FACING MEMORY ID
      |
      +---- forget ----> tombstoned
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

## Build

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Next

L7 should add the first ZENKAI verification loop: bounded attempt records, tool/compile/test evidence, verifier outcomes and retry policy so recursion can improve a result without hiding why another attempt was allowed.
