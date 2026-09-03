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
- upstream source revision + SHA lineage so a derived GGUF can be traced back to its pristine master.

## L2 — SCORECARD Foundation

- `HardwareProfile` — platform, CPU architecture, logical threads, RAM and optional GPU/VRAM metadata.
- immutable `guff:hardware:sha256:<digest>` hardware identity.
- `BenchmarkRecord` — task/profile identity plus latency, throughput, memory, accuracy, tool, verifier, retry, completion and optional energy telemetry.
- `ScorecardEvaluator` — weighted quality, speed, memory-efficiency, reliability and energy-efficiency dimensions.
- fair-course ranking only on the exact same hardware identity and task class.

## L3 — CADDY × SCORECARD Fusion

- `CaddyRouter` preserves the base CADDY risk gate before model selection.
- deterministic tasks stay routed to deterministic tools.
- destructive uncertain work still escalates to human review.
- candidates must exist in the registry, pass verification by default, satisfy hardware/capability contracts, and match the benchmark profile.
- SCORECARD selects the best remaining club on the current machine.
- absent evidence produces an explicit refusal state instead of a guessed model.

## L4 — Persistent SCORECARD + Route Trace

The Ring can now keep benchmark evidence on disk without keeping the whole benchmark corpus resident in RAM:

- `ScorecardStore` is an append-only, dependency-free benchmark journal.
- string fields are hex-escaped, so tabs/newlines in metadata cannot corrupt record boundaries.
- duplicate run IDs are rejected before append.
- hydration streams the journal line-by-line and filters by exact hardware ID, task and optional profile.
- a bounded hydration limit retains the strongest matching observations seen across the whole file instead of blindly taking the first N records.
- missing stores are treated as an empty evidence source rather than a fatal condition.
- malformed records are rejected and reported without loading them as trusted evidence.
- `RouteTrace` records the exact routing path: risk gate, SCORECARD evidence, profile/score/registry/verification/hardware/capability gates, final selection and recursion/verification budget.
- route traces are bounded to 64 entries so observability cannot become an unbounded memory sink.

```text
DISK JOURNAL
    |
    | stream / filter / retain strongest N
    v
HOT SCORECARD SLICE ---> CADDY ROUTER ---> MODEL / TOOL / HUMAN
                              |
                              v
                    BOUNDED ROUTE TRACE
                 PASS / REJECT / SELECT / STOP
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

## Build

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Next

L5 should add the first permissioned DATA LEECH / context-slice layer: content-addressed source observations, delta detection and bounded task-local hydration from repos/files/tool outputs without turning ORGANIC into a giant resident database.
