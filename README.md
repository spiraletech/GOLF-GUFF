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

The Ring can now turn benchmark evidence into an actual model-routing decision:

- `CaddyRouter` preserves the base CADDY risk gate before model selection.
- deterministic tasks stay routed to deterministic tools.
- destructive uncertain work still escalates to human review.
- model candidates must exist in the registry and, by default, be cryptographically verified.
- candidates must satisfy the manifest hardware contract and task capability.
- benchmark profile filters prevent unrelated tasks from contaminating a route.
- duplicate benchmark runs for the same model collapse to the strongest eligible observation.
- SCORECARD rank selects the best remaining club on the current machine.
- score confidence can raise or lower the bounded recursion budget while execution keeps verification enabled.
- absent evidence produces an explicit refusal state instead of a guessed model.

```text
TASK / REALITY
      |
      v
  base CADDY --------------------> TOOL / HUMAN when appropriate
      |
      v
CURRENT HARDWARE-ID
      +-------------------+
      |                   |
VERIFIED MODEL REGISTRY   SCORECARD(task + profile + hardware)
      |                   |
      +---------+---------+
                v
         ELIGIBILITY GATES
                |
                v
          RANKED CLUBS
                |
                v
       MODEL + RECURSION BUDGET
                |
                v
             VERIFY
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

## Build

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Next

L4 should add the first persistent SCORECARD store plus route-trace records so CADDY can reload benchmark evidence without keeping it resident in memory and every selection can explain which facts caused the route.
