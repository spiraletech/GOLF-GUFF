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
- `ModelRegistry` with validated and verified registration paths.
- upstream source revision + SHA lineage so a derived GGUF can be traced back to its pristine master.

## L2 — SCORECARD Foundation

The Ring can now identify the machine and record comparable model performance:

- `HardwareProfile` — platform, CPU architecture, logical threads, RAM and optional GPU/VRAM metadata.
- immutable `guff:hardware:sha256:<digest>` IDs from canonical hardware descriptions.
- dependency-free Windows/Linux/macOS CPU + RAM discovery; GPU metadata remains explicit until a backend reports it.
- `BenchmarkRecord` — task class, profile, context/output size, prompt/gen throughput, TTFT, wall time, peak RAM/VRAM, accuracy, tool success, verifier pass rate, retries, completion and optional energy.
- `ScorecardEvaluator` — weighted 0–100 quality, speed, memory-efficiency, reliability and energy-efficiency dimensions.
- `Scorecard` — validates runs and ranks only benchmarks measured on the exact same hardware fingerprint and task class.

```text
pristine master -> provenance -> GGUF -> SHA-256 -> MODEL-ID
                                                 |
CURRENT MACHINE -> HARDWARE-ID ------------------+
                                                 v
                                  task benchmark -> SCORECARD
                                                 |
                                                 v
                                      evidence for CADDY
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

## Build

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Next

L3 connects CADDY to SCORECARD so route decisions can select a verified model by task fit, measured quality, latency and memory headroom on the current machine.
