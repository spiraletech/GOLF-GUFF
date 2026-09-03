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

The Ring now has a cryptographic club registry:

- `ModelManifest` — architecture, family, parameter count, GGUF/weight format, quantization, provenance, licensing, hardware requirements and capability metadata.
- immutable `guff:model:sha256:<digest>` model IDs derived from canonical manifest identity.
- streaming SHA-256 for multi-gigabyte weights without loading them into RAM.
- exact file-size + digest verification before trusted admission.
- `ModelRegistry` with validated and verified registration paths.
- upstream source revision + SHA lineage so a derived GGUF can be traced back to its pristine master.

```text
Reality -> Caddy -> Recursor -> Verify
   ^                              |
   +------------ delta -----------+

pristine master -> provenance -> GGUF -> SHA-256 -> MODEL-ID -> Registry
```

## Design laws

1. **Reality has layers.** Context must declare what layer it belongs to.
2. **Memory is a cache, not the world.** Rehydrate permitted source data on demand.
3. **Recursion is bounded.** Every loop has depth, step and confidence stop conditions.
4. **Tools beat guessing.** Deterministic operations route to deterministic tools when possible.
5. **Symbiosis is permissioned.** User authority is the root authority.
6. **Aesthetics never corrupt semantics.** CHROMA/AURA/GLYPH remain presentation metadata.
7. **Model identity is cryptographic.** A filename never establishes trust.

## Build

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Next

L2 adds the first SCORECARD hardware fingerprint and benchmark record so CADDY can route models by measured latency, memory cost and task success instead of model-name vibes.
