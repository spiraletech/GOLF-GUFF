# GOLF GUFF

**Codename:** The Ring  
**Mission:** a memory-light, recursive, reality-aware AI development console for solo developers.

GOLF GUFF is not a single GGUF. It is the routing, benchmarking, reality-model, verification and capability-bus layer that decides which local model or deterministic tool should act on which layer of a developer's reality.

## L0 — Ring Foundation

The first implementation deliberately starts below models and UI:

- `RealityStack` — explicit coordinates for physical, OS, runtime, project, application, simulation, semantic, memory, meta and representation layers.
- `Caddy` — routes work toward tiny/core/deep local inference, deterministic tools or human review.
- `Recursor` — bounded recursive refinement with hard depth/step/confidence stops.
- native C++20, no third-party runtime dependency.

```text
Reality -> Caddy -> Recursor -> Verify
   ^                              |
   +------------ delta -----------+
```

## Design laws

1. **Reality has layers.** Context must declare what layer it belongs to.
2. **Memory is a cache, not the world.** Rehydrate permitted source data on demand.
3. **Recursion is bounded.** Every loop has depth, step and confidence stop conditions.
4. **Tools beat guessing.** Deterministic operations route to deterministic tools when possible.
5. **Symbiosis is permissioned.** User authority is the root authority.
6. **Aesthetics never corrupt semantics.** CHROMA/AURA/GLYPH remain presentation metadata.

## Build

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

## Next

L1 adds model manifests, pristine-weight provenance and SHA-256 verification so every future GGUF loaded by the Ring has a reproducible identity.
