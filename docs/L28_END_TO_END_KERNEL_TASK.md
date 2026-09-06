# L28 — End-to-End Mini-Kernel Task

L28 turns the L27 GGUF bridge + artifact vault into one bounded task path.

The governing idea is the BROLY-GUFF model: Hugging Face or another provider is only an upstream cartridge warehouse. GUFF owns local artifact identity, routing, execution, verification and provenance.

```text
UPSTREAM WAREHOUSE
Hugging Face / mirror / removable media
            |
            v
      ArtifactVault
   verify + cache once
            |
            v
       NETWORK OFF
            |
            v
       KernelRoster
 router / fast / code / world / media / deep
            |
            v
 CADDY + SCORECARD selects exact model
            |
            v
 verified cached artifact
            |
            v
 exact CLUBHOUSE slot + llama.cpp binding
            |
            v
 bounded DATA LEECH context arena
            |
            v
           FORGE
            |
            v
 local GGUF inference
            |
            v
 transient answer delivery
            |
            v
 verification + compact task proof
```

## Kernel roster

`KernelRoster` maps an immutable GUFF model ID to a role and a CLUBHOUSE slot.

Current roles:

- `kernel.router`
- `kernel.fast`
- `kernel.code`
- `kernel.world`
- `kernel.media`
- `kernel.deep`

The roster does not choose a model by itself. CADDY + SCORECARD still select the model using task class, exact hardware identity, cryptographic model verification and benchmark evidence. The roster only proves that the selected model is installed as a callable local cartridge.

## Offline-first task law

`KernelTaskRequest` defaults to `ArtifactResolveMode::CacheOnly`.

That means a normal L28 task performs no acquisition. The selected model must already exist in the content-addressed ArtifactVault. `AcquireIfMissing` remains available only when the caller explicitly supplies an external fetch adapter.

This preserves the intended lifecycle:

```text
ONLINE ONCE -> acquire -> verify -> cache
                         |
                         v
                    AIRPLANE MODE
                         |
                         v
                 execute indefinitely
```

## Exact identity crossing

Before local inference, L28 proves that all of these refer to the same immutable model:

1. CADDY selected model ID.
2. `KernelCartridge.model_id`.
3. verified `ModelRegistry` manifest.
4. resolved ArtifactVault SHA-256 + local path.
5. `GgufInferenceBridge` model ID, SHA-256 and path.
6. CLUBHOUSE `MODEL_INFER` slot.

Any mismatch fails closed before llama.cpp executes.

## Context behavior

Task context enters through `ContextSlice` objects and is admitted into a fresh `ContextArena`.

The arena has hard slice-count and byte ceilings. A duplicate or over-budget slice causes the task to fail instead of silently dropping context and pretending the model saw it.

The composed prompt is also checked against both:

- the CLUBHOUSE slot payload ceiling;
- the selected GGUF inference profile's `max_prompt_bytes`.

Context is transient. The task proof stores hashes and byte counts, not raw source bodies.

## Answer delivery

FORGE still does not persist raw executor transcripts.

L28 captures the bounded output only inside the current task call so it can be delivered to the operator/application. The durable-style provenance object stores only:

- selected model ID;
- kernel role + cartridge ID;
- artifact ID + upstream source URI;
- llama.cpp binding ID;
- slot + hardware IDs;
- prompt/context/answer SHA-256 values;
- route-trace SHA-256;
- byte counts + wall time;
- cache/semantic-verification flags.

The proof is content-addressed as:

```text
guff:task-proof:sha256:<digest>
```

## Verification boundary

L28 distinguishes two different things:

### Transport integrity

Built in. The transient answer must match the bytes, byte count and SHA-256 observed by FORGE.

### Semantic verification

Optional and task-specific. A caller may provide a verifier for deterministic markers, tests, schemas, code compilation, structured constraints, or another domain-specific truth check.

If `require_semantic_verification=true`, the task cannot complete unless a verifier explicitly passes. GUFF therefore does not confuse "the model returned bytes successfully" with "the answer is correct."

## Regression proof

`guff.kernel_task` proves the complete path with no network dependency:

1. create a stub GGUF upstream;
2. register and cryptographically verify its model manifest;
3. acquire it once into ArtifactVault;
4. bind the cached artifact to a fake llama.cpp process;
5. add benchmark evidence for the exact hardware identity;
6. install the model as `kernel.code`;
7. delete the upstream artifact;
8. run CADDY -> roster -> cache-only artifact resolution -> bounded context -> FORGE -> GGUF inference;
9. verify the transient answer;
10. produce `guff:task-proof:sha256:<digest>`;
11. confirm the provider fetcher was not called again.

The test also proves fail-closed behavior for missing semantic verification and context-budget overflow.

## Scope boundary

L28 is the first real single-task local intelligence path. It does not yet implement:

- automatic Hugging Face network clients;
- multi-file Diffusers/video model trees;
- live kernel hot-swapping under memory pressure;
- parallel multi-kernel plans;
- full benchmark telemetry collection from the just-completed inference;
- persistent task-proof journaling.

Those are later product/benchmark layers. L28's job is narrower: prove that one task can move from routed intent to the exact verified local mini-kernel, use bounded context, execute offline and return a verifiable answer without paid inference APIs.
