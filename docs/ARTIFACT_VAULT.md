# L27 Artifact Vault / Upstream Resolver

L27 does not make Hugging Face, llama.cpp, or any single model host the center of GUFF.

The stable boundary is:

```text
UPSTREAM PROVIDERS
Hugging Face / local mirror / future registry / removable media
                    |
                    v
             ArtifactSourceRef
                    |
                    v
               ArtifactSpec
                    |
                    v
              ArtifactVault
          verify -> cache -> resolve
                    |
                    v
             ModelRegistry
                    |
                    v
        runner-specific adapters
          llama.cpp / future engines
```

## Why this exists

The Ring needs to distinguish **where weights came from** from **how they execute**.

`ArtifactVault` is an offline-first, content-addressed local store. It accepts a generic `FetchFunction`; network/authentication behavior lives outside the core resolver. Hugging Face is represented as the first logical upstream using `hf://<repo>@<revision>/<file>`, but the vault itself has no Hugging Face SDK dependency and stores no provider credentials.

This prevents GUFF from becoming a wrapper around one hosted inference API.

## Resolution modes

### `CACHE_ONLY`

Airplane-mode behavior. If the exact SHA-256 artifact is not already present and valid in the local vault, resolution fails. A supplied fetcher is never called.

### `ACQUIRE_IF_MISSING`

If the artifact is absent, GUFF asks a provider adapter to materialize bytes into a temporary file. GUFF then independently checks expected byte size and SHA-256 before atomically moving the artifact into the content-addressed vault.

The provider is never trusted to declare success by itself.

## Content addressing

A single-file model artifact is stored under:

```text
<vault>/sha256/<first-two-hex>/<full-sha256>/<filename>
```

The logical artifact receives:

```text
guff:artifact-source:sha256:<digest>
guff:artifact:sha256:<digest>
```

The artifact identity includes the immutable GUFF model ID, upstream source identity, expected size, and expected SHA-256.

## Hugging Face policy

Hugging Face is an **upstream cartridge warehouse**, not an execution authority.

The L27 core records only:

- provider
- repository
- pinned revision
- artifact filename
- expected size
- expected SHA-256

A Hugging Face adapter may later implement acquisition using the Hub API, `huggingface_hub`, a controlled downloader, or another approved mechanism. Tokens/credentials belong to that provider adapter and must not enter artifact identities, provenance payloads, or the local runner contract.

Public, gated, and private repositories therefore share the same GUFF artifact contract; only the external acquisition adapter differs.

## Runner separation

`GgufInferenceBridge` now accepts a verified `ResolvedArtifact` in addition to a raw local path. It refuses the artifact unless:

- resolution completed successfully;
- the artifact belongs to the exact requested immutable model ID;
- size/SHA match the registered model manifest;
- the model is registered and cryptographically verified;
- GGUF preflight succeeds;
- the configured llama.cpp executable is itself hashed and bound.

This keeps artifact acquisition independent from inference.

## Airplane-mode proof

The regression suite proves this sequence without network access:

1. cache-only resolution misses and performs zero fetch calls;
2. a fake upstream adapter installs the expected artifact;
3. upstream bytes are removed;
4. cache-only resolution succeeds from the vault with zero additional fetch calls;
5. tampering with the cached artifact is detected and fails closed.

That is the foundation for the intended GUFF benchmark:

```text
ONLINE ONCE -> ACQUIRE + VERIFY -> CACHE
                         |
                         v
                   NETWORK OFF
                         |
                         v
       ROUTER / CODER / WORLD / MEDIA CARTRIDGES
                         |
                         v
                 LOCAL RUNNERS ONLY
```

## Scope boundary

L27 currently resolves immutable **single-file model artifacts**, which covers GGUF cleanly. Multi-file generator repositories (for example Diffusers-style model trees) should use the same resolver/vault contract but need a separately specified tree-manifest and directory hashing format rather than pretending a directory is one file.
