# L1 — Pristine Model Identity

GOLF GUFF treats a model file as untrusted bytes until its identity is declared and verified.

## Identity law

A model identity is not its filename.

`ModelManifest::immutable_id()` hashes a canonical, order-stable payload containing:

- architecture and model family,
- parameter count,
- file format and quantization,
- exact file size and SHA-256,
- upstream provider/repository/revision,
- upstream source filename and source SHA-256,
- license metadata,
- minimum hardware requirements,
- capabilities and tags.

The resulting identifier is:

```text
guff:model:sha256:<64 hex characters>
```

Changing any identity-bearing field creates a new immutable ID.

## Verification

`ModelManifest::verify_file()` performs:

1. schema validation,
2. regular-file existence check,
3. exact byte-size comparison,
4. streaming SHA-256 verification.

The file hash is computed in 64 KiB chunks. Multi-gigabyte GGUFs are never loaded into memory merely to establish identity.

## Registry

`ModelRegistry` supports two admission paths:

- `register_manifest()` — register structurally valid metadata.
- `register_verified()` — verify the local file first, then admit the manifest.

Runtime loading should prefer `register_verified()`.

Duplicate immutable IDs are rejected as duplicates rather than creating multiple aliases for the same declared identity.

## Provenance rule

GOLF-generated quantizations should record the pristine upstream source revision and source SHA-256 in addition to the derived GGUF's own SHA-256.

That yields an auditable lineage:

```text
upstream master
    |
    | source SHA-256 + revision
    v
post-training / merge
    |
    v
canonical master
    |
    v
GGUF quant
    |
    | file SHA-256
    v
GOLF immutable model ID
```

L1 deliberately does not download models or trust network metadata. It establishes the identity contract that later runtime/model-slot layers must obey.
