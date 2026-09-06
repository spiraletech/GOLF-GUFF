# L31 — Releaseable GUFF Alpha

L31 closes the product-proof sequence started at L27. The goal is not to add another speculative subsystem. The goal is to make the implemented GUFF control plane packageable, auditable and explicitly scoped as an alpha.

## Governing rule

> An alpha release is not READY because a version string exists. It is READY only when the pre-existing Ring release gate is READY and the L27-L30 product proofs plus package-build evidence are all content-addressed and passing.

L31 therefore adds a second, narrower release certificate rather than weakening the existing L26 Ring release gate.

## Alpha release certificate

`AlphaReleaseGate` consumes:

- the alpha version line (`0.31.0-alpha.N`);
- the exact Git commit identity;
- a SHA-256 digest of the source tree/archive being released;
- a previously READY `guff:ring-release:sha256:<digest>`;
- content-addressed alpha evidence.

A successful evaluation produces:

```text
guff:alpha-release:sha256:<digest>
```

The certificate is stable under evidence reordering because evidence is canonicalized by name/hash/status/detail before hashing.

## Required L31 evidence

The alpha gate requires these five proof names:

1. `l27-real-gguf-bridge`
2. `l28-offline-kernel-task`
3. `l29-benchmark-memory-proof`
4. `l30-failure-replay-proof`
5. `release-package-build`

Every supplied alpha evidence item must pass. Missing, failed, duplicated or malformed evidence prevents READY.

The alpha gate also refuses:

- a blocked/invalid Ring release;
- malformed Ring release identity;
- wrong alpha version line;
- malformed Git object identity;
- missing/malformed source-tree SHA-256;
- evidence overflow or zero release-budget ceilings.

## Alpha release CLI

L31 ships `GOLF-GUFF-ALPHA-CHECK`, a read-only command-line evaluator for the alpha certificate contract.

Usage:

```text
GOLF-GUFF-ALPHA-CHECK <alpha-evidence-manifest>
```

The manifest is strict and starts with:

```text
GOLF-GUFF-ALPHA-EVIDENCE-V1
version=0.31.0-alpha.1
commit_sha=<40-or-64-hex-git-object>
source_tree_sha256=<64-hex-sha256>
ring_release_status=READY
ring_release_id=guff:ring-release:sha256:<digest>
PASS\tl27-real-gguf-bridge\t<sha256>\t<detail>
PASS\tl28-offline-kernel-task\t<sha256>\t<detail>
PASS\tl29-benchmark-memory-proof\t<sha256>\t<detail>
PASS\tl30-failure-replay-proof\t<sha256>\t<detail>
PASS\trelease-package-build\t<sha256>\t<detail>
```

Unknown fields, duplicate required fields, malformed evidence lines, missing files, missing required evidence or non-READY ring state fail closed. A READY evaluation prints the content-addressed alpha release ID and exits zero; blocked/invalid input exits non-zero.

The CLI does not mint a Ring release decision. It consumes the L26 Ring release identity supplied by the release process and evaluates only the L31 alpha envelope.

## Packaging contract

The CMake project version is `0.31.0` and install/package rules ship:

- `GOLF-GUFF`
- `GOLF-GUFF-OPERATOR`
- `GOLF-GUFF-RELEASE-CHECK`
- `GOLF-GUFF-ALPHA-CHECK`
- `guff_core`
- public GUFF headers
- project documentation
- `release/alpha-manifest.txt`

CPack produces a portable archive (`TGZ` on Unix-like hosts, `ZIP` on Windows) without bundling model weights.

The package deliberately does **not** silently fetch or embed a Hugging Face model. Public/private model licensing, revision, SHA-256 and acquisition remain explicit Artifact Vault / Model Registry concerns.

## Product proof chain

```text
L27  VERIFIED LOCAL GGUF / llama.cpp BRIDGE
  |
  v
L28  OFFLINE CADDY -> KERNEL -> FORGE TASK
  |
  v
L29  MEASURED RAM / TIMING / SCORECARD PROOF
  |
  v
L30  FAILURE + REPLAY PROOF
  |
  v
L26  RING RELEASE GATE READY
  |
  v
L31  ALPHA RELEASE CERTIFICATE
  |
  v
ALPHA CHECK + INSTALL + CPACK ARCHIVE
```

## Scope boundary

`0.31.0-alpha.1` means the architecture is packaged for experimental use and repeatable testing. It does not mean:

- every GGUF/model family has been qualified;
- all llama.cpp backends have been benchmarked;
- model outputs are mathematically deterministic;
- every platform/runtime combination is production supported;
- GUFF includes third-party weights;
- the system is production-secure merely because the alpha gate passes.

The alpha certificate proves the declared GUFF release envelope and evidence set, not universal correctness.

## Regression proof

`guff.alpha_release` proves:

- a complete evidence set produces READY and a content-addressed alpha ID;
- evidence order does not change release identity;
- missing evidence blocks;
- failed evidence blocks;
- blocked Ring state blocks;
- malformed Ring identity blocks;
- wrong version, malformed commit and malformed source digest block;
- duplicate/malformed evidence is INVALID;
- zero release budgets are INVALID.

The CLI regressions additionally prove:

- a complete strict evidence manifest returns READY;
- a missing evidence manifest fails closed.

This is the end of the L27-L31 product-proof sprint. Further work should be driven by real model runs, packaging results, user-facing execution and measured defects rather than automatically adding more theoretical layers.
