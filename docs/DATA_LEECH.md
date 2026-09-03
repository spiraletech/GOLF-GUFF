# DATA LEECH / Context Slices

L5 gives the Ring a permissioned perception primitive. DATA LEECH does not own authority and does not crawl arbitrary sources. It can only observe a locator through an explicit `SourceGrant` supplied by a higher user-authority layer.

## Grants

A `SourceGrant` declares:

- grant identity;
- source kind: file, repo file, or tool output;
- scope: session, project, or device-local;
- STRATA reality layer;
- exact file root or tool-output locator prefix;
- whether a file root is recursive;
- maximum permitted source size;
- maximum bytes in one hydrated slice.

File paths are resolved before access. Recursive grants require the resolved target to remain beneath the resolved grant root. Non-recursive grants match one exact resolved path. Tool outputs must match their explicit locator prefix.

## Observations and deltas

DATA LEECH produces compact `SourceObservation` metadata:

- content-addressed `guff:source:sha256:<digest>` source ID;
- locator;
- reality layer;
- byte size;
- SHA-256 content digest.

The previous observation body is unnecessary. Passing the prior compact stamp is enough to classify the next read as `FIRST_SEEN`, `UNCHANGED`, or `MODIFIED`. Missing, denied, oversized, and read-error states stay explicit.

This is the core memory rule:

> retain identity + digest + offsets; rehydrate source bytes only when the current task needs them.

## Context slices

`slice_file()` and `slice_text()` return bounded `ContextSlice` objects. A slice carries its source identity, content hash, reality layer, locator and byte offset alongside the hydrated bytes. Per-grant slice caps prevent a request from silently pulling an entire large source into hot memory.

`ContextArena` is the task-local hot tier. It enforces maximum slice count, maximum aggregate bytes, duplicate-slice rejection, and explicit clearing when the task ends.

The arena owns no cold corpus. Files, repos, build logs and other tools remain the external memory.

## Security boundary

L5 intentionally does not persist grants or manufacture them. Grant creation, revocation, expiry and audit belong to the future SYMBIOSIS authority layer. DATA LEECH only enforces the grant it receives.

## L6 handoff

L6 should add the SYMBIOSIS LEDGER: explicit grant lifecycle, revocation/expiry, compact observation stamps, source-level retention policy and inspectable promotion into persistent ORGANIC memory.
