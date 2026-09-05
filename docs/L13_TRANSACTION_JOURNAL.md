# L13 — Durable Transaction Journal / Crash Recovery

## Purpose

L13 makes transaction intent durable before governed execution can produce side effects.

A journal-enabled `ExecutionSessionOrchestrator` must write a valid `BEGIN` record before routing or execution proceeds. The session ends with exactly one `COMMIT` or `ABORT` record when the terminal journal append succeeds.

## Record model

Each append-only journal record contains compact metadata only:

- schema version
- global sequence number
- record kind: `BEGIN`, `COMMIT`, or `ABORT`
- immutable session ID
- correlation ID
- request-contract SHA-256
- terminal session audit SHA-256 when applicable
- optional DOJO episode identity when applicable
- compact terminal status
- timestamp label supplied by the session
- previous-record SHA-256
- current-record SHA-256

The transaction journal never stores request payload bodies, stdout/stderr, source slices, artifact bodies, or model working context.

## Global integrity chain

The first record points to the all-zero SHA-256 genesis value. Every later record must point to the exact digest of the prior record.

Recovery inspection validates:

1. schema and record encoding
2. monotonic sequence continuity
3. previous-record hash continuity
4. current record content hash
5. unique immutable `BEGIN` session IDs
6. terminal record existence only for an open session
7. terminal correlation/request identity matching its `BEGIN`

Any integrity failure makes the journal unhealthy. An unhealthy journal refuses new `BEGIN` and terminal appends.

## Crash recovery

An interrupted transaction is represented by a valid `BEGIN` with no matching terminal record.

`RecoveryInspection` exposes only:

- session ID
- correlation ID
- request SHA-256
- BEGIN record SHA-256
- recorded timestamp label
- `replay_authorized = false`
- `requires_human_decision = true`

L13 deliberately has no API named `resume`, `replay`, `retry`, or `execute` on `SessionJournal`.

Recovery observation is not execution authority.

## Orchestrator rules

When a journal is supplied:

1. validate the session request
2. derive immutable session identity and request-contract digest
3. append `BEGIN`
4. only then route and resolve capability authority
5. execute through FORGE/native or another slot executor
6. verify through ZENKAI
7. commit compact learning evidence to DOJO when the session reaches that stage
8. freeze the session audit SHA-256
9. append `COMMIT` only for `SessionStatus::Completed`
10. append `ABORT` for every other journaled terminal state

If `BEGIN` fails, execution does not start.

If terminal append fails after work occurred, the orchestrator returns `JOURNAL_STORE_FAILED`. The durable `BEGIN` remains open, so later recovery inspection reports an interrupted transaction instead of manufacturing closure.

## Replay doctrine

A recovered session identity must never be reused to repeat side effects automatically.

Future recovery policy may allow a human to authorize a new child transaction derived from interrupted metadata, but it must receive a new session identity and fresh authority. That belongs to L14, not L13.
