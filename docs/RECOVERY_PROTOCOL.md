# L14 — Recovery Decision Protocol

L14 converts L13 crash inspection into an explicit human decision without turning recovery into replay authority.

## Decisions

An interrupted session may receive exactly one of two explicit decisions:

- `DISMISS` — close the interrupted parent as a recovery dismissal. No child identity or retry authority is created.
- `RETRY_AS_NEW_SESSION` — close the interrupted parent and reserve a fresh child correlation identity. The child is a new transaction with its own immutable session ID, request digest, BEGIN/terminal records, ZENKAI budget and DOJO episode.

## Human authorization object

`RecoveryAuthorization` is content-addressed from:

- decision kind
- exact parent session ID
- exact parent BEGIN record SHA-256
- actor reference
- issuance timestamp
- fresh child correlation ID, when retrying
- explicitly granted child `RetryAuthority`
- explicit approval bit

The resulting `guff:recovery-auth:sha256:<digest>` is provenance, not a cryptographic signature. The caller remains responsible for establishing that the approving human is authorized to make the decision.

## Fresh authority law

A recovery retry never resumes the parent transaction. L14 creates a child `ExecutionSessionRequest` and forcibly replaces any retry authority in the supplied template with the retry authority carried by the new recovery authorization.

Therefore:

- parent correlation ID is never reused;
- parent immutable session ID is never reused;
- parent ZENKAI retry authority is never inherited;
- parent executor state is never resumed;
- parent payload/tool output is not recovered from the journal;
- the child must independently pass CADDY, CLUBHOUSE, FORGE and verification gates.

## Journal-enforced lineage

`RECOVERY_RETRY_AS_NEW_SESSION` reserves the fresh child correlation ID inside the hash-chained transaction journal. A normal `SessionJournal::begin()` cannot consume that reservation.

Only:

`begin_recovery_child(child_begin, parent_session_id, authorization_sha256)`

may commit the child's durable BEGIN. The execution-session orchestrator automatically uses this path whenever `parent_session_id` and `recovery_authorization_sha256` are present.

The journal's `RecoveryInspection::recovery_lineage` reports:

- parent session ID
- parent correlation ID
- recovery authorization SHA-256
- reserved child correlation ID
- eventual child session ID
- whether the child has actually started

A retry decision can therefore exist durably even if the new child never starts.

## Schema compatibility

L14 writes transaction-journal schema version 2 while continuing to read schema-v1 L13 BEGIN/COMMIT/ABORT records. Recovery record kinds are legal only in schema version 2.

## No implicit execution

`RecoveryDecisionProtocol::decide()` can prepare a fresh child request. It does not execute it. Execution still requires a later call through `ExecutionSessionOrchestrator`, which must commit the authorized child BEGIN before routing or side effects.

## Failure behavior

The protocol refuses:

- missing explicit approval;
- stale or incorrect parent BEGIN identity;
- a parent that is no longer interrupted;
- reused parent correlation ID;
- malformed or already-used child correlation ID;
- recovery against an unhealthy journal;
- child BEGIN with a missing or tampered authorization hash;
- ordinary BEGIN attempting to consume a reserved recovery correlation.

The invariant is simple:

> Recovery may create a new transaction only from fresh, explicit authority. It never resurrects the crashed transaction.
