# Execution Session / Transaction Orchestrator

L12 turns the Ring's routing and execution primitives into one bounded transaction.

A session begins with an opaque `correlation_id`. The base FORGE invocation must use that exact prefix (`<correlation_id>:...`). Retry requests may change payload identity, but they may not switch slot, capability or STRATA layer. This prevents a retry from silently becoming a different operation.

## Lifecycle

```text
SESSION CREATED
      |
      v
CADDY ROUTE
      |
      v
CLUBHOUSE RESOLVE
      |
      v
ZENKAI ATTEMPT LOOP
      |
      +--> FORGE --> EXECUTOR --> typed evidence
      |                    |
      +------ retry <-------+
      |
   VERIFIED
      |
      v
ARTIFACT PROMOTION
metadata only: name / locator / SHA-256 / bytes
      |
      v
DOJO COMMIT
      |
      v
SESSION COMPLETED
```

## Transaction identity

`guff:session:sha256:<digest>` is derived from the correlation ID, exact hardware identity, task/profile, base invocation identity, slot/capability/layer and input digest. The session result also contains a compact `audit_sha256` over bounded lifecycle events, promoted artifact metadata and the committed DOJO episode identity.

## Retry discipline

Retries still require ZENKAI authority. In addition, L12 enforces transaction continuity:

- every retry invocation ID must keep the session correlation prefix;
- slot ID is immutable for the transaction;
- requested capability is immutable;
- STRATA layer is immutable;
- payload/hash may change so a failed candidate can actually be repaired;
- no retry planner means no invented mutation and ZENKAI stops on no new information.

## Artifact promotion

Artifact bodies remain external. A collector may nominate compact metadata only: logical name, locator, SHA-256 and byte count. Promotion occurs only after verified success and under hard artifact-count and total-byte ceilings. Invalid or over-budget candidates are rejected individually without retaining their bodies.

## DOJO commit

A session that reaches ZENKAI is committed to DOJO as success, failure or aborted evidence. DOJO tags carry the opaque correlation ID, immutable session ID and artifact counters. Pre-execution routing/permission refusals do not masquerade as execution episodes.

A verified tool run is not considered a fully completed L12 session if the terminal DOJO record cannot be committed.

## Privacy / memory discipline

The transaction record contains IDs, hashes, counters, bounded event descriptions and artifact metadata. Raw request payloads, compiler output, source slices and artifact bodies are not copied into the session audit or DOJO journal.

## L13 handoff

L13 should add a durable transaction journal with explicit BEGIN / COMMIT / ABORT markers and crash-recovery inspection. Interrupted executions must be discoverable, but never automatically replayed without fresh retry authority.
