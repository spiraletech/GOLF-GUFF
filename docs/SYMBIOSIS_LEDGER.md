# SYMBIOSIS LEDGER

L6 gives GOLF GUFF a compact, inspectable contract for adapting to a user without turning observation into silent permanent memory.

## Authority first

`SymbiosisLedger` does not create permission. It records and enforces `SymbiosisGrant` objects whose source boundary is still defined by the L5 `SourceGrant`.

A symbiosis grant adds:

- issue time
- optional expiry time
- persistence policy
- observation-stamp retention limit
- explicit memory-promotion authority
- maximum promoted-summary size

Lifecycle is evaluated at the time an operation is attempted:

- `PENDING`
- `ACTIVE`
- `REVOKED`
- `EXPIRED`
- `MISSING`

Revocation is explicit and immediately blocks new observation stamps and promotions.

## Retention policy

`RetentionPolicy` separates three independent decisions:

1. whether the grant itself survives restart;
2. whether compact observation stamps survive restart;
3. whether the user permits explicit memory promotion.

Persistent observation stamps require a persistent grant. Session-only grants can therefore disappear completely when the process ends.

Observation stamps are bounded per grant. L6 does not preserve raw source bodies in the ledger.

## Observation stamp

A stamp stores only:

- grant ID
- immutable source ID
- content SHA-256
- source size
- STRATA layer
- observation timestamp

The ledger verifies the source identity is bound to the grant ID and locator using the same content-addressed source identity scheme as DATA LEECH.

## Memory promotion

Observation is not promotion.

`promote_memory()` requires:

- an active grant;
- `allow_memory_promotion=true`;
- a matching prior observation stamp for the exact source ID + content hash;
- a non-empty summary within the configured byte cap.

The ledger stores the compact summary, not the source body. The promotion receives:

`guff:memory:sha256:<digest>`

A promotion can later be explicitly forgotten. Persistent grants journal that forget event so replay preserves the tombstone.

## Journal

Persistent events use a dependency-free append-only event journal:

- `G` grant
- `R` revoke
- `S` observation stamp
- `P` memory promotion
- `F` forget promotion

String fields are hex encoded so tabs and newlines cannot corrupt record boundaries. Replay reconstructs only persistent state.

The journal is intentionally not a giant semantic database. It is an authority and provenance ledger.

## L7 handoff

L7 should build the first ZENKAI verification loop on top of this authority model: attempt records, deterministic execution evidence, verifier outcomes and bounded retry permission.
