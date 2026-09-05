# L18 — Authority Delegation / Attenuation

L18 allows a live authority receipt to transfer a strictly smaller portion of its authority into a signed child receipt without increasing the total executable authority budget.

## Core law

> A child may inherit authority. It may never amplify authority.

Delegation is therefore not a copy operation. It is a budgeted transfer recorded in the L17 authority journal.

## Why schema v3 exists

L15/L17 `scope_sha256` values are intentionally opaque content identities. Two unrelated hashes cannot prove that one scope is a subset of another.

Schema v3 adds signed, machine-comparable delegation caveats:

- `scope_path` — hierarchical resource scope.
- `capabilities` — explicit bounded capability set.
- `parent_receipt_id` — immutable parent lineage.
- `delegation_depth` — current chain depth.
- `max_delegation_depth` — absolute signed chain ceiling.

For schema v3, `scope_sha256` must equal `SHA-256(scope_path)`.

A child scope must be equal to or descend from the parent path at a `/` boundary. Its capability set must be a subset of the parent's set.

## Attenuation dimensions

A valid child preserves the parent's:

- authority purpose,
- subject identity,
- signer identity,
- signer key,
- signature algorithm.

It may only reduce:

- hierarchical scope,
- capability set,
- expiry time,
- use budget,
- future delegation depth.

At least one of those dimensions must become strictly narrower. A no-op delegation is rejected.

## Use-budget conservation

Delegation itself spends one parent use and reserves the child's complete `max_uses` budget from the parent.

For a parent with `N` signed uses:

```text
parent direct uses
+ delegation operations
+ delegated child reservations
<= N
```

The same rule applies recursively. If a five-use child delegates a two-use grandchild, one child use is spent to delegate, two uses are reserved for the grandchild, and only two direct child uses remain.

This prevents the classic delegation bug where one five-use token could mint many independent five-use children.

## Journal event

L18 adds a hash-chained authority event:

```text
D = delegation registration
```

A `D` record binds:

- parent receipt ID,
- child receipt ID,
- signer/key identity,
- parent nonce,
- child nonce,
- parent delegation-use index,
- reserved child uses,
- durable timestamp.

The event is appended before the child is considered registered.

## Gate behavior

A schema-v3 receipt with `parent_receipt_id` is unusable until its exact child→parent lineage has been registered in `AuthorityLedger`.

A cryptographically valid but unregistered child is refused with `DELEGATION_REJECTED`.

The existing L17 `AuthorityGate` therefore consumes delegated authority without a parallel bypass path.

## Revocation

Child signatures remain cryptographically valid after issuance, but authorization remains stateful.

If any registered ancestor receipt is revoked, descendants are refused at the gate. Key revocation continues to invalidate the entire key lineage.

## Deliberate L18 trust boundary

L18 keeps the signer key constant across a delegation chain. The root authority signer signs narrower receipts for different `actor_reference` values.

This avoids treating possession of a public parent receipt as proof that an arbitrary new signer may mint descendants. Cross-signer delegation requires a separate signer-handoff proof and is intentionally deferred.

## Spiral Barcode

A Spiral Barcode can transport a delegated receipt ID exactly like a root receipt ID. The barcode still grants nothing itself.

```text
barcode scan
  -> resolve receipt
  -> verify signature
  -> verify L18 parent lineage
  -> verify L17 revocation/replay/use state
  -> verify L16 purpose/subject/scope
  -> allow or refuse
```

## Failure posture

Delegation is fail-closed. Invalid scope/capability/lifetime/depth requests do not consume parent authority. Once a delegation is durably registered, its parent use and child reservation are part of the cold audit history.
