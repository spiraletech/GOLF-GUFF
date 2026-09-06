# L24 — Signed Policy Registry / Activation Protocol

L23 answers: **what should this operation be allowed to do?**

L24 answers: **which signed L23 policy is allowed to answer that question right now?**

## Trust separation

Policy authorship and live policy control are different authorities.

- a **policy author signer** signs the immutable `PolicyDocument` content and produces a `guff:policy-package:sha256:<digest>` package identity.
- a **policy control signer** signs `ACTIVATE`, `ROLLBACK`, or `REVOKE` transitions.
- the registry receives separate `AuthorityVerifier` instances for those trust domains.

Possessing an author key does not imply activation authority. A program evaluating policy is not given either signing capability by the registry.

## External policy bodies

The cold registry retains signed content identity and control history, not arbitrary policy source bodies. A caller that wants to evaluate a policy supplies the `PolicyDocument`; `RegistryBackedPolicyEngine` verifies that its immutable `guff:policy:sha256:<digest>` identity is the currently active, non-revoked registry identity on every evaluation.

This follows the Ring's memory-light rule: bodies can remain external while durable state records exactly which content identity is active.

## Signed policy package

A policy package signature covers:

- immutable policy ID
- signing time
- policy-author signer identity
- exact canonical L23 policy payload

Package identity is content-addressed from the signed metadata and signature.

Registration verifies the canonical policy, immutable policy identity, signer trust and signature before an append-only `REGISTER` event is accepted.

## Signed control envelope

Every control signature covers:

- `ACTIVATE`, `ROLLBACK`, or `REVOKE`
- exact package ID
- exact policy ID
- expected currently-active policy ID
- actor reference
- control signer identity
- issued timestamp
- nonce
- SHA-256 of the external human/operator reason

The expected-active field is a compare-and-swap guard. A stale process cannot activate a new policy based on an obsolete view of which policy is active.

## Replay resistance

Each control has immutable identity:

`guff:policy-control:sha256:<digest>`

The registry refuses:

- a consumed control ID
- a second distinct control that reuses the same `(control signer, nonce)` pair
- an activation whose expected-active policy does not equal current state

## Rollback and revocation

`ROLLBACK` is not an alias for ordinary activation. Its target must have been active previously and must not be revoked.

`REVOKE` permanently marks a registered policy unusable. If the revoked policy is active, the registry clears active policy state immediately. The system therefore fails closed to **no active policy** rather than silently selecting a replacement.

No automatic fallback policy is inferred.

## Cold journal

The registry journal is append-only and globally SHA-256 chained.

Record classes:

- `REGISTER`
- `ACTIVATE`
- `ROLLBACK`
- `REVOKE`

Replay reconstructs registered package identities, revocation, active policy/package IDs, used control IDs/nonces and activation generation. Sequence discontinuity, record hash mismatch, impossible state transition or malformed tail makes the registry unhealthy.

An unhealthy registry authorizes no policy evaluation.

## Evaluation boundary

`RegistryBackedPolicyEngine` checks the registry on every evaluation.

Therefore a process holding an older `PolicyDocument` cannot continue authorizing operations after:

- activation of a newer policy
- rollback to another policy
- revocation of its policy
- registry corruption

The stale engine returns `POLICY_INACTIVE` + `REFUSE` without entering the underlying L23 rule evaluator.

## Laws

1. **A policy signature proves authorship, not activation authority.**
2. **A running evaluator cannot activate its own rulebook.**
3. **Activation is compare-and-swap.** Stale control state cannot overwrite current policy state.
4. **Control nonces are single-purpose.** Re-signing a different transition with the same signer/nonce does not create fresh control authority.
5. **Rollback returns to history; it does not invent history.**
6. **Revoking the active policy fails closed.** No replacement is selected automatically.
7. **Policy bodies remain external; active content identity is durable.**
8. **Every evaluation rechecks active state.** Cached policy objects do not become permanent authority.
9. **Registry corruption is policy refusal.** Broken history cannot become an authorization source.
10. **L24 chooses the rulebook; L23 interprets it.** Neither layer executes tools or mints authority.
