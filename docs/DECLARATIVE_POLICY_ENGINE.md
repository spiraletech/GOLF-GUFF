# L23 — Declarative Policy Engine

L23 places an explicit policy decision layer between trusted facts and privileged work.

It does **not** validate signatures, execute tools, mint authority, mutate identity state, or consume authority uses. Those responsibilities remain in L15-L22. L23 consumes already-established facts and returns one of three decisions:

- `ALLOW`
- `REFUSE`
- `HUMAN_REVIEW`

## Decision inputs

A `PolicyOperation` declares the subject, CLUBHOUSE slot, capability, STRATA layer, uncertainty, and whether the operation is destructive, persistent, externally side-effecting, identity-bound, or authority-bound.

`PolicyAuthorityFacts` represent the result of prior authority validation. The authority level is explicit:

`NONE -> SIGNED_RECEIPT -> DURABLE_RECEIPT -> DELEGATED_RECEIPT -> SESSION_KEY -> RUNTIME_LEASE -> ATTESTED_RUNTIME_LEASE`

The policy engine does not trust those facts merely because they are fields. Callers must construct them from the corresponding L15-L21 gate result. When an operation requires authority, L23 refuses missing validation, scope mismatch, capability mismatch, or missing runtime binding before permissive rules are evaluated.

When an operation requires identity, L23 validates the supplied L21 attestation identity, confirms slot/STRATA continuity, and asks the L22 `RuntimeIdentityStore` whether the device/image/process lineage remains active.

## Risk classification

Risk is derived from operation facts instead of accepted as a caller-selected label.

Base classes:

- low: model inference, repository read, audio analysis, world observation, representation translation
- moderate: build/test, audio/image/video generation
- high: repository write, world mutation, generic tool

Modifiers only raise risk:

- uncertainty >= 0.40 -> at least moderate
- uncertainty >= 0.75 -> at least high
- persistent work -> at least high
- external side effect -> at least high
- destructive work -> critical

## Policy document

`PolicyDocument` is content-addressed as:

`guff:policy:sha256:<digest>`

Each rule is content-addressed as:

`guff:policy-rule:sha256:<digest>`

Rule order is not semantic. Canonical policy identity sorts canonical rule payloads before hashing.

Every valid policy is default-deny. A document whose `default_decision` is anything except `REFUSE` is invalid. An `ALLOW` rule must narrow at least one operation dimension so an empty accidental allow-all rule cannot validate.

## Rule matching

Rules can match:

- subject prefix
- exact slot ID
- capability
- STRATA layer
- destructive / persistent / external-side-effect flags
- bounded risk range
- minimum validated authority level
- active runtime identity requirement
- validated authority requirement
- runtime binding requirement

All matching rules are retained in a bounded explanation trace.

Conflict precedence is deliberately fail-closed:

`REFUSE > HUMAN_REVIEW > ALLOW`

Numeric priority resolves only rules with the same effect. Therefore a high-priority broad allow cannot outrank an explicit deny.

## Budgets

Default ceilings:

- 256 policy rules
- 64 matched-rule IDs
- 64 trace entries
- 1024 bytes per reason/trace detail

A zero ceiling or policy larger than the rule budget returns `BUDGET_EXCEEDED` + `REFUSE`.

## Boundary law

```text
L15-L20 AUTHORITY FACTS ----+
                            |
L21 ATTESTATION ------------+--> L23 POLICY --> ALLOW / REFUSE / HUMAN_REVIEW
                            |
L22 IDENTITY CONTINUITY ----+
                            |
CLUBHOUSE CAPABILITY -------+
STRATA + OPERATION RISK ----+
```

L23 is an evaluator, not an actuator. `ALLOW` means policy permits the already-described operation; it does not execute the operation and does not create missing authority.

## Design laws

1. **Policy is explicit.** Routing heuristics are not authorization policy.
2. **Default is deny.** Absence of a matching allow never becomes permission.
3. **Denial dominates.** An explicit refuse cannot be numerically outranked by allow.
4. **Risk is derived.** Callers provide operation facts, not a self-selected risk label.
5. **Identity is checked at decision time.** Revoked L22 lineage defeats permissive rules.
6. **Authority facts must already be validated.** L23 does not replace cryptographic or durable authority gates.
7. **Review is a decision, not authority.** `HUMAN_REVIEW` does not itself approve anything.
8. **Evaluation has no side effects.** L23 consumes no leases/receipts and executes no slots.
9. **Policy identity is content-addressed.** Rule order cannot silently change the policy digest.
10. **Explanation is bounded.** Every decision has a compact reason and finite rule trace.
