# L25 — Operator Control Surface / Inspection Console

L25 is the first consolidated operator-facing control plane in the Ring. It does not replace any authority, identity, policy, recovery, or execution subsystem. It exposes their state in one read-first interface and routes explicit mutations back through the subsystem that owns them.

## Read-first snapshot

`OperatorConsole::snapshot()` aggregates:

- L24 signed policy-registry health, active policy/package identity, and activation generation;
- active policy author provenance (`signer_id`, algorithm, package ID, signing time);
- L13 interrupted transaction/recovery inspection;
- L17 authority-ledger health and aggregate trust/revocation/use state;
- L22 runtime device/image/process identity health and revocation counts;
- L25 human-review queue health and pending tickets.

The aggregate snapshot is healthy only when every underlying inspection is healthy. Corruption is surfaced, not hidden.

## Human review is not authorization

L23 `HUMAN_REVIEW` decisions may be promoted to durable `guff:operator-review:sha256:<digest>` tickets. Tickets retain bounded policy/operation metadata and matched rule IDs, not raw payloads or source bodies.

Review states are intentionally limited to:

- `PENDING`
- `DEFERRED`
- `REFUSED`
- `SUPERSEDED`

There is no `ALLOW` review state. Closing or acknowledging a ticket cannot create execution authority. If an action needs approval, authority must still be produced through the existing receipt/delegation/session-key/lease mechanisms and re-evaluated by policy.

The review journal is append-only, globally SHA-256 chained, bounded by ticket/record/reason/matched-rule ceilings, and cold-replayable. Duplicate closure, unknown tickets, malformed identities, capacity exhaustion, storage failure, and corrupted tails fail closed.

## Signed policy-control issuance

`OperatorConsole::issue_policy_control()` creates an L24 `SignedPolicyControl` only after reconstructing the exact registered target package and current active-policy identity.

The console fills the L24 compare-and-swap field from the registry state observed at issuance time. If policy state changes before application, L24 rejects the stale control with `ACTIVE_MISMATCH`.

Issuance and application are separate calls. The operator console never marks a control trusted merely because it created the envelope. `SignedPolicyRegistry::apply_control()` still independently verifies:

- control signer trust;
- signature integrity;
- target policy/package identity;
- expected-active compare-and-swap state;
- replay/control-ID rules;
- signer/nonce collision defense;
- policy revocation and rollback history.

A policy author can therefore use the console to sign a control object, but that object still fails if the L24 control-verifier domain does not trust the author as a policy administrator.

## Provenance

L25 adds read-only package provenance queries to `SignedPolicyRegistry`. They are available only when the underlying L24 registry scan is healthy. Provenance is reconstructed from the already-validated append-only policy journal; it does not create a second source of policy truth.

## Laws

1. **The console observes before it acts.** Aggregate inspection is the default operation.
2. **Human review is not permission.** Queue state cannot manufacture `ALLOW`.
3. **The console owns no hidden authority.** Signers and receipts come from outside the console.
4. **Issuance is not activation.** A signed control must still cross L24 verification.
5. **Stale controls fail compare-and-swap.** The operator cannot overwrite a policy change it did not observe.
6. **Provenance is inspectable.** The live rulebook exposes which signed package and author produced it.
7. **Subsystem corruption is visible.** Aggregate health fails closed if policy, recovery, authority, identity, or review state is unhealthy.
8. **Review context stays bounded.** No raw execution payload or source body is copied into the operator queue.

## L26 handoff

L26 should be the v1 release-hardening gate: fuzz/property tests for parsers and journal replay, failure injection around append/flush boundaries, deterministic corruption corpus, concurrency/single-writer assertions, sanitizer coverage where available, and a release checklist that proves all L0-L25 security invariants survive malformed and interrupted state.
