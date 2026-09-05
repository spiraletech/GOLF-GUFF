# L19 — Delegation Key Handoff / Session Keys

L19 lets a narrower authority branch move onto a different ephemeral signing key without exposing the root signing key or promoting the ephemeral key into the root trust store.

## Two-layer authority

A session key is backed by a normal L18 delegated authority receipt (the **voucher**):

```text
ROOT RECEIPT
    |
    | L18 attenuation
    v
BACKING VOUCHER  -- root signer, finite uses
    |
    | parent-signed key-handoff certificate
    v
EPHEMERAL SESSION KEY
    |
    | child signature
    v
SESSION-KEY RECEIPT
```

The voucher preserves every existing L17/L18 rule: scope, capability set, expiry, use budget, parent lineage, key rotation/revocation, receipt revocation and ancestor revocation.

The child key never enters `AuthorityLedger::trust_key()`.

## Handoff certificate

`SessionKeyCertificate` binds one exact L18 voucher to:

- child signer identity
- child key identity
- signing algorithm
- SHA-256 key fingerprint
- purpose and subject
- hierarchical scope path + scope SHA-256
- exact capability set
- issue/expiry times
- exact maximum use count
- certificate nonce

The certificate is signed by the parent/root signer and content-addressed as:

`guff:key-handoff:sha256:<digest>`

## Child receipt

The ephemeral key signs a second content-addressed object:

`guff:session-key:sha256:<digest>`

The child receipt must exactly reproduce the certificate's authority dimensions. A signature over a wider scope, different capability set, altered lifetime, different key fingerprint or different backing voucher is rejected.

## One key = one branch

`SessionKeyLedger` will register one ephemeral `(signer_id, key_id)` pair for only one branch. Reusing that key for a second authority branch is refused instead of silently unioning privileges.

## Consumption law

A successful session-key authorization is two-phase and fail-closed:

1. preflight the durable handoff registration, parent certificate, child signature, key fingerprint, scope, capability, expiry/revocation and child use budget;
2. consume one use from the L18 backing voucher through the existing `AuthorityGate`;
3. durably append one child-use record to `SessionKeyLedger`;
4. only an `ALLOWED` result may be treated as authority for the caller's subsequent side effect.

If step 3 fails after the backing voucher was consumed, the operation remains refused. Authority may be burned, but it is never amplified.

## Durable journal

`SessionKeyLedger` is a separate SHA-256 chained cold journal:

- `H` — register handoff
- `U` — consume one child receipt use
- `R` — revoke an ephemeral key
- `X` — revoke one session-key receipt

Every record carries a monotonic sequence, previous-record SHA-256 and record SHA-256. Broken replay marks the ledger unhealthy and authorization fails closed.

## Revocation

There are two revocation planes:

- L19 can revoke the ephemeral key or its individual session-key receipt.
- L17/L18 can revoke the backing voucher, any ancestor receipt, or the root signer key.

Because every child use must cross the backing `AuthorityGate`, upstream revocation automatically kills the session key without sharing root private material.

## SpiralOS / cartridge use

This is the intended shape for temporary domain identities:

```text
MASTER AUTHORITY
   |
   +-- XENON session key   -> audio.generate only
   +-- HAKUI session key   -> world.mutate only
   +-- FORGE session key   -> code.build only
   +-- DEVICE session key  -> one device / short expiry
```

A Spiral Barcode may transport the certificate/receipt references, but barcode transport still does not create authority. The full certificate, child signature, handoff registration and backing voucher must all verify at use time.

## L19 laws

1. **Root signing material is never handed off.** A child receives its own key identity.
2. **Ephemeral keys are not root-trusted keys.** Their authority exists only through a registered handoff branch.
3. **Every child use is backed by one finite L18 voucher use.** Handoff cannot clone use budget.
4. **Fingerprint binds identity to key material.** Signer/key labels alone are insufficient.
5. **One ephemeral key cannot union multiple branches.** Key reuse across registered branches is refused.
6. **Upstream revocation propagates automatically.** A live child signature cannot outlive revoked backing authority.
7. **Cold replay is authoritative.** Handoff registrations, child uses and child revocations survive restart.
8. **Failure burns safely.** Persistence failure may consume authority, but it never grants an unrecorded privileged operation.
