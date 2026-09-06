# GOLF GUFF L26 — Release Hardening / V1 Gate

L26 is the architectural stop for the first Ring foundation. It does not add a new authority domain. It proves that the existing domains fail closed under corruption, storage failure, unresolved operator state, and incomplete release evidence.

## Release gate

`RingReleaseGate` consumes an `OperatorConsoleSnapshot` plus explicit, content-addressed release evidence. Its immutable result identity is `guff:ring-release:sha256:<digest>`.

A release is blocked unless all of the following are true:

- operator aggregate state is healthy;
- policy registry, transaction/recovery journal, authority ledger, runtime identity store, and operator review queue are individually healthy;
- an active signed policy exists and its signer/package provenance resolves;
- no interrupted transaction remains unresolved;
- no `HUMAN_REVIEW` ticket remains pending;
- `mutation-corpus` evidence exists and passed;
- `storage-failure-injection` evidence exists and passed;
- `regression-suite` evidence exists and passed;
- `operator-cli` evidence exists and passed;
- `cross-platform-ci` evidence exists and passed.

Release evidence is never inferred from environment variables or the fact that the process happens to run in CI. The evidence manifest is an explicit input so the decision can be reproduced elsewhere.

## Evidence manifest

`GOLF-GUFF-RELEASE-CHECK <state-root> <evidence.tsv>` accepts tab-separated lines:

```text
PASS\tmutation-corpus\t<sha256>\tdeterministic cold-journal mutation campaign
PASS\tstorage-failure-injection\t<sha256>\tappend failures remained fail-closed
PASS\tregression-suite\t<sha256>\tfull CTest suite
PASS\toperator-cli\t<sha256>\tread-only operator CLI smoke
PASS\tcross-platform-ci\t<sha256>\tUbuntu + Windows + hardened Linux
```

`FAIL` is a valid evidence state but blocks release. Duplicate evidence names, malformed SHA-256 values, or over-budget evidence make the release input invalid.

## Adversarial validation

`guff.release_adversarial` creates valid cold journals, then runs deterministic byte-mutation campaigns against the operator-review and transaction-journal grammars. Single-byte mutations, truncation, duplicated records, and garbage tails must all produce unhealthy replay state.

The same test injects storage failure by replacing a would-be journal parent directory with a regular file. Review and transaction append attempts must return typed storage failures and must not mutate valid source journals.

## Sanitizer lane

`GUFF_ENABLE_SANITIZERS=ON` enables AddressSanitizer and UndefinedBehaviorSanitizer on non-MSVC builds. CI runs the full test suite in a dedicated hardened Linux Debug job in addition to the normal Ubuntu and Windows Release jobs.

## Release laws

1. **Green tests are evidence, not authority.** Test success cannot grant runtime capabilities.
2. **Release is default-blocked.** Missing proof never becomes implied success.
3. **Corruption is a blocker, not a warning.** Any unhealthy durable trust surface blocks v1.
4. **Unresolved work blocks release.** Interrupted transactions and pending human review must be resolved explicitly.
5. **Adversarial evidence is content-addressed.** The release decision binds the exact evidence digest supplied.
6. **The release checker is read-only.** It cannot activate policy, resolve review, consume authority, recover work, or execute tools.
7. **Sanitizer-clean is part of hardening.** Memory/UB diagnostics are first-class release evidence.
8. **L26 closes architecture, not product evolution.** Future work should integrate real models, cartridges, HAKUI/XENON, UI, benchmarks, and deployment on top of the frozen Ring contracts rather than continuing an unbounded foundation ladder.
