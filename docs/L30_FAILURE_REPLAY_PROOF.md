# L30 — Failure + Replay Proof

L30 makes replay a verification protocol instead of a hidden retry button.

The governing rule is:

> A replay may use a fresh correlation/session identity, but it must not silently change the task contract, hardware identity, model/artifact/runtime binding, prompt/context identity, or expected output/failure boundary.

L30 does **not** automatically execute a replay. The caller must first pass preflight, then explicitly run the ordinary L28 task path, then hand the result back to the replay verifier.

```text
SOURCE TASK
   |
   +--> completed --------------------+
   |                                  |
   |                         task-proof hashes
   |                                  |
   +--> failed -----------------------+--> L30 Replay Capsule
                              failure-proof hashes
                                         |
                                         v
                              REHYDRATE INPUTS LATER
                                         |
                                  replay preflight
                              input + hardware exact?
                                   /           \
                                 no             yes
                                 |               |
                              REFUSE         caller may run
                                                 |
                                      ordinary L28 execution
                                                 |
                                      L30 post-run verifier
                                   /      |       |       \
                               exact   output   runtime   failure
                               match    drift    drift     drift
```

## Request contract

`replay_request_contract_sha256()` hashes the replay-relevant task contract while intentionally excluding `correlation_id`.

A replay is therefore allowed to receive a fresh transaction/session identity, but the following remain bound:

- instruction content by SHA-256;
- intent, STRATA/reality layer, complexity and uncertainty;
- execution/destructive flags;
- task class and routing profile;
- SCORECARD weights, minimum score and verified-model requirement;
- ordered context-slice identities, locators, offsets and body SHA-256 values;
- context budgets;
- artifact resolve mode;
- FORGE wall/output budgets;
- permission set;
- semantic-verification requirement.

The raw instruction/context bodies are not placed inside the replay capsule.

## Completed-task replay capsule

A completed L28 task becomes a content-addressed replay capsule that binds:

- original `guff:task-proof:sha256:<digest>`;
- request-contract SHA-256;
- hardware identity;
- exact model identity;
- kernel cartridge identity;
- artifact identity;
- GGUF/llama.cpp binding identity;
- CLUBHOUSE slot identity;
- prompt SHA-256;
- context SHA-256;
- answer SHA-256;
- semantic-verification state.

The GGUF binding identity already includes executable SHA-256 and inference-profile parameters such as context size, output limit, thread count, temperature, top-p, seed and verification mode. L30 therefore detects runtime-profile drift through the binding identity instead of copying those parameters into a second authority structure.

A completed capsule is content-addressed as:

```text
guff:replay-capsule:sha256:<digest>
```

## Failure proof

L30 also makes failed task boundaries content-addressable.

`KernelFailureProof` records stable failure evidence rather than transient timing noise:

- task status;
- whether FORGE execution existed;
- FORGE status and exit code;
- request-contract SHA-256;
- hardware identity;
- selected model identity when available;
- artifact/binding/slot identity when the task reached those boundaries;
- route-trace SHA-256;
- captured-output SHA-256 when present;
- failure-reason SHA-256.

It intentionally does not include wall time, TTFT or memory telemetry because those measurements are not deterministic failure identity.

Failure proofs are content-addressed as:

```text
guff:failure-proof:sha256:<digest>
```

## Preflight law

Replay preflight is pure validation. It performs no model execution and grants no retry authority.

A replay is `READY` only when:

1. the replay capsule validates;
2. the rehydrated request-contract SHA-256 matches;
3. the current hardware identity matches.

Otherwise it returns `INPUT_DRIFT`, `HARDWARE_DRIFT`, or `INVALID_CAPSULE`.

This keeps L30 compatible with the existing L13/L14 recovery doctrine: discovering or describing past execution never mints permission to run it again.

## Post-run verification

For a completed source task, a replay is `EXACT_MATCH` only if all replay-stable identities still match:

- task status;
- model;
- cartridge;
- artifact;
- GGUF/runtime binding;
- CLUBHOUSE slot;
- hardware;
- prompt hash;
- context hash;
- semantic-verification state;
- answer hash.

Wall time and process telemetry may differ and do not invalidate deterministic semantic replay.

If identity changed before output comparison, L30 returns `RUNTIME_DRIFT`. If the exact runtime/input identity held but the answer hash changed, it returns `OUTPUT_DRIFT`.

For a failed source task, the replay result is converted into a fresh failure proof. Only an identical failure-proof identity returns `REPRODUCED_FAILURE`; a different failure class/reason/output/runtime boundary returns `FAILURE_DRIFT`.

## Regression proof

`guff.replay_proof` proves:

1. a fresh correlation ID does not alter the replay request contract;
2. unchanged request + hardware passes preflight;
3. wall-time changes alone still permit `EXACT_MATCH`;
4. instruction drift is refused before execution;
5. hardware drift is refused before execution;
6. GGUF binding drift is detected as `RUNTIME_DRIFT`;
7. answer hash drift is detected as `OUTPUT_DRIFT`;
8. a failed task produces `guff:failure-proof:sha256:<digest>`;
9. the same failure boundary is recognized as `REPRODUCED_FAILURE`;
10. a changed failure reason or unexpected success becomes `FAILURE_DRIFT`.

## Scope boundary

L30 is not a magical guarantee that every model invocation is mathematically deterministic. It proves whether the observable GUFF execution contract and output/failure identity reproduced under the same captured conditions.

Sources of nondeterminism outside GUFF's current control may still cause `OUTPUT_DRIFT`. That is the point: L30 reports drift instead of calling a merely similar rerun deterministic.

L30 also does not persist raw prompts/context, auto-retry failed work, or bypass authority/policy gates. It is a proof layer around the existing execution path.
