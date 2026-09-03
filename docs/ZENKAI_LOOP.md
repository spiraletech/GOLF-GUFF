# ZENKAI Verification Loop

L7 adds bounded self-correction to the Ring without granting an agent unlimited retries or hidden execution authority.

## Contract

`ZenkaiLoop` owns orchestration and budgets. It does not own compilers, shells, tests, models or other execution tools.

The caller supplies an `AttemptFunction` that receives the attempt index and previous candidate state, then returns:

- the candidate state produced by that attempt;
- typed execution evidence;
- a verifier outcome;
- whether the attempt produced new information;
- whether a fatal failure occurred.

This keeps ZENKAI usable for code repair, tool workflows, HAKUI state mutation, XENON generation or other future slots without fusing those executors into the Ring core.

## Retry authority

Attempt zero is always evaluable. Any attempt after zero requires:

`RetryAuthority::Bounded`

Without that grant the loop returns `RETRY_NOT_AUTHORIZED` after the first failed attempt. A verifier, model or tool cannot create its own retry authority.

## Evidence

Evidence kinds are:

- `BUILD`
- `TEST`
- `TOOL`
- `VERIFIER`

Build/test/tool items consume the tool-event budget. All evidence consumes item and byte budgets. Individual source/detail fields are clipped to `max_detail_bytes` before accounting.

The loop records compact evidence summaries, not raw logs or artifacts. Full logs remain external and can be rehydrated through permissioned sources when needed.

## Verification

A result becomes `VERIFIED` only when both conditions are true:

1. `VerificationOutcome.passed == true`
2. `VerificationOutcome.confidence >= acceptance_confidence`

This prevents a low-confidence nominal pass from silently ending verification.

## Stop reasons

ZENKAI always exits with an explicit reason:

- `VERIFIED`
- `RETRY_NOT_AUTHORIZED`
- `NO_NEW_INFORMATION`
- `FATAL_FAILURE`
- `ATTEMPT_BUDGET`
- `TOOL_BUDGET`
- `EVIDENCE_BUDGET`

Trace entries are also bounded. Truncation is explicit through `trace_truncated`.

## Relationship to RECURSOR

`Recursor` is the general bounded reasoning primitive from L0. `ZenkaiLoop` is the execution-verification primitive.

A future orchestration layer can use RECURSOR inside one ZENKAI attempt, but ZENKAI remains authoritative over execution retries and verifier acceptance. This separation prevents extra reasoning depth from silently becoming extra execution permission.

## L8 handoff

L8 should add a compact DOJO trace store that can record successful and failed routing/ZENKAI episodes as content-addressed summaries for later SCORECARD analysis and training-data export without preserving raw transient context.
