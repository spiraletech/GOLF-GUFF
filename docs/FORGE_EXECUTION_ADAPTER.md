# FORGE Execution Adapter

L10 adds the Ring's first standardized execution boundary.

FORGE does not contain a shell, compiler, Git client, XENON engine, HAKUI engine or model runtime. It consumes a `SlotInvocation`, resolves it through CLUBHOUSE, verifies the transient payload against the invocation's byte count and SHA-256 identity, then hands a bounded request to a caller-supplied executor adapter.

## Contract

Execution order is fixed:

1. validate non-zero FORGE budgets;
2. verify payload byte count + SHA-256 identity;
3. resolve the invocation through CLUBHOUSE;
4. refuse unless CLUBHOUSE returns `READY`;
5. call the supplied executor adapter;
6. capture output through a bounded `ForgeOutputSink`;
7. measure wall time and compare it with the request budget;
8. convert the result into typed ZENKAI evidence;
9. discard raw output when the call returns.

`ForgeExecutionResult` retains status, immutable slot identity, exit code, timing, output counters, a SHA-256 of the bounded captured output and compact evidence. It does not retain the raw payload or raw executor output.

## Statuses

- `COMPLETED`
- `INVALID_REQUEST`
- `INVOCATION_REJECTED`
- `INPUT_MISMATCH`
- `EXECUTOR_ERROR`
- `TIMEOUT`
- `OUTPUT_BUDGET`
- `EXECUTION_FAILED`

Pre-execution refusals do not create tool evidence because no tool was executed. Once an executor actually runs, FORGE emits one typed evidence item. `CODE_BUILD` becomes `BUILD`, `CODE_TEST` becomes `TEST`, and other slot capabilities become `TOOL` evidence.

## Output discipline

Executors write output through `ForgeOutputSink`. The sink stores at most `max_output_bytes`; once that ceiling is crossed it marks the stream truncated and rejects additional retention. The result keeps only the captured prefix digest and byte counters.

This keeps FORGE memory-light even when a compiler or creative tool is noisy. A future process backend should stop/drain the child when the sink reports overflow rather than continue producing useless output.

## Time discipline

FORGE measures callback wall time and also accepts an executor-reported elapsed time. The larger value is compared with `max_wall_time_ms`.

L10 is the adapter contract, not OS process isolation: a synchronous callback cannot be forcibly preempted by the Ring core. A future native local-process backend must enforce the same budget with child-process termination/cancellation.

## ZENKAI + DOJO

```text
CLUBHOUSE READY
      |
      v
    FORGE
      |
      +-- bounded execution
      +-- output hash/counters
      |
      v
ZENKAI EVIDENCE
 BUILD / TEST / TOOL
      |
      v
 ZENKAI RESULT
      |
      v
 DOJO EPISODE
```

DOJO continues to store compact outcome summaries and hashes rather than raw tool transcripts.

## L11 handoff

L11 should add the first executor registry + native local-process backend: argv-based process launch without shell interpolation, granted working-directory constraints, bounded environment, stdout/stderr streaming into `ForgeOutputSink`, timeout termination and portable Windows/Linux process evidence.
