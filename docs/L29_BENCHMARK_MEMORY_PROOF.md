# L29 — Benchmark + Memory Proof

L29 turns the L28 end-to-end local mini-kernel path into a measurable execution path without inventing performance numbers.

The core rule is:

> GUFF may record only telemetry it actually observed or telemetry an execution adapter explicitly supplied as exact runner timing.

```text
L28 TASK
CADDY -> cached GGUF -> FORGE -> native llama.cpp process -> answer
                                      |
                                      +--> wall time
                                      +--> first output latency
                                      +--> peak resident memory
                                      |
                                      v
                              L29 BENCHMARK PROBE
                                      ^
                                      |
                           exact runner token timing
                         prompt/eval tokens + timings
                                      |
                                      v
                           SCORECARD BenchmarkRecord
                                      |
                                      v
                    guff:benchmark-proof:sha256:<digest>
```

## Native process telemetry

`NativeLocalProcessExecutor` now reports bounded process telemetry through `ForgeExecutorReport` and `ForgeExecutionResult`:

- wall-clock execution time;
- whether output was actually observed;
- time to first captured process output;
- whether process memory was measurable;
- peak resident-memory bytes.

On Windows, GUFF reads the child process peak working set using the OS process-memory API before the process handle is released.

On Linux, GUFF samples `/proc/<pid>/status` while the child is alive and records `VmHWM`/`VmRSS` as available. Platforms without a supported process-memory provider return telemetry as unavailable rather than fabricating zero-memory success.

The telemetry stays attached to the exact FORGE execution crossing, so a benchmark cannot silently substitute measurements from a different process.

## First output is not TTFT

L29 deliberately distinguishes **time to first process output** from **time to first model token**.

A pipe becoming readable proves that the native runner emitted bytes. It does not prove those bytes are the first generated token; a runner may emit banners, logs, warnings or metadata first.

Therefore:

- `time_to_first_output_ms` is measured directly by the native executor;
- `time_to_first_token_ms` enters SCORECARD only through `RunnerTokenTelemetry`, whose contract is exact runner/model token timing;
- GUFF refuses SCORECARD-ready token throughput when exact token telemetry is required but absent.

This prevents a fast log line from masquerading as model TTFT.

## Exact token telemetry contract

`RunnerTokenTelemetry` carries:

- prompt token count;
- generated token count;
- prompt evaluation time;
- generation evaluation time;
- time to first generated token.

All counts/timings are validated. When present, `KernelBenchmarkProbe` derives:

```text
prompt_tokens_per_second     = prompt_tokens * 1000 / prompt_eval_ms
generation_tokens_per_second = generated_tokens * 1000 / generation_eval_ms
```

The current L29 core does not scrape unstable human-readable llama.cpp logs and does not estimate token counts from bytes or characters. A llama.cpp adapter can populate this contract from a stable runner timing interface later without changing the benchmark proof schema.

## Benchmark proof

`KernelBenchmarkProbe` accepts only a completed L28 task with both execution state and `KernelTaskProvenance`.

It binds the benchmark to:

- L28 task-proof identity;
- exact immutable model ID;
- exact hardware ID;
- task class and route profile;
- first-output telemetry;
- process-memory telemetry;
- exact token telemetry when available;
- completion / verification state;
- optional externally measured VRAM and energy values.

The result is content-addressed as:

```text
guff:benchmark-proof:sha256:<digest>
```

If exact token telemetry is supplied, the proof contains a validated `BenchmarkRecord` that can be inserted directly into SCORECARD.

If token telemetry is intentionally optional, GUFF may still create a process/memory proof, but it does **not** create a SCORECARD throughput record filled with guessed zeroes or byte-derived pseudo-tokens.

## Memory proof regression

`guff.native_telemetry` launches a real child process through the existing CLUBHOUSE -> FORGE -> NativeLocalProcessExecutor boundary. The child:

1. allocates and touches a 16 MiB resident buffer;
2. delays before writing output;
3. emits a deterministic marker;
4. remains alive briefly after output.

The parent asserts:

- execution succeeds;
- first output is observed after the deliberate delay;
- first-output latency is no greater than total wall time;
- output SHA-256 matches exactly;
- Windows/Linux report measurable child resident memory;
- measured peak resident memory is non-trivial.

This is an instrumentation proof, not a claim that the CI stub has the memory profile of a real billion-parameter model.

## SCORECARD proof regression

`guff.benchmark_probe` proves that measured process telemetry plus exact runner token timing becomes a valid SCORECARD record with:

- prompt throughput;
- generation throughput;
- exact TTFT;
- wall time;
- measured peak RAM;
- verification/reliability fields;
- immutable model + hardware binding.

It also proves fail-closed behavior for:

- required token telemetry missing;
- required process-memory telemetry missing;
- hardware identity mismatch;
- incomplete L28 task state.

## What L29 proves vs. what requires a real machine

L29 proves the **measurement architecture and OS telemetry path** in CI.

A real model course still has to run on the target machine to produce meaningful numbers such as:

- Qwen / Llama / coder-kernel startup time;
- real model TTFT;
- real prompt-eval and generation tokens/sec;
- actual peak RAM for a selected quantization;
- model-switch cost;
- cold-cache versus warm-cache behavior;
- CPU/GPU-specific VRAM and energy measurements.

Those values cannot be honestly manufactured in repository CI with a stub GGUF. The L29 code exists so that when GUFF runs a real local cartridge, those measurements have a precise place to go and can become routing evidence rather than anecdotes.
