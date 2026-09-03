# SCORECARD Foundation

L2 gives GOLF GUFF a reproducible performance vocabulary. Model names and parameter counts are not routing evidence; measured behavior on a known machine and task is.

## Hardware identity

`HardwareProfile` captures the minimum stable machine context needed for local inference comparisons:

- platform and CPU architecture
- logical thread count
- total system RAM
- optional GPU presence, GPU name and VRAM
- CPU name when the operating system exposes it

The canonical profile hashes to:

`guff:hardware:sha256:<digest>`

GPU discovery is intentionally not guessed in L2. A future backend may enrich the profile with accelerator telemetry, but unknown GPU data remains unknown rather than fabricated.

## Benchmark record

Every benchmark run binds:

- immutable model ID
- immutable hardware ID
- task class
- named benchmark profile
- context and output sizes
- prompt and generation throughput
- time to first token and total wall time
- peak RAM and VRAM
- accuracy
- tool success rate
- verification pass rate
- retry count and completion state
- optional energy consumption

Records are rejected if identities are malformed, ratios leave `[0,1]`, numeric telemetry is negative/non-finite, or a run ID is duplicated.

## Score dimensions

`ScorecardEvaluator` emits separate 0–100 dimensions before producing the weighted total:

- **Quality (40%)** — accuracy + tool success + verification pass rate.
- **Speed (20%)** — generation throughput + prompt throughput + TTFT response.
- **Memory efficiency (15%)** — remaining RAM headroom and, when declared, VRAM headroom.
- **Reliability (20%)** — completion, verifier/tool success and retry penalty.
- **Energy efficiency (5%)** — optional energy telemetry; unknown energy receives a neutral midpoint instead of a fabricated measurement.

Weights are configurable. Negative weights clamp to zero and an all-zero set falls back to the default profile.

## Fair-course rule

L2 only ranks records when both `task` and `hardware_id` match the requested course. Cross-hardware normalization is deferred until GUFF has enough real measurements to justify it.

This intentionally prevents a fast desktop GPU result from silently becoming the recommendation for a low-memory CPU-only laptop.

## L3 handoff

L3 should connect CADDY route requests to verified model manifests plus SCORECARD rankings. That is the first point where the Ring can say:

> For this task, on this machine, among models I have cryptographically verified and actually measured, this is the best club.
