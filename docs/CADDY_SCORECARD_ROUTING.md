# CADDY × SCORECARD Routing

L3 is the first evidence-driven model selector in the Ring.

## Separation of responsibilities

`Caddy::route()` remains the cheap risk and execution heuristic. It answers whether a task should use local inference, a deterministic tool, or human review, and assigns a bounded recursion budget.

`CaddyRouter` answers a different question: when local inference is appropriate, which measured model should receive the task?

Keeping those decisions separate prevents benchmark performance from bypassing destructive-action or deterministic-tool policy.

## Eligibility pipeline

A SCORECARD benchmark is routing evidence only when all active gates pass:

1. the benchmark task matches the requested task class;
2. the benchmark hardware ID exactly matches the current hardware profile;
3. the requested benchmark profile matches when one is specified;
4. the model ID resolves in `ModelRegistry`;
5. the model is cryptographically verified when `require_verified` is enabled (default);
6. the manifest declares the required task capability;
7. the manifest RAM/VRAM/CPU-only contract fits the current machine;
8. the benchmark reaches the optional minimum GOLF score.

Multiple benchmark observations for one model are de-duplicated after SCORECARD ranking, preserving that model's strongest eligible observation.

## Explicit refusal states

L3 never silently substitutes an unmeasured model.

- `DETERMINISTIC_PREFERRED` — a deterministic tool is the better route.
- `HUMAN_REVIEW_REQUIRED` — the base risk gate requires human authority.
- `NO_BENCHMARK_EVIDENCE` — this exact task/hardware course has no measurements.
- `NO_ELIGIBLE_MODEL` — measurements exist, but every candidate failed a trust, profile, capability, hardware or score gate.
- `SELECTED` — a model passed the complete pipeline.

## Recursion coupling

The base CADDY recursion budget remains authoritative, but SCORECARD confidence can tune it inside a hard range of 1–6 levels:

- score below 55: add two levels;
- score below 70: add one level;
- score at least 90 with very low task uncertainty: remove one unnecessary level when possible.

Execution tasks always retain verification. A high SCORECARD score is evidence of prior performance, not permission to skip verification.

## Registry verification state

L3 extends `ModelRegistry` with explicit verification state. `register_manifest()` records metadata without claiming the bytes were checked. `register_verified()` verifies exact size and streaming SHA-256 before admitting a model as verified. An existing unverified manifest can be promoted only after the same immutable model identity passes file verification.

This distinction is required because a syntactically valid manifest and a cryptographically verified local model are not the same fact.

## L4 handoff

L4 should persist SCORECARD records and route traces in a memory-light append-only store. The Ring should hydrate only the task/hardware slice needed for the current route and preserve a compact explanation trail for every decision.
