# SCORECARD Persistence and Route Trace

L4 turns SCORECARD from a process-local vector into cold persistent evidence while preserving the Ring's memory-light doctrine.

## Store model

`ScorecardStore` uses a versioned append-only text journal with one benchmark per physical line. It deliberately has no database dependency in L4.

Each record contains the complete `BenchmarkRecord` needed for later scoring. String fields are hexadecimal-escaped, including tags, so tabs, newlines and delimiter characters cannot alter the journal structure.

Before append, the record must pass the existing `BenchmarkRecord::validate()` contract. The store then streams existing records to reject duplicate `run_id` values. If an existing journal is structurally corrupt, append fails instead of extending unknown state.

## Selective hydration

A hydration request provides:

- the current `HardwareProfile`
- `TaskClass`
- optional benchmark profile name
- SCORECARD weights
- a maximum hot-record budget

The journal is scanned line-by-line. Nonmatching hardware/task/profile records never enter the hot `Scorecard`.

When more matching records exist than the hot budget, the loader continuously retains only the strongest N records under the requested SCORECARD weights. This means a 256-record RAM budget still examines the entire cold history and does not simply privilege the first 256 rows in the file.

The store reports scanned, matched, loaded and rejected counts plus whether the hot slice was truncated.

A missing store is valid empty state. It is not an error and must not cause CADDY to invent benchmark evidence.

## Route trace

Every `CaddyRouter::select()` decision now owns a `RouteTrace`.

Trace outcomes are:

- `INFO` — context or budget information
- `PASS` — a routing gate accepted evidence
- `REJECT` — a candidate failed a specific gate
- `SELECT` — the winning model was chosen
- `STOP` — routing intentionally ended without model selection

Current trace stages include the base risk gate, SCORECARD availability, benchmark profile, minimum score, per-model dedupe, registry presence, cryptographic verification, hardware contract, task capability, final selection and recursion/verification budget.

The trace has a hard 64-entry ceiling. Additional events set `truncated=true` rather than growing memory without bound.

## Memory law

The intended state hierarchy is now concrete:

```text
COLD   append-only SCORECARD journal on disk
  |
  | streaming query
  v
WARM   strongest bounded hardware/task/profile evidence slice
  |
  v
HOT    current CADDY decision + <=64 trace events
```

This is the first persistent implementation of the GOLF GUFF rule that the world is external memory and only relevant evidence should be hydrated into working state.
