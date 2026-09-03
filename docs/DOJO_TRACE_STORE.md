# DOJO Trace Store

L8 gives GOLF GUFF a cold, content-addressed learning record for successful, failed and budget-stopped routing/verification episodes.

## Purpose

DOJO is not a transcript archive and not an always-resident vector database.

Its job is to preserve enough compact evidence to answer questions such as:

- Which verified model tends to succeed on this task/profile/hardware?
- Which route patterns repeatedly end in `NO_NEW_INFORMATION`?
- How many attempts and tool events are normally required before verification?
- Which compact episodes should be exported for evaluator development, adapter training or routing-policy analysis?

## Episode contract

A `DojoEpisode` stores:

- task class and profile;
- exact GOLF hardware identity;
- exact GOLF model identity when a model was selected;
- route status;
- success/failure/aborted outcome;
- ZENKAI stop reason;
- verified flag;
- attempt, evidence-item and tool-event counts;
- SHA-256 of final candidate state;
- SHA-256 of the route trace description;
- SHA-256 outcome signature;
- compact human-readable summary;
- timestamp label;
- bounded tags.

It does **not** store the raw final candidate state or raw route trace.

`make_dojo_episode()` accepts transient state only long enough to hash it. The resulting episode keeps the hashes, not the original transient strings.

## Identity

Canonical episode identity is:

`guff:dojo:sha256:<digest>`

Canonicalization includes the compact semantic record and sorts tags before hashing, so equivalent tag ordering produces the same identity.

The store validates canonical model/hardware identities before admission.

## Cold journal

`DojoStore` uses a dependency-free append-only journal.

String fields are hex encoded before tab-separated serialization so embedded whitespace cannot corrupt record framing. An episode with an existing immutable ID is rejected as a duplicate.

Malformed lines are surfaced as replay errors and skipped. They are never silently promoted into valid learning evidence.

## Bounded replay

Replay streams the journal line by line and filters on:

- task;
- outcome;
- profile;
- model;
- verified-only.

Only the latest bounded number of matching episodes are retained in memory. L8 caps a single replay/export slice at 4096 episodes.

Larger datasets should be consumed later through explicit batching/cursor semantics rather than one giant hydration.

## Export

`export_jsonl()` writes compact episode records suitable for downstream evaluation or training preparation.

Exports include summaries, counters and hashes. They do not reconstruct or export raw prompt text, source bodies, context slices, candidate bodies or tool transcripts.

## Relationship to SCORECARD

SCORECARD measures benchmark runs.

DOJO records compact real workflow episodes.

A later layer can compare these two evidence streams to improve CADDY routing while keeping benchmark claims and lived workflow traces distinguishable.

## L9 handoff

L9 should add SLOT CAPABILITY BUS / CLUBHOUSE so external executors can advertise typed capabilities and permission requirements through one common Ring contract.
