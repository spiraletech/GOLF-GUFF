# L27 — Real GGUF / llama.cpp Inference Bridge

L27 turns the Ring's model-routing and execution architecture into a concrete GGUF execution path.

## What is implemented

`GgufInferenceBridge` binds a verified L1 `ModelManifest` to a L9 MODEL/LOCAL_PROCESS slot and an absolute `llama-cli` executable. The resulting binding is content-addressed as `guff:gguf-binding:sha256:<digest>` and records:

- exact GUFF model identity;
- canonical GGUF path and model SHA-256;
- canonical llama.cpp executable path and executable SHA-256;
- immutable generation profile;
- slot immutable identity;
- verification mode.

The bridge builds a fixed llama.cpp argv contract and sends only the prompt as the final single argument. No prompt bytes are shell-interpolated.

```text
CLUBHOUSE MODEL_INFER slot
          |
          v
GgufInferenceBridge
  |  verified ModelRegistry identity
  |  GGUF header preflight
  |  model SHA-256
  |  llama-cli SHA-256
  |  fixed generation profile
  v
NativeProcessRegistry
          |
          v
NativeLocalProcessExecutor
          |
          v
       llama-cli
```

## llama.cpp argv contract

A binding currently lowers to the following shape:

```text
llama-cli
  --model <canonical-model.gguf>
  --ctx-size <fixed-context>
  --threads <fixed-thread-count>
  --n-predict <fixed-output-limit>
  --temp <fixed-temperature>
  --top-p <fixed-top-p>
  --seed <fixed-nonnegative-seed>
  [--no-display-prompt]
  [--log-disable]
  --prompt <PROMPT-AS-ONE-ARGUMENT>
```

Generation controls are fixed at bind time. A request cannot smuggle new flags through its prompt because the prompt remains one process argument and embedded NUL bytes are refused.

## Fail-closed binding sequence

A llama.cpp binding is installed only when all of the following are true:

1. the CLUBHOUSE slot is valid, MODEL-kind, LOCAL_PROCESS, and exposes MODEL_INFER;
2. the requested model ID exists in `ModelRegistry` and is marked verified;
3. the manifest format is GGUF;
4. the model file is an absolute existing regular file whose size and SHA-256 still match the manifest;
5. the fixed GGUF header has `GGUF` magic, a supported v2/v3 version, and non-zero tensor/metadata counts;
6. `llama-cli` is an absolute existing regular file and can be SHA-256 identified;
7. the generation profile and native-process limits validate;
8. the native process registry accepts the slot binding.

No partially installed GUFF binding is exposed if preflight fails.

## Runtime verification

The default mode is `EveryExecution`. Before every inference crossing the bridge, GUFF re-verifies:

- the model remains registered and verified;
- the complete model file still matches its manifest SHA-256;
- the GGUF fixed header still passes preflight;
- the llama.cpp executable still matches the executable SHA-256 recorded at bind time.

This is intentionally conservative and can be I/O-expensive for multi-gigabyte models. L29 benchmarking should measure this cost before any optimization is introduced. `BindOnly` exists for controlled experiments, but it weakens post-bind mutation detection.

## Regression coverage

`tests/gguf_inference.cpp` uses the test binary itself as a fake `llama-cli`, so CI exercises the real direct-process launch path on Linux and Windows without downloading a model or llama.cpp. The test covers:

- valid GGUF header probing;
- verified manifest binding;
- executable/model content identities;
- content-addressed binding identity;
- literal shell-metacharacter prompt transport;
- FORGE + CLUBHOUSE integration;
- prompt ceilings;
- embedded-NUL rejection;
- invalid GGUF magic refusal;
- unverified model refusal;
- post-bind model tamper detection.

## Important boundary

L27 is a **real process bridge**, not a claim that GUFF embeds llama.cpp as a linked inference library. It deliberately uses the existing registry-bound L11 native executor so the Ring keeps one execution boundary.

The L11 working-root rule constrains the process working directory; it is not an OS security sandbox. Filesystem/network sandboxing remains a separate future hardening problem.

FORGE also continues to persist hashes/counters/evidence rather than raw model text. Interactive delivery of ephemeral model output belongs to the L28 end-to-end task path rather than being silently persisted here.

## Exit condition

L27 is complete when the bridge builds and passes the Linux, Windows, and hardened CI matrix, and a real `llama-cli` + verified GGUF can be substituted for the test double without changing the bridge contract.
