# CLUBHOUSE Slot Capability Bus

L9 gives GOLF GUFF a typed cartridge contract so specialized programs can plug into the Ring without being fused into the core.

## Separation of responsibility

`ClubhouseRegistry` is a registry and policy gate. It does not launch processes, call connectors, mutate repositories or execute model inference.

A slot advertises what it can do. An invocation declares what it wants to do. CLUBHOUSE resolves whether that invocation is eligible to reach an executor.

This preserves the core law:

**GOLF owns the bus; specialized systems own their domain execution.**

## Slot manifest

`SlotManifest` carries:

- logical `slot_name` plus human display name and version;
- typed `SlotKind` and `SlotTransport`;
- a logical entrypoint;
- typed capability set;
- allowed STRATA reality layers;
- required permission tokens;
- maximum invocation payload size;
- enabled/disabled state and compact tags.

The meaningful manifest is canonicalized and receives:

`guff:slot:sha256:<digest>`

Capability, layer, permission and tag ordering does not change identity.

## Capabilities

L9 begins with typed capabilities for:

- model inference;
- code build/test;
- repository read/write;
- audio analyze/generate;
- world observe/mutate;
- image generation;
- video render;
- representation translation;
- generic deterministic tools.

The set is deliberately small and semantic. Future slot versions can extend the enum without turning the bus into app-specific code.

## Invocation envelope

`SlotInvocation` contains only the routing contract:

- invocation ID;
- immutable slot ID or registered slot alias;
- requested capability;
- STRATA layer;
- SHA-256 input identity;
- payload byte size;
- permission tokens supplied by the authority layer.

The payload itself is not stored by CLUBHOUSE.

Resolution returns one explicit state:

- `READY`
- `INVALID`
- `SLOT_NOT_FOUND`
- `SLOT_DISABLED`
- `CAPABILITY_MISSING`
- `PERMISSION_MISSING`
- `LAYER_MISMATCH`
- `PAYLOAD_TOO_LARGE`

`READY` means only that the contract is satisfied. It is not proof that execution happened.

## Example cartridges

XENON can register as an `AUDIO` local-process slot exposing `AUDIO_ANALYZE` and `AUDIO_GENERATE` on application/representation layers.

HAKUI can later register as a `WORLD` slot exposing `WORLD_OBSERVE` and separately permissioned `WORLD_MUTATE` on simulation/application layers.

GitHub can register as a connector-backed `REPOSITORY` slot with separate read and write capabilities. Compiler toolchains can register as `COMPILER` slots with `CODE_BUILD` and `CODE_TEST`.

The same Ring therefore routes between programs without pretending those programs are one monolithic executable.

## Authority law

Permission tokens are requirements, not authority generators. CLUBHOUSE never manufactures them. The caller must obtain them from the appropriate user/project/device authority layer before resolution.

## L10 handoff

L10 should add FORGE, the first executor-adapter contract: a bounded execution request/result interface that consumes only `READY` CLUBHOUSE resolutions and returns typed evidence suitable for ZENKAI and DOJO, while keeping process launch and connector implementations outside the Ring kernel.
