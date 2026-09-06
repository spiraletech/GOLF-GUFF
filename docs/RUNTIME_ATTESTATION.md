# L21 — Trusted Runtime Attestation Provider

L21 closes the trust gap left intentionally by L20. Runtime leases still define the exact device/executable/process/slot/session/STRATA coordinate, but privileged callers no longer get to self-report those coordinates.

## Native provider

`NativeRuntimeAttestationProvider` measures the current process from the operating system on Windows and Linux:

- hashed machine identity (`guff:hardware:sha256:...`)
- actual executable SHA-256 from disk
- OS process ID
- OS process creation/start time
- process-instance digest derived from device + executable + PID + start time + challenge
- requested CLUBHOUSE slot, immutable session ID, and STRATA layer
- short-lived freshness window
- challenge nonce

Evidence is content-addressed as `guff:attestation:sha256:<digest>`.

Windows uses native Win32 process/module APIs plus the local MachineGuid registry value. Linux uses `/proc/self/exe`, `/proc/self/stat`, `/proc/stat`, and `/etc/machine-id` (or boot-id fallback). Raw machine identifiers are hashed inside the provider and are never returned in evidence.

## Privileged path

`AttestedRuntimeLeaseAuthorityGate` obtains evidence from the injected `RuntimeAttestationProvider`, validates provider identity, canonical evidence digest, challenge, requested slot/session/layer, freshness, and trust level, then passes only the measured `RuntimeBinding` into the existing L20 runtime-lease gate.

A caller can therefore request an operation but cannot supply the trusted device, executable, or process identity used to authorize it.

`AttestedRuntimeLeaseIssuer` can mint an L20 capability lease directly from valid attestation evidence so the lease coordinate and the measured coordinate are identical by construction.

## Failure rules

- stale evidence is refused before L20/L19/L18 authority is consumed
- challenge mismatch is refused
- provider mismatch is refused
- context mismatch (slot/session/layer) is refused
- malformed or tampered evidence identity is refused
- degraded machine identity is refused unless policy explicitly allows it
- attestation does not automatically execute anything

## Trust boundary

L21 is **OS-derived local attestation**, not hardware-backed remote attestation. It is suitable for preventing application-level self-assertion and copied runtime packets from crossing the local GUFF authority boundary. It does not prove the host kernel, firmware, hypervisor, or remote machine is uncompromised.

A future TPM/TEE provider can implement the same `RuntimeAttestationProvider` interface without changing L20 lease semantics.

## Doctrine

1. **The requester may request context; it may not self-attest runtime identity.**
2. **Attestation is fresh evidence, not durable authority.**
3. **Challenge binding prevents reuse of old evidence as a new observation.**
4. **Executable identity is measured from bytes, not filenames.**
5. **PID alone never establishes process identity.**
6. **Raw machine identifiers stay inside the provider.**
7. **OS-local evidence is not equivalent to TPM/remote attestation.**
8. **Attestation failure burns no upstream authority.**
