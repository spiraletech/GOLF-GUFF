# Native Local-Process Executor

L11 adds the first real operating-system process backend behind the FORGE execution contract.

## Boundary

A local process is executable only when all three layers agree:

1. CLUBHOUSE resolves the invocation to a `READY` `LOCAL_PROCESS` slot.
2. FORGE verifies payload bytes/SHA-256 and supplies wall-time/output budgets.
3. `NativeProcessRegistry` already contains a validated binding for that exact immutable slot identity.

The request payload never selects an executable and is never parsed as a shell command.

## Registered binding

`NativeProcessBinding` contains:

- absolute executable path;
- fixed argv elements;
- payload mode (`NONE` or `SINGLE_ARGUMENT`);
- absolute working root;
- absolute working directory constrained beneath that root;
- explicit environment entries;
- hard argv/environment count and byte limits.

Bindings are keyed by the slot's immutable `guff:slot:sha256:...` identity. Changing meaningful slot metadata changes the identity and therefore requires a new process binding.

## No shell interpolation

The backend launches the registered executable directly.

On POSIX it uses `fork` + `execve`. On Windows it uses `CreateProcessW` with an explicit application path and Windows argv quoting. It does not invoke `/bin/sh`, `cmd.exe`, PowerShell, `system()`, or an equivalent shell surface.

When payload mode is `SINGLE_ARGUMENT`, the entire transient FORGE payload becomes exactly one argv element. Shell-looking bytes such as `&`, `|`, `<`, `>`, quotes or spaces therefore remain data for the child program.

## Working directory and environment

Registration fails unless both working root and working directory exist and the canonical working directory is contained by the canonical root.

The environment is explicit and bounded. The backend does not add arbitrary environment variables from the request. Environment names are validated and duplicate names are rejected.

## Output and timeout

stdout and stderr are redirected into one pipe and continuously drained into `ForgeOutputSink`.

- crossing the FORGE output ceiling causes the child to be terminated;
- crossing the FORGE wall-time ceiling causes the child to be terminated;
- exit status is returned through `ForgeExecutorReport`;
- FORGE remains responsible for converting the report into `BUILD`, `TEST`, or `TOOL` evidence and for discarding raw output after hashing/counter extraction.

The executor therefore enforces the budget while the child is alive instead of merely noticing an overrun after a synchronous callback returns.

## Portability

The regression self-spawns the test executable on both CI platforms and checks:

- literal argv preservation with shell metacharacters;
- exact bounded environment delivery;
- stdout and stderr streaming;
- valid working-directory confinement;
- timeout termination;
- non-zero exit propagation;
- output-budget termination;
- refusal of escaped working directories, invalid environment keys, duplicate bindings and non-local slot transports.

## L12 handoff

L12 should add the first execution session/orchestrator that composes CADDY → CLUBHOUSE → FORGE → native executor → ZENKAI → DOJO as one bounded task transaction with a shared correlation ID and explicit artifact/evidence promotion rules.
