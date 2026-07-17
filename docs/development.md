# Development Guide

Read `AGENTS.md` before changing code. The main invariants are clean-host
execution, current native Linux interfaces, strict typing, interruption-safe
state transitions, fail-closed routing, and no toolkit changes to the SSH server.

## Layout

- `shuttle-gate` and `test`: dependency-free host launchers
- `src/shuttle_gate/`: typed control plane and runtime
- `tests/unit/`: unprivileged injected/fake tests
- `tests/integration/`: opt-in real kernel namespace tests
- `Dockerfile` and `docker-compose.yml`: all application and quality tooling
- `docs/`: operator and design documentation

The runtime is intentionally split into validated immutable models, protected
file/key operations, deterministic renderers, an injected command runner, and a
small lifecycle supervisor. Keep pure rendering separate from privileged I/O.

## Quality commands

```console
./test
./test --integration
docker compose config --quiet
```

`./test` builds the locked test image and runs Ruff formatting, Ruff linting,
strict mypy for source/tests and both host scripts, then pytest with branch
coverage. The current gate is at least 90%.

Python 3.14 is the minimum supported version. The container defaults to that
baseline; set `SG_PYTHON_VERSION` when checking a newer compatible Python image.
Mypy and Ruff deliberately target the minimum so code does not accidentally
require a newer interpreter.

`./test --integration` repeats the standard gate, then uses a disposable
`NET_ADMIN` container. It creates a kernel WireGuard interface, applies IPv4 and
IPv6 policy routes, generates/loads a real WireGuard configuration, installs
real native nftables TPROXY tables, and removes all objects. It does not contact
an SSH server.

## Interruption-safe state changes

Assume termination, timeout, power loss, or dependency failure between any two
steps. Structure mutations as prepare, apply, verify, and publish phases. Do all
validation before the first effect and never report success until durable state
and external postconditions agree.

- Prefer atomic primitives such as temporary files plus atomic replacement.
- When one transaction cannot cover every effect, make each step idempotent and
  make partial progress detectable. A retry, resume, or cleanup must converge on
  the desired state or a known fail-closed state.
- Use deterministic ownership markers for files, processes, containers, and
  kernel resources. Serialize operations that could mutate the same state.
- Perform irreversible effects last. Rollback is defense in depth; recovery
  must remain safe when rollback itself is interrupted.
- Retry automatically only for classified transient failures, with explicit
  limits and backoff. Unknown outcomes must be safe to reconcile before retry.
- Inject failure at every meaningful step boundary and test restart, retry,
  cleanup, and postcondition verification.

Persistent WireGuard state follows one concrete protocol: build and validate a
private `state/generations/.staging-*` tree, fsync it, rename it to its final
generation name, then atomically replace `state/current`. Hold `.state.lock`
across the complete operation. Readers must bind to the resolved generation
while holding a shared lock; never read multiple files through a moving
`current` pointer.

Operations that intentionally produce a new value, such as key rotation, need
a caller-visible operation ID. Store its receipt in the same atomic publication
as the effect. The SSH private/public pair is the exception to the generation
tree: keep its durable transaction journal until both files are verified and a
state receipt is durable. Recovery must derive every owned path from validated
journal fields rather than trusting arbitrary paths from JSON.

Runtime transitions are convergent rather than filesystem-atomic. Install the
drop policy before exposing ingress, activate the WireGuard interface last,
publish ready only after postcondition checks, attempt every independent cleanup
step, and rely on namespace destruction as the final boundary.

## Implementation rules

- Keep executables and options program-controlled. Pass subprocess arguments as
  sequences, map user choices to allowlisted options, and put validated dynamic
  operands after `--` when supported. Otherwise use a command-specific safe
  boundary or reject ambiguous values.
- Treat each shell, remote command, or interpreter boundary as a new parser. Do
  not interpolate dynamic data into program text or rely on ad-hoc quoting. If
  an interpreter is unavoidable, keep its source static and pass values through
  positional arguments or a controlled environment.
- Validate and bound every file or external input before use.
- Keep private material out of exceptions, logs, manifests, and test output.
- Syntax-check nftables transactions before application and use deterministic
  owned table names for cleanup.
- Test exact IPv4 and IPv6 commands, failure rollback, file permissions, stale
  state, redaction, and manual-only remote setup instructions.
- Do not add a host package, virtual environment, generated cache, hosted CI,
  license, or remote mutation without an explicit design decision.

Dependency updates must preserve the declared minimum Python version, regenerate
`uv.lock`, rebuild, and pass both test modes.
