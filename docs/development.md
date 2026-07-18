# Development Guide

Read `AGENTS.md` before changing code. The main invariants are rootless
namespace isolation, current native Linux interfaces, strict typing,
interruption-safe transitions, fail-closed routing, and no toolkit changes to
the SSH server.

## Layout and dependencies

- `shuttle-gate` plus `shuttle-gate.lock`: production PEP 723 entry point
- `test` plus `test.lock`: quality-tool and test entry point
- `src/shuttle_gate/`: typed host control plane and sandbox runtime
- `src/shuttle_gate/claim.py`: immutable host UDP-claim supervisor
- `tests/unit/`: unprivileged injected/fake tests
- `tests/integration/`: real kernel and namespace tests
- `Dockerfile`, `docker-compose.yml`: Docker integration tests only
- `docs/`: operator, security, and design documentation

Python 3.14 is the minimum language baseline, not an exact pin. Locked uv scripts
may select a newer compatible interpreter. Do not create `.venv` or install
project packages on the host; uv-managed interpreters, dependencies, and tools
remain in its user cache.

When dependencies change, keep inline script metadata and `pyproject.toml` in
sync, then update both locks:

```console
uv lock --script shuttle-gate
uv lock --script test
```

## Quality commands

```console
./test
./test --integration
```

`./test` verifies both locks, runs Ruff format/check, strict mypy over source,
tests, and launchers, then pytest with branch coverage of at least 90%. It uses
uv directly and needs no Docker. Tool caches and coverage data use a temporary
directory, so the quality gate leaves no project-local development artifacts.

`./test --integration` first repeats that gate. It then creates a short-lived
transient user service, proves XDG initialization works from a physically
read-only application tree, verifies the immutable socket-claim supervisor,
runs concurrent pasta/bubblewrap instances from unusual printable paths, proves
a duplicate UDP tuple fails without disturbing them, and exercises WireGuard,
IPv4/IPv6 policy routing, and native nftables. Finally it runs the kernel tests
in a disposable Compose service with fixed `0:0` IDs and `NET_ADMIN`. It never
contacts an SSH server.

## Interruption-safe state changes

Assume termination, timeout, power loss, or dependency failure between any two
steps. Structure mutations as prepare, apply, verify, and publish. Validate
before the first effect; never report success before durable state and external
postconditions agree.

- Prefer temporary files plus atomic replacement and fsync where durability matters.
- Otherwise make steps idempotent and partial progress detectable; retry,
  resume, or cleanup must converge on the goal or a known fail-closed state.
- Use deterministic ownership markers for files, processes, services, and
  kernel resources. Serialize operations that share state.
- Reconciliation must recognize and remove only explicitly owned staging files,
  including atomic-write temporaries left by an uncatchable process exit.
- Perform irreversible effects last. Recovery must remain safe if rollback is
  itself interrupted.
- Retry only classified transient failures, with explicit limits. Reconcile an
  unknown outcome before retrying.
- Inject failures at meaningful boundaries and test recovery and postconditions.

Persistent state is prepared under `state/generations/.staging-*`, validated,
fsynced, renamed, then published through an atomic `state/current` replacement.
Hold `.state.lock` for the entire mutation. Readers bind to one resolved
generation under a shared lock. Value-producing operations require an operation
ID whose receipt is published with the effect. SSH key-pair recovery retains a
durable journal until both files and that receipt are verified.

Runtime transitions are convergent rather than filesystem-atomic: install the
drop policy before ingress, activate WireGuard last, publish ready after checks,
attempt every cleanup independently, and rely on namespace destruction as the
final boundary.

## Implementation rules

- Keep executables and options program-controlled. Pass argument sequences,
  map choices to allowlisted options, and place validated operands after `--`
  when supported. Otherwise use a documented command boundary or reject values
  that could be parsed as options.
- Treat every shell, remote-command, or interpreter boundary as a new parser.
  Do not interpolate data into source or depend on ad-hoc quoting. Keep source
  static and pass values as positional arguments or controlled environment.
- Validate and bound every file and external input before use. Keep private
  material out of errors, logs, manifests, and test output.
- Preserve exact bind-address exposure, read-only mounts, native nftables
  syntax checks, deterministic owned names, and manual-only remote setup.
- Keep immutable application and mutable instance roots separate and
  non-overlapping in every API. Derive unit, runtime, locks, and state identity
  only from the canonical instance path.
- Pass `InstancePaths` through helpers that consume instance files. Never embed
  service-only mount paths in code callable from an operator sandbox.
- Treat command selection as an effect boundary: a `NAME` operation may update
  only that named peer unless the command explicitly declares a global effect.
- Test IPv4 and IPv6, printable unusual paths, control-character rejection,
  concurrent instances, socket conflicts, failure rollback, permissions, stale
  state, redaction, retries, and postcondition verification.
