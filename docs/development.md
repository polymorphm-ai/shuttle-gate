# Development Guide

Read `AGENTS.md` before changing code. The main invariants are clean-host
execution, Python 3.14, native nftables only, strict typing, fail-closed routing,
and no toolkit changes to the SSH server.

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

`./test` builds the locked Python 3.14 test image and runs Ruff formatting,
Ruff linting, strict mypy for source/tests and both host scripts, then pytest
with branch coverage. The current gate is at least 90%.

`./test --integration` repeats the standard gate, then uses a disposable
`NET_ADMIN` container. It creates a kernel WireGuard interface, applies IPv4 and
IPv6 policy routes, generates/loads a real WireGuard configuration, installs
real native nftables TPROXY tables, and removes all objects. It does not contact
an SSH server.

## Implementation rules

- Pass subprocess arguments as sequences; never use a shell for dynamic data.
- Validate and bound every file or external input before use.
- Keep private material out of exceptions, logs, manifests, and test output.
- Syntax-check nftables transactions before application and use deterministic
  owned table names for cleanup.
- Test exact IPv4 and IPv6 commands, failure rollback, file permissions, stale
  state, redaction, and manual-only remote setup instructions.
- Do not add a host package, virtual environment, generated cache, hosted CI,
  license, or remote mutation without an explicit design decision.

Dependency updates must keep `requires-python` at Python 3.14, regenerate
`uv.lock` inside Docker, rebuild, and pass both test modes.
