# Repository Guidelines

## Project Layout

Keep the dependency-free host launchers at `./shuttle-gate` and `./test`.
Application code belongs in `src/shuttle_gate/`, unit tests in `tests/unit/`,
privileged tests in `tests/integration/`, and operational guidance in `docs/`.
Runtime definitions stay in `Dockerfile` and `docker-compose.yml`. Use
`README.md` as the documentation index; detailed rules live in `docs/`.

## Development Commands

- `./shuttle-gate config validate` validates configuration without starting the gateway.
- `./shuttle-gate doctor` checks Docker, kernel networking, SSH, and remote Python.
- `./shuttle-gate up`, `status`, `logs`, and `down` manage the gateway.
- `./test` runs formatting, linting, strict typing, and unit tests in Docker.
- `./test --integration` adds disposable privileged kernel/network tests.

Keep dependencies and quality tools inside Docker; never install project
packages on the host.

## Code and Tests

Support the minimum Python version declared in `pyproject.toml`. Use four-space
indentation, complete type annotations, small auditable functions, `snake_case`
for modules/functions, and `PascalCase` for classes/models. Ruff and strict mypy
must pass without warnings or errors.

Keep subprocess structure program-controlled. Pass argument sequences,
allowlist selectable options, and place validated operands after `--` or a
command-specific boundary. Treat each interpreter boundary as a new parser:
keep source static and pass values as positional arguments or a controlled
environment. Never use `shell=True` with dynamic data.

Prefer current, native Linux interfaces and actively maintained components. Do
not introduce deprecated commands or compatibility layers when a supported
native interface exists. Networking backend changes must update architecture,
security guidance, and integration coverage. Name tests `test_<behavior>` in
`test_<area>.py`. Unit tests must inject external commands and need no network or
privileges. Maintain at least 90% coverage and keep privileged tests opt-in.

Design multi-step state changes for interruption at any step. Prefer atomic
primitives; otherwise make transitions idempotent, retry-safe, crash-consistent,
and convergent. Detect partial progress, serialize conflicts, verify
postconditions before publishing success, and ensure retry or cleanup reaches a
safe state. Fail closed; reliability takes priority over optimization. See
`docs/development.md` for detailed implementation and recovery rules.

## Security and Changes

Follow `docs/security.md`: keep secrets untracked and mounts read-only, preserve
fail-closed routing, keep the host clean, and never let the toolkit modify the
remote SSH server. It may print manual key-setup instructions but must not run
them.

Use short Conventional Commit subjects. Pull requests should explain behavior
and security impact, list tests run, and keep unrelated refactors separate.
