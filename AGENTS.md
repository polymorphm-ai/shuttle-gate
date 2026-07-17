# Repository Guidelines

## Project Layout

Keep the dependency-free host launchers at `./shuttle-gate` and `./test`.
Application code belongs in `src/shuttle_gate/`, unit tests in `tests/unit/`,
privileged tests in `tests/integration/`, and operational guidance in `docs/`.
Runtime definitions stay in `Dockerfile` and `docker-compose.yml`. Use
`README.md` as the documentation index and consult the architecture, security,
configuration, and development guides before changing those areas.

## Development Commands

- `./shuttle-gate config validate` validates configuration without starting the gateway.
- `./shuttle-gate doctor` checks Docker, kernel networking, SSH, and remote Python.
- `./shuttle-gate up`, `status`, `logs`, and `down` manage the gateway.
- `./test` runs formatting, linting, strict typing, and unit tests in Docker.
- `./test --integration` adds disposable privileged kernel/network tests.
- `docker compose config --quiet` validates the Compose definition.

Keep application dependencies and quality tools inside Docker. Do not create a
host virtual environment or install project packages on the host.

## Code and Tests

Support the minimum Python version declared in `pyproject.toml`. Use four-space
indentation, complete type annotations, small auditable functions, `snake_case`
for modules/functions, and `PascalCase` for classes/models. Ruff and strict mypy
must pass without warnings or errors.

Keep subprocess command structure program-controlled. Pass arguments as
sequences, map user choices to allowlisted options, and place validated dynamic
operands after `--` or a command-specific boundary. Treat every shell or
interpreter boundary as a new parser: avoid interpolated program text and ad-hoc
quoting. If an interpreter is unavoidable, keep its source static and pass
values through positional arguments or a controlled environment. Never use
`shell=True` with dynamic data.

Prefer current, native Linux interfaces and actively maintained components. Do
not introduce deprecated commands or compatibility layers when a supported
native interface exists. Treat changes to security-critical networking backends
as design changes: update the architecture, security guidance, and integration
coverage. Name pytest files `test_<area>.py` and tests `test_<behavior>`. Unit
tests must not need privileges or network access; inject external command
execution. Maintain at least 90% coverage and keep privileged tests opt-in. See
`docs/development.md` for the detailed test and implementation rules.

## Security and Changes

Follow `docs/security.md`: keep secrets untracked and mounts read-only, preserve
fail-closed routing, keep the host clean, and never let the toolkit modify the
remote SSH server. It may print manual key-setup instructions but must not run
them.

Use short Conventional Commit subjects. Pull requests should explain behavior
and security impact, list tests run, and keep unrelated refactors separate.
