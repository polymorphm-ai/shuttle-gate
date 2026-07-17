# Repository Guidelines

## Project Layout

Keep the locked PEP 723 launchers and adjacent lock files at `./shuttle-gate`,
`shuttle-gate.lock`, `./test`, and `test.lock`. Application code belongs in
`src/shuttle_gate/`, unit tests in `tests/unit/`, privileged tests in
`tests/integration/`, and operator guidance in `docs/`. `Dockerfile` and
`docker-compose.yml` exist only for disposable integration tests; production
uses systemd user services, pasta, and bubblewrap.

## Development Commands

- `./shuttle-gate config validate` checks local configuration without network changes.
- `./shuttle-gate doctor` checks host tools, namespaces, kernel networking, SSH, and remote Python.
- `./shuttle-gate up`, `status`, `logs`, and `down` manage the user service.
- `./test` runs lock checks, Ruff, strict mypy, and unit tests with 90% coverage.
- `./test --integration` adds native namespace tests and fixed-ID Docker tests.

Do not create a project virtual environment or install Python packages directly.
Locked scripts obtain Python 3.14+ and packages through uv's user cache.

## Code and Tests

Use four-space indentation, complete type annotations, small auditable
functions, `snake_case` for modules/functions, and `PascalCase` for classes.
Ruff and strict mypy must pass without warnings. Name tests `test_<behavior>`
in `test_<area>.py`; unit tests must inject external commands and require no
network or privilege.

Keep subprocess structure program-controlled. Pass argument sequences,
allowlist options, and put validated operands after `--` or another documented
boundary. Treat every interpreter boundary as a new parser: keep source static
and pass data as arguments or controlled environment values. Never use dynamic
data with `shell=True`.

Design multi-step changes for interruption anywhere. Prefer atomic primitives;
otherwise make steps idempotent, retry-safe, crash-consistent, and convergent.
Serialize conflicts, detect partial progress, verify postconditions before
success, and fail closed. See `docs/development.md` for recovery rules.

## Security and Changes

Use current native Linux interfaces. Keep host network state unchanged and
confine runtime effects to the rootless namespace. Mount configuration, secrets,
and state with minimum access. Never let the toolkit modify the SSH server; it
may only print manual key-setup instructions. Keep host-facing paths valid
outside the sandbox; explicit phone-config copies belong only below the ignored
`exports/` directory.

Use short Conventional Commit subjects. Pull requests must describe behavior
and security impact, list tests run, and separate unrelated refactors.
