# Repository Guidelines

## Project Structure & Module Organization

Keep the dependency-free host launchers at `./shuttle-gate` and `./test`. Both use Python 3.14 through an offline, no-cache `uv run --script` shebang and only the standard library. Put all application code in `src/shuttle_gate/`, unit tests in `tests/unit/`, privileged Docker/network tests in `tests/integration/`, and operational documentation in `docs/`. Runtime definitions belong in `Dockerfile` and `docker-compose.yml`. Local `config.yaml`, `secrets/`, `state/`, phone configurations, and private keys must never be committed.

## Build, Test, and Development Commands

- `./shuttle-gate init` creates project-local configuration and protected state directories.
- `./shuttle-gate config validate` validates configuration in the tool container.
- `./shuttle-gate doctor` checks Docker, kernel networking, SSH, and remote Python prerequisites.
- `./shuttle-gate up`, `status`, `logs`, and `down` manage the gateway through Docker Compose.
- `./test` runs formatting, linting, strict typing, and unit tests in Docker.
- `./test --integration` also runs disposable dual-stack WireGuard/SSH network tests.
- `docker compose config --quiet` checks the static Compose definition.

All application packages and quality tools stay inside Docker images. Do not create a host virtual environment or install project packages on the host.

## Coding Style & Naming Conventions

Use Python 3.14, four-space indentation, complete type annotations, immutable validated models, and small auditable functions. Use `snake_case` for modules/functions, `PascalCase` for classes/models, and kebab-case for CLI commands. Ruff formatting and linting and strict mypy must complete with zero warnings and zero errors. Pass subprocess arguments as lists and never use `shell=True`.

Use native `nft` commands and nftables syntax only. Do not introduce `iptables`, `ip6tables`, compatibility frontends, or legacy firewall rule models.

## Testing Guidelines

Use pytest with files named `test_<area>.py` and tests named `test_<behavior>`. Unit-test logic must use injected command runners and require no network or privileges, although the standard test launcher itself runs in Docker. Cover configuration matrices, IPv4/IPv6 routes, peer lifecycle, generated files, permissions, redaction, exact external commands, nft cleanup, and failure rollback. Maintain at least 90% coverage. Keep privileged integration tests opt-in.

## Commit & Pull Request Guidelines

Use short Conventional Commit subjects, such as `feat: add dual-stack peer configs` or `fix: clean nft state on shutdown`. Pull requests must explain behavior and security impact, list tests run, and include relevant operator output. Keep unrelated refactors separate.

## Security and Isolation Rules

Keep the host clean: only Docker-managed resources and intentional project-local files may be created. WireGuard, routing, DNS, sshuttle, firewalling, Python dependencies, and tests run inside containers.

The toolkit must never modify the SSH server: no package installation, file copy, `authorized_keys` edit, firewall/routing change, or persistent process. It may only run sshuttle's temporary Python process. The tool may print a safely quoted `ssh-copy-id` instruction, but must never execute it. Mount SSH credentials read-only, require verified host keys, and never log private material.
