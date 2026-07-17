"""Protected project-local paths and atomic file operations."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import ProjectConfig
from .errors import ConfigurationError, StateError


@dataclass(frozen=True)
class InstancePaths:
    """Resolved paths for one project-local instance."""

    root: Path
    config: Path
    state: Path
    secrets: Path

    @classmethod
    def from_root(cls, root: Path) -> InstancePaths:
        resolved = root.resolve()
        return cls(
            root=resolved,
            config=resolved / "config.yaml",
            state=resolved / "state",
            secrets=resolved / "secrets",
        )

    def server_dir(self) -> Path:
        return self.state / "server"

    def peer_dir(self, name: str) -> Path:
        return self.state / "peers" / name

    def runtime_dir(self) -> Path:
        return self.state / "runtime"


def resolve_config_path(config_path: Path, configured: Path) -> Path:
    """Resolve a configured file relative to the YAML document."""

    if configured.is_absolute():
        return configured.resolve()
    return (config_path.parent / configured).resolve()


def ensure_private_directory(path: Path) -> None:
    """Create a non-symlink private directory and enforce mode 0700."""

    if path.is_symlink():
        raise StateError(f"private directory must not be a symlink: {path}")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    if not path.is_dir():
        raise StateError(f"expected a directory: {path}")


def require_private_file(path: Path, label: str) -> None:
    """Require a regular owner-only file."""

    try:
        info = path.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ConfigurationError(f"{label} does not exist: {path}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ConfigurationError(f"{label} must be a regular non-symlink file: {path}")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ConfigurationError(
            f"{label} permissions must not allow group or other access: {path}"
        )


def require_regular_file(path: Path, label: str) -> None:
    """Require a regular non-symlink file."""

    try:
        info = path.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise ConfigurationError(f"{label} does not exist: {path}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ConfigurationError(f"{label} must be a regular non-symlink file: {path}")


def validate_ssh_files(config: ProjectConfig, config_path: Path) -> tuple[Path, Path]:
    """Resolve and validate SSH identity and known-host files."""

    identity = resolve_config_path(config_path, config.ssh.identity_file)
    known_hosts = resolve_config_path(config_path, config.ssh.known_hosts_file)
    require_private_file(identity, "SSH identity")
    require_regular_file(known_hosts, "SSH known-hosts file")
    return identity, known_hosts


def container_secret_path(configured: Path) -> Path:
    """Map a project-local ``secrets/`` path into the gateway mount."""

    if configured.is_absolute():
        raise ConfigurationError("SSH files must use project-relative secrets/ paths")
    parts = configured.parts
    if len(parts) < 2 or parts[0] != "secrets" or ".." in parts:
        raise ConfigurationError("SSH files must be located below the project secrets/ directory")
    return Path("/secrets").joinpath(*parts[1:])


def atomic_write(path: Path, data: str, mode: int) -> None:
    """Atomically replace one UTF-8 file with explicit permissions."""

    ensure_private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        path.chmod(mode)
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def atomic_write_json(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    """Write deterministic JSON atomically."""

    atomic_write(path, json.dumps(value, indent=2, sort_keys=True) + "\n", mode)


def read_text_secret(path: Path, label: str) -> str:
    """Read a private one-line state file."""

    require_private_file(path, label)
    try:
        if path.stat().st_size > 4096:
            raise StateError(f"{label} is unexpectedly large")
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise StateError(f"cannot read {label}: {exc}") from exc
    if not value or "\n" in value or "\r" in value:
        raise StateError(f"{label} must contain exactly one non-empty line")
    return value
