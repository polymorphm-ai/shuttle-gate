"""Protected instance-local paths and atomic file operations."""

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
    """Resolved paths for one local instance."""

    root: Path
    config: Path
    state: Path
    secrets: Path
    data: Path | None = None

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
        return self.data_dir() / "server"

    def peer_dir(self, name: str) -> Path:
        return self.data_dir() / "peers" / name

    def data_dir(self) -> Path:
        """Return the active or explicitly selected persistent generation."""

        return self.data if self.data is not None else self.state / "current"

    def with_data(self, data: Path) -> InstancePaths:
        """Return paths bound to one immutable persistent-state generation."""

        return InstancePaths(
            root=self.root,
            config=self.config,
            state=self.state,
            secrets=self.secrets,
            data=data,
        )


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


def fsync_directory(path: Path) -> None:
    """Persist directory-entry changes on the Linux filesystems we support."""

    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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


def sandbox_secret_path(configured: Path) -> Path:
    """Map an instance-local ``secrets/`` path into the sandbox mount."""

    if configured.is_absolute():
        raise ConfigurationError("SSH files must use instance-relative secrets/ paths")
    parts = configured.parts
    if len(parts) < 2 or parts[0] != "secrets" or ".." in parts:
        raise ConfigurationError("SSH files must be located below the instance secrets/ directory")
    return Path("/secrets").joinpath(*parts[1:])


def mounted_secret_path(paths: InstancePaths, configured: Path) -> Path:
    """Resolve a validated configured secret against this execution environment."""

    relative = sandbox_secret_path(configured).relative_to("/secrets")
    return paths.secrets / relative


def resolve_export_path(paths: InstancePaths, requested: Path) -> Path:
    """Resolve one explicit, instance-local sensitive export destination."""

    if (
        not str(requested).isprintable()
        or requested.is_absolute()
        or len(requested.parts) != 2
        or requested.parts[0] != "exports"
        or requested.name in {".", ".."}
    ):
        raise ConfigurationError("--output must use the instance-relative form exports/FILE")
    export_directory = paths.root / "exports"
    destination = export_directory / requested.name
    if export_directory.is_symlink() or destination.is_symlink():
        raise ConfigurationError("export paths must not be symbolic links")
    if export_directory.exists() and not export_directory.is_dir():
        raise ConfigurationError("exports must be a directory")
    if destination.exists() and not destination.is_file():
        raise ConfigurationError("the export destination must be a regular file")
    return destination


def atomic_write_bytes(path: Path, data: bytes, mode: int) -> None:
    """Atomically replace one binary file with explicit permissions."""

    ensure_private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    except BaseException:
        with suppress(OSError):
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise


def atomic_write(path: Path, data: str, mode: int) -> None:
    """Atomically replace one UTF-8 file with explicit permissions."""

    atomic_write_bytes(path, data.encode("utf-8"), mode)


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
