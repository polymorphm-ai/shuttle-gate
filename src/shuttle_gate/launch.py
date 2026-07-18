"""Immutable launch metadata for one rootless gateway instance."""

from __future__ import annotations

import json
import os
import re
import secrets
import stat
from hashlib import sha256
from pathlib import Path
from typing import Any

from .config import ProjectConfig
from .errors import StateError, with_command_hint
from .files import (
    InstancePaths,
    atomic_write_json,
    mounted_secret_path,
    require_private_file,
    require_regular_file,
    validate_ssh_files,
)
from .keys import recover_ssh_key_transaction, require_current_phone_configs
from .state import locked_state_view

LAUNCH_SCHEMA_VERSION = 3
MAX_LAUNCH_BYTES = 64 * 1024
MAX_INPUT_BYTES = 8 * 1024 * 1024
INSTANCE_PATTERN = re.compile(r"^[0-9a-f]{20}$")
LAUNCH_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
UNIT_PATTERN = re.compile(r"^shuttle-gate-[0-9a-f]{20}\.service$")


def file_digest(path: Path, label: str, *, private: bool = False) -> str:
    """Hash one bounded regular file without following a final symlink."""

    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise StateError(f"cannot open {label} {path}: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_INPUT_BYTES:
            raise StateError(f"{label} must be a bounded regular file: {path}")
        if private and stat.S_IMODE(info.st_mode) & 0o077:
            raise StateError(f"{label} permissions are too open: {path}")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            return sha256(source.read(MAX_INPUT_BYTES + 1)).hexdigest()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def prepare_launch(
    config: ProjectConfig,
    paths: InstancePaths,
    launch_path: Path,
    app_bundle: Path,
    *,
    instance_id: str,
    unit_name: str,
) -> dict[str, object]:
    """Validate and atomically publish one immutable namespace launch plan."""

    if INSTANCE_PATTERN.fullmatch(instance_id) is None:
        raise StateError("launch instance identifier is invalid")
    if UNIT_PATTERN.fullmatch(unit_name) is None:
        raise StateError("launch systemd unit name is invalid")
    require_private_file(app_bundle, "application bundle")

    with locked_state_view(paths, exclusive=True, blocking=False) as view:
        recover_ssh_key_transaction(config, paths)
        identity, known_hosts = validate_ssh_files(config, paths)
        require_current_phone_configs(config, view.paths)
        if view.generation is None:
            raise StateError(
                with_command_hint("persistent keys are not initialized", "keys", "generate")
            )

        value: dict[str, object] = {
            "schema_version": LAUNCH_SCHEMA_VERSION,
            "launch_id": secrets.token_hex(16),
            "instance_id": instance_id,
            "unit": unit_name,
            "project": config.project,
            "config_digest": file_digest(paths.config, "configuration", private=True),
            "state_generation": view.generation,
            "ssh_identity": config.ssh.identity_file.as_posix(),
            "ssh_identity_digest": file_digest(identity, "SSH identity", private=True),
            "ssh_known_hosts": config.ssh.known_hosts_file.as_posix(),
            "ssh_known_hosts_digest": file_digest(known_hosts, "SSH known-hosts"),
            "application_digest": file_digest(app_bundle, "application bundle", private=True),
            "bind_addresses": [str(address) for address in config.wireguard.bind_addresses],
            "listen_port": config.wireguard.listen_port,
        }
        atomic_write_json(launch_path, value, 0o600)
        return value


def read_launch_manifest(launch_path: Path) -> dict[str, Any]:
    """Read one bounded versioned launch manifest."""

    try:
        info = launch_path.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_LAUNCH_BYTES:
            raise StateError("launch manifest is not a bounded regular file")
        value = json.loads(launch_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StateError(f"launch manifest is unavailable: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != LAUNCH_SCHEMA_VERSION:
        raise StateError(with_command_hint("launch manifest has an unsupported format", "up"))
    return value


def validate_launch_manifest(
    config: ProjectConfig,
    paths: InstancePaths,
    generation: str | None,
    launch_path: Path,
    app_bundle: Path,
) -> dict[str, Any]:
    """Require every runtime input to match the published launch plan."""

    value = read_launch_manifest(launch_path)
    launch_id = value.get("launch_id")
    instance_id = value.get("instance_id")
    unit_name = value.get("unit")
    if not isinstance(launch_id, str) or LAUNCH_ID_PATTERN.fullmatch(launch_id) is None:
        raise StateError("launch manifest has an invalid launch identifier")
    if not isinstance(instance_id, str) or INSTANCE_PATTERN.fullmatch(instance_id) is None:
        raise StateError("launch manifest has an invalid instance identifier")
    if not isinstance(unit_name, str) or UNIT_PATTERN.fullmatch(unit_name) is None:
        raise StateError("launch manifest has an invalid systemd unit")

    identity = mounted_secret_path(paths, config.ssh.identity_file)
    known_hosts = mounted_secret_path(paths, config.ssh.known_hosts_file)
    require_private_file(identity, "SSH identity")
    require_regular_file(known_hosts, "SSH known-hosts file")
    require_private_file(app_bundle, "application bundle")
    expected: dict[str, object] = {
        "project": config.project,
        "config_digest": file_digest(paths.config, "configuration", private=True),
        "state_generation": generation,
        "ssh_identity": config.ssh.identity_file.as_posix(),
        "ssh_identity_digest": file_digest(identity, "SSH identity", private=True),
        "ssh_known_hosts": config.ssh.known_hosts_file.as_posix(),
        "ssh_known_hosts_digest": file_digest(known_hosts, "SSH known-hosts"),
        "application_digest": file_digest(app_bundle, "application bundle", private=True),
        "bind_addresses": [str(address) for address in config.wireguard.bind_addresses],
        "listen_port": config.wireguard.listen_port,
    }
    if any(value.get(key) != item for key, item in expected.items()):
        raise StateError(
            with_command_hint("configuration or launch inputs changed after prepare", "up")
        )
    return value
