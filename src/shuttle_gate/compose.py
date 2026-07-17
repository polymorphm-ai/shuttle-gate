"""Generated Docker Compose inputs and recovery manifests."""

from __future__ import annotations

import json
import os
import re
import stat
from contextlib import suppress
from hashlib import sha256
from pathlib import Path
from typing import Any

import yaml

from .config import ProjectConfig
from .errors import StateError
from .files import (
    InstancePaths,
    atomic_write,
    atomic_write_json,
    mounted_secret_path,
    require_private_file,
    require_regular_file,
    validate_ssh_files,
)
from .keys import recover_ssh_key_transaction, require_current_phone_configs
from .state import StateView, locked_state_view

LAUNCH_SCHEMA_VERSION = 2
MAX_LAUNCH_BYTES = 64 * 1024
MAX_INPUT_BYTES = 1024 * 1024
OVERRIDE_PREFIX = "compose.override-"
OVERRIDE_PATTERN = re.compile(r"^compose\.override-[0-9a-f]{64}\.yaml$")


def _digest(path: Path) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise StateError(f"cannot open launch input {path}: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_INPUT_BYTES:
            raise StateError(f"launch input must be a bounded regular file: {path}")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            return sha256(source.read(MAX_INPUT_BYTES + 1)).hexdigest()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _launch_values(
    config: ProjectConfig,
    paths: InstancePaths,
    view: StateView,
    identity: Path,
    known_hosts: Path,
) -> tuple[str, str, str, str, str, Path]:
    if view.generation is None:
        raise StateError("persistent keys are not initialized; run keys generate")
    config_digest = _digest(paths.config)
    ports: list[dict[str, Any]] = []
    for address in config.wireguard.bind_addresses:
        ports.append(
            {
                "target": config.wireguard.listen_port,
                "published": str(config.wireguard.listen_port),
                "host_ip": str(address),
                "protocol": "udp",
            }
        )
    override = {"services": {"gateway": {"ports": ports}}}
    rendered = yaml.safe_dump(override, sort_keys=True)
    override_digest = sha256(rendered.encode("utf-8")).hexdigest()
    identity_digest = _digest(identity)
    known_hosts_digest = _digest(known_hosts)
    launch_digest = sha256(
        (
            f"{config_digest}:{view.generation}:{identity_digest}:"
            f"{known_hosts_digest}:{override_digest}"
        ).encode("ascii")
    ).hexdigest()
    override_path = paths.runtime_dir() / f"{OVERRIDE_PREFIX}{launch_digest}.yaml"
    return (
        rendered,
        config_digest,
        identity_digest,
        known_hosts_digest,
        override_digest,
        override_path,
    )


def prepare_launch(config: ProjectConfig, paths: InstancePaths) -> tuple[Path, Path]:
    """Validate and atomically publish immutable Compose launch metadata."""

    with locked_state_view(paths, exclusive=True, blocking=False) as view:
        recover_ssh_key_transaction(config, paths)
        identity, known_hosts = validate_ssh_files(config, paths.config)
        if identity != mounted_secret_path(paths, config.ssh.identity_file) or (
            known_hosts != mounted_secret_path(paths, config.ssh.known_hosts_file)
        ):
            raise StateError("SSH files must resolve below the project secrets directory")
        require_current_phone_configs(config, view.paths)
        (
            rendered,
            config_digest,
            identity_digest,
            known_hosts_digest,
            override_digest,
            override_path,
        ) = _launch_values(config, paths, view, identity, known_hosts)
        runtime = paths.runtime_dir()
        atomic_write(override_path, rendered, 0o600)
        launch_path = runtime / "launch.json"
        atomic_write_json(
            launch_path,
            {
                "schema_version": LAUNCH_SCHEMA_VERSION,
                "project": config.project,
                "config_digest": config_digest,
                "state_generation": view.generation,
                "ssh_identity": config.ssh.identity_file.as_posix(),
                "ssh_identity_digest": identity_digest,
                "ssh_known_hosts": config.ssh.known_hosts_file.as_posix(),
                "ssh_known_hosts_digest": known_hosts_digest,
                "compose_override": str(override_path.relative_to(paths.root)),
                "compose_override_digest": override_digest,
            },
            0o600,
        )
        for candidate in runtime.glob(f"{OVERRIDE_PREFIX}*.yaml"):
            if candidate != override_path:
                with suppress(OSError):
                    candidate.unlink()
        return override_path, launch_path


def validate_launch_manifest(
    config: ProjectConfig,
    paths: InstancePaths,
    generation: str | None,
) -> None:
    """Require runtime inputs to match the atomically published launch plan."""

    launch_path = paths.runtime_dir() / "launch.json"
    try:
        launch_info = launch_path.stat(follow_symlinks=False)
        if not stat.S_ISREG(launch_info.st_mode) or launch_info.st_size > MAX_LAUNCH_BYTES:
            raise StateError("launch manifest is unexpectedly large")
        value = json.loads(launch_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StateError(f"launch manifest is unavailable: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != LAUNCH_SCHEMA_VERSION:
        raise StateError("launch manifest has an unsupported format; run up again")
    override_value = value.get("compose_override")
    if not isinstance(override_value, str):
        raise StateError("launch manifest has an invalid Compose override")
    relative_override = Path(override_value)
    try:
        expected_parent = paths.runtime_dir().relative_to(paths.root)
    except ValueError as exc:
        raise StateError("runtime directory is outside the project") from exc
    if (
        relative_override.is_absolute()
        or relative_override.parent != expected_parent
        or OVERRIDE_PATTERN.fullmatch(relative_override.name) is None
    ):
        raise StateError("launch manifest Compose override escapes the runtime directory")
    override = paths.root / relative_override
    try:
        override_info = override.stat(follow_symlinks=False)
        if not stat.S_ISREG(override_info.st_mode) or override_info.st_size > MAX_LAUNCH_BYTES:
            raise StateError("launch manifest Compose override is not a bounded regular file")
        identity = mounted_secret_path(paths, config.ssh.identity_file)
        known_hosts = mounted_secret_path(paths, config.ssh.known_hosts_file)
        require_private_file(identity, "SSH identity")
        require_regular_file(known_hosts, "SSH known-hosts file")
        expected: dict[str, object] = {
            "project": config.project,
            "config_digest": _digest(paths.config),
            "state_generation": generation,
            "ssh_identity": config.ssh.identity_file.as_posix(),
            "ssh_identity_digest": _digest(identity),
            "ssh_known_hosts": config.ssh.known_hosts_file.as_posix(),
            "ssh_known_hosts_digest": _digest(known_hosts),
            "compose_override_digest": _digest(override),
        }
    except OSError as exc:
        raise StateError(f"cannot verify launch inputs: {exc}") from exc
    if any(value.get(key) != item for key, item in expected.items()):
        raise StateError("configuration or persistent state changed after prepare; run up again")
