"""Generated Docker Compose inputs and recovery manifests."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import Any

import yaml

from .config import ProjectConfig
from .files import InstancePaths, atomic_write, atomic_write_json, validate_ssh_files
from .keys import require_current_phone_configs


def prepare_launch(config: ProjectConfig, paths: InstancePaths) -> tuple[Path, Path]:
    """Validate persistent inputs and write non-secret Compose metadata."""

    validate_ssh_files(config, paths.config)
    require_current_phone_configs(config, paths)
    runtime = paths.runtime_dir()
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
    override = {
        "services": {
            "gateway": {
                "ports": ports,
            }
        }
    }
    override_path = runtime / "compose.override.yaml"
    atomic_write(override_path, yaml.safe_dump(override, sort_keys=True), 0o600)
    config_digest = sha256(paths.config.read_bytes()).hexdigest()
    launch_path = runtime / "launch.json"
    atomic_write_json(
        launch_path,
        {
            "schema_version": 1,
            "project": config.project,
            "config_digest": config_digest,
            "compose_override": str(override_path.relative_to(paths.root)),
        },
        0o600,
    )
    return override_path, launch_path
