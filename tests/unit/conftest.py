from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from shuttle_gate.config import ProjectConfig
from shuttle_gate.files import InstancePaths, atomic_write, ensure_private_directory
from shuttle_gate.state import state_lock


def config_data() -> dict[str, Any]:
    return {
        "version": 1,
        "project": "test-gate",
        "wireguard": {
            "bind_addresses": ["127.0.0.1", "::1"],
            "endpoint_host": "gate.example.test",
            "listen_port": 51820,
            "gateway_addresses": ["10.77.0.1/24", "fd77::1/64"],
            "mtu": 1420,
            "peers": [
                {
                    "name": "phone",
                    "addresses": ["10.77.0.2/32", "fd77::2/128"],
                    "persistent_keepalive_seconds": 25,
                },
                {
                    "name": "tablet",
                    "addresses": ["10.77.0.3/32", "fd77::3/128"],
                    "persistent_keepalive_seconds": 0,
                },
            ],
        },
        "ssh": {
            "host": "ssh.example.test",
            "user": "tester",
            "port": 2222,
            "identity_file": "secrets/id_ed25519",
            "known_hosts_file": "secrets/known_hosts",
            "remote_python": "python3",
            "connect_timeout_seconds": 10,
            "server_alive_interval_seconds": 15,
            "server_alive_count_max": 3,
        },
        "routing": {
            "mode": "selected",
            "networks": ["10.0.0.0/8", "fd20:1234::/48"],
        },
        "dns": {"enabled": True, "upstream": "fd20:1234::53"},
        "backend": {
            "mode": "sshuttle",
            "method": "nft-tproxy",
            "startup_timeout_seconds": 45,
        },
    }


@pytest.fixture
def config() -> ProjectConfig:
    return ProjectConfig.model_validate(config_data())


@pytest.fixture
def instance(tmp_path: Path) -> InstancePaths:
    paths = InstancePaths.from_root(tmp_path)
    ensure_private_directory(paths.secrets)
    ensure_private_directory(paths.state)
    with state_lock(paths, exclusive=True):
        pass
    atomic_write(paths.config, yaml.safe_dump(config_data()), 0o600)
    atomic_write(paths.secrets / "id_ed25519", "private\n", 0o600)
    atomic_write(paths.secrets / "known_hosts", "host key\n", 0o644)
    return paths
