from __future__ import annotations

import json

import yaml

from shuttle_gate.compose import prepare_launch
from shuttle_gate.config import ProjectConfig
from shuttle_gate.files import InstancePaths
from shuttle_gate.keys import generate_missing_keys

from .fakes import FakeRunner


def test_prepare_writes_non_secret_dual_stack_port_override(
    config: ProjectConfig, instance: InstancePaths
) -> None:
    generate_missing_keys(config, instance, FakeRunner())

    override_path, launch_path = prepare_launch(config, instance)

    override = yaml.safe_load(override_path.read_text())
    ports = override["services"]["gateway"]["ports"]
    assert [port["host_ip"] for port in ports] == ["127.0.0.1", "::1"]
    assert all(port["protocol"] == "udp" for port in ports)
    launch = json.loads(launch_path.read_text())
    assert launch["project"] == "test-gate"
    assert launch["compose_override"] == "state/runtime/compose.override.yaml"
    combined = override_path.read_text() + launch_path.read_text()
    assert "private-" not in combined
    assert "psk-" not in combined
