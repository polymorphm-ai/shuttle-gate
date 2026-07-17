from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest
import yaml

from shuttle_gate.compose import prepare_launch, validate_launch_manifest
from shuttle_gate.config import ProjectConfig
from shuttle_gate.errors import StateError
from shuttle_gate.files import InstancePaths, atomic_write, atomic_write_json
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
    assert re.fullmatch(
        r"state/runtime/compose\.override-[0-9a-f]{64}\.yaml",
        launch["compose_override"],
    )
    assert launch["state_generation"].startswith("gen-")
    assert launch["ssh_identity"] == "secrets/id_ed25519"
    assert launch["ssh_known_hosts"] == "secrets/known_hosts"
    combined = override_path.read_text() + launch_path.read_text()
    assert "private-" not in combined
    assert "psk-" not in combined


def test_launch_validation_fails_closed_when_a_credential_changes(
    config: ProjectConfig, instance: InstancePaths
) -> None:
    generate_missing_keys(config, instance, FakeRunner())
    _override, launch = prepare_launch(config, instance)
    generation = Path(os.readlink(instance.state / "current")).name
    validate_launch_manifest(config, instance, generation)

    atomic_write(instance.secrets / "known_hosts", "changed host key\n", 0o644)

    with pytest.raises(StateError, match="changed"):
        validate_launch_manifest(config, instance, generation)
    assert launch.is_file()


def test_interrupted_prepare_keeps_the_previous_manifest_until_retry(
    config: ProjectConfig,
    instance: InstancePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generate_missing_keys(config, instance, FakeRunner())
    _override, launch = prepare_launch(config, instance)
    previous = launch.read_text(encoding="utf-8")
    atomic_write(instance.secrets / "known_hosts", "new host key\n", 0o644)
    real_write_json = atomic_write_json

    def interrupt(path: Path, value: dict[str, object], mode: int = 0o600) -> None:
        if path == launch:
            raise OSError("interrupted manifest publish")
        real_write_json(path, value, mode)

    monkeypatch.setattr("shuttle_gate.compose.atomic_write_json", interrupt)
    with pytest.raises(OSError, match="manifest publish"):
        prepare_launch(config, instance)
    assert launch.read_text(encoding="utf-8") == previous

    monkeypatch.setattr("shuttle_gate.compose.atomic_write_json", real_write_json)
    _new_override, new_launch = prepare_launch(config, instance)
    generation = Path(os.readlink(instance.state / "current")).name
    validate_launch_manifest(config, instance, generation)
    assert new_launch.read_text(encoding="utf-8") != previous


def test_launch_manifest_rejects_an_override_outside_runtime(
    config: ProjectConfig, instance: InstancePaths
) -> None:
    generate_missing_keys(config, instance, FakeRunner())
    _override, launch = prepare_launch(config, instance)
    value = json.loads(launch.read_text(encoding="utf-8"))
    value["compose_override"] = "/etc/passwd"
    launch.write_text(json.dumps(value), encoding="utf-8")
    generation = Path(os.readlink(instance.state / "current")).name

    with pytest.raises(StateError, match="escapes"):
        validate_launch_manifest(config, instance, generation)
