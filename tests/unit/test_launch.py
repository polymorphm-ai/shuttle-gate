from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from shuttle_gate.config import ProjectConfig
from shuttle_gate.errors import StateError
from shuttle_gate.files import InstancePaths, atomic_write, atomic_write_json
from shuttle_gate.keys import generate_missing_keys
from shuttle_gate.launch import (
    file_digest,
    prepare_launch,
    read_launch_manifest,
    validate_launch_manifest,
)

from .fakes import FakeRunner

INSTANCE_ID = "1" * 20
UNIT_NAME = f"shuttle-gate-{INSTANCE_ID}.service"


def _launch_inputs(instance: InstancePaths) -> tuple[Path, Path]:
    runtime = instance.root / "volatile"
    bundle = runtime / "application.pyz"
    launch = runtime / "launch.json"
    atomic_write(bundle, "immutable application\n", 0o600)
    return bundle, launch


def _prepare(config: ProjectConfig, instance: InstancePaths) -> tuple[Path, Path]:
    generate_missing_keys(config, instance, FakeRunner())
    bundle, launch = _launch_inputs(instance)
    prepare_launch(
        config,
        instance,
        launch,
        bundle,
        instance_id=INSTANCE_ID,
        unit_name=UNIT_NAME,
    )
    return bundle, launch


def test_prepare_writes_secret_free_exact_bindings(
    config: ProjectConfig, instance: InstancePaths
) -> None:
    bundle, launch_path = _prepare(config, instance)

    launch = json.loads(launch_path.read_text())
    assert launch["project"] == "test-gate"
    assert launch["unit"] == UNIT_NAME
    assert launch["bind_addresses"] == ["127.0.0.1", "::1"]
    assert launch["listen_port"] == 51820
    assert launch["application_digest"]
    combined = bundle.read_text() + launch_path.read_text()
    assert "private-" not in combined
    assert "psk-" not in combined


def test_launch_validation_fails_closed_when_an_input_changes(
    config: ProjectConfig, instance: InstancePaths
) -> None:
    bundle, launch = _prepare(config, instance)
    generation = Path(os.readlink(instance.state / "current")).name
    validate_launch_manifest(config, instance, generation, launch, bundle)

    atomic_write(instance.secrets / "known_hosts", "changed host key\n", 0o644)

    with pytest.raises(StateError, match="changed"):
        validate_launch_manifest(config, instance, generation, launch, bundle)


def test_interrupted_prepare_keeps_previous_manifest_until_retry(
    config: ProjectConfig,
    instance: InstancePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, launch = _prepare(config, instance)
    previous = launch.read_text(encoding="utf-8")
    atomic_write(instance.secrets / "known_hosts", "new host key\n", 0o644)
    real_write_json = atomic_write_json

    def interrupt(path: Path, value: dict[str, object], mode: int = 0o600) -> None:
        if path == launch:
            raise OSError("interrupted manifest publish")
        real_write_json(path, value, mode)

    monkeypatch.setattr("shuttle_gate.launch.atomic_write_json", interrupt)
    with pytest.raises(OSError, match="manifest publish"):
        prepare_launch(
            config,
            instance,
            launch,
            bundle,
            instance_id=INSTANCE_ID,
            unit_name=UNIT_NAME,
        )
    assert launch.read_text(encoding="utf-8") == previous

    monkeypatch.setattr("shuttle_gate.launch.atomic_write_json", real_write_json)
    prepare_launch(
        config,
        instance,
        launch,
        bundle,
        instance_id=INSTANCE_ID,
        unit_name=UNIT_NAME,
    )
    generation = Path(os.readlink(instance.state / "current")).name
    validate_launch_manifest(config, instance, generation, launch, bundle)


def test_launch_manifest_rejects_invalid_identity(
    config: ProjectConfig, instance: InstancePaths
) -> None:
    bundle, launch = _prepare(config, instance)
    value = json.loads(launch.read_text(encoding="utf-8"))
    value["launch_id"] = "not-safe"
    atomic_write_json(launch, value)
    generation = Path(os.readlink(instance.state / "current")).name

    with pytest.raises(StateError, match="launch identifier"):
        validate_launch_manifest(config, instance, generation, launch, bundle)


def test_launch_rejects_unsafe_metadata_and_input_files(
    config: ProjectConfig,
    instance: InstancePaths,
    tmp_path: Path,
) -> None:
    generate_missing_keys(config, instance, FakeRunner())
    bundle, launch = _launch_inputs(instance)
    with pytest.raises(StateError, match="instance identifier"):
        prepare_launch(
            config,
            instance,
            launch,
            bundle,
            instance_id="bad",
            unit_name=UNIT_NAME,
        )
    with pytest.raises(StateError, match="unit name"):
        prepare_launch(
            config,
            instance,
            launch,
            bundle,
            instance_id=INSTANCE_ID,
            unit_name="bad.service",
        )

    public = tmp_path / "public"
    public.write_text("value", encoding="utf-8")
    public.chmod(0o644)
    with pytest.raises(StateError, match="permissions"):
        file_digest(public, "private input", private=True)
    with pytest.raises(StateError, match="cannot open"):
        file_digest(tmp_path / "missing", "missing input")

    launch.write_text("[]", encoding="utf-8")
    with pytest.raises(StateError, match="unsupported"):
        read_launch_manifest(launch)
