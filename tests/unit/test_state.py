from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from shuttle_gate.errors import StateError
from shuttle_gate.files import InstancePaths, atomic_write, fsync_directory
from shuttle_gate.state import locked_state_view, mutate_state, read_state, void_operation


def _write_value(paths: InstancePaths, value: str) -> None:
    atomic_write(paths.data_dir() / "value", value, 0o600)


def _validate_value(paths: InstancePaths) -> None:
    if not (paths.data_dir() / "value").is_file():
        raise StateError("value is missing")


def _read_value(paths: InstancePaths) -> str:
    return (paths.data_dir() / "value").read_text(encoding="utf-8")


def test_state_generation_has_one_atomic_publish_pointer(instance: InstancePaths) -> None:
    def create(paths: InstancePaths) -> str:
        _write_value(paths, "ready")
        return "created"

    result = mutate_state(
        instance,
        create,
        _validate_value,
    )

    assert result == "created"
    target = os.readlink(instance.state / "current")
    assert target.startswith("generations/gen-")
    generation = instance.state / target
    assert json.loads((generation / "manifest.json").read_text()) == {
        "generation": generation.name,
        "schema_version": 1,
    }
    assert read_state(instance, _read_value) == "ready"
    assert [path for path in (instance.state / "generations").iterdir()] == [generation]


def test_validation_failure_keeps_the_previous_generation(instance: InstancePaths) -> None:
    mutate_state(instance, lambda paths: _write_value(paths, "old"), _validate_value)
    previous_target = os.readlink(instance.state / "current")

    def reject(_paths: InstancePaths) -> None:
        raise StateError("rejected")

    with pytest.raises(StateError, match="rejected"):
        mutate_state(instance, lambda paths: _write_value(paths, "new"), reject)

    assert os.readlink(instance.state / "current") == previous_target
    assert read_state(instance, _read_value) == "old"


def test_failure_before_pointer_swap_is_safe_to_retry(
    instance: InstancePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mutate_state(instance, lambda paths: _write_value(paths, "old"), _validate_value)
    real_replace = os.replace
    failed = False

    def fail_pointer_once(source: Path, destination: Path) -> None:
        nonlocal failed
        if destination == instance.state / "current" and not failed:
            failed = True
            raise OSError("interrupted before pointer swap")
        real_replace(source, destination)

    monkeypatch.setattr("shuttle_gate.state.os.replace", fail_pointer_once)
    operation = void_operation("change-value-1", "test.change-value")
    with pytest.raises(OSError, match="pointer swap"):
        mutate_state(
            instance,
            lambda paths: _write_value(paths, "new"),
            _validate_value,
            operation=operation,
        )
    assert read_state(instance, _read_value) == "old"

    mutate_state(
        instance,
        lambda paths: _write_value(paths, "new"),
        _validate_value,
        operation=operation,
    )
    assert read_state(instance, _read_value) == "new"
    assert len(list((instance.state / "generations").iterdir())) == 1


def test_completed_operation_is_not_repeated_after_late_failure(
    instance: InstancePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mutate_state(instance, lambda paths: _write_value(paths, "old"), _validate_value)
    real_sync = fsync_directory
    state_syncs = 0
    mutations = 0

    def fail_after_pointer_swap(path: Path) -> None:
        nonlocal state_syncs
        real_sync(path)
        if path == instance.state:
            state_syncs += 1
            if state_syncs == 2:
                raise OSError("interrupted after pointer swap")

    def mutate(paths: InstancePaths) -> None:
        nonlocal mutations
        mutations += 1
        _write_value(paths, "new")

    monkeypatch.setattr("shuttle_gate.state.fsync_directory", fail_after_pointer_swap)
    operation = void_operation("change-value-2", "test.change-value")
    with pytest.raises(OSError, match="after pointer swap"):
        mutate_state(instance, mutate, _validate_value, operation=operation)
    assert read_state(instance, _read_value) == "new"

    mutate_state(instance, mutate, _validate_value, operation=operation)
    assert mutations == 1


def test_shared_reader_blocks_a_conflicting_mutation(instance: InstancePaths) -> None:
    with locked_state_view(instance, required=False), pytest.raises(StateError, match="busy"):
        mutate_state(instance, lambda paths: _write_value(paths, "new"), _validate_value)


def test_state_rejects_an_escaping_pointer(instance: InstancePaths) -> None:
    (instance.state / "current").symlink_to("../secrets")

    with pytest.raises(StateError, match="invalid persistent-state pointer"):
        read_state(instance, _read_value)


def test_operation_id_cannot_be_reused_for_another_request(instance: InstancePaths) -> None:
    mutate_state(
        instance,
        lambda paths: _write_value(paths, "one"),
        _validate_value,
        operation=void_operation("request-1", "test.one"),
    )

    with pytest.raises(StateError, match="already used"):
        mutate_state(
            instance,
            lambda paths: _write_value(paths, "two"),
            _validate_value,
            operation=void_operation("request-1", "test.two"),
        )


def test_writer_refuses_objects_outside_its_owned_generation_names(
    instance: InstancePaths,
) -> None:
    generations = instance.state / "generations"
    generations.mkdir()
    unexpected = generations / "keep-me"
    unexpected.write_text("operator data", encoding="utf-8")

    with pytest.raises(StateError, match="unexpected object"):
        mutate_state(instance, lambda paths: _write_value(paths, "new"), _validate_value)

    assert unexpected.read_text(encoding="utf-8") == "operator data"
