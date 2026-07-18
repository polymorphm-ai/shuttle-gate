from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from shuttle_gate.errors import (
    INSTANCE_ENV,
    LAUNCHER_ENV,
    command_context,
    command_hint,
    with_command_hint,
)


def test_command_hint_shell_quotes_the_complete_active_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launcher = "/opt/shuttle gate/ -launcher $ ' \" ; 🚀"
    instance = "/tmp/  -instance $ ' \" ; 🚀"
    monkeypatch.setenv(LAUNCHER_ENV, launcher)
    monkeypatch.setenv(INSTANCE_ENV, instance)

    hint = command_hint("phone-config", "tablet")

    assert hint.startswith("run: ")
    assert shlex.split(hint.removeprefix("run: ")) == [
        launcher,
        "--instance",
        instance,
        "phone-config",
        "tablet",
    ]
    assert with_command_hint("phone config is stale", "phone-config", "tablet") == (
        f"phone config is stale; {hint}"
    )


def test_host_command_context_overrides_environment_and_restores_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(LAUNCHER_ENV, "/environment/launcher")
    monkeypatch.setenv(INSTANCE_ENV, "/environment/instance")

    with command_context(Path("/context/launcher"), Path("/context/instance")):
        contextual = command_hint("keys", "generate")

    restored = command_hint("keys", "generate")
    assert shlex.split(contextual.removeprefix("run: ")) == [
        "/context/launcher",
        "--instance",
        "/context/instance",
        "keys",
        "generate",
    ]
    assert shlex.split(restored.removeprefix("run: ")) == [
        "/environment/launcher",
        "--instance",
        "/environment/instance",
        "keys",
        "generate",
    ]
