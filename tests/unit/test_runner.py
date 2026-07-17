from __future__ import annotations

import subprocess
from typing import Any

import pytest

from shuttle_gate.errors import CommandError
from shuttle_gate.runner import SubprocessRunner


def test_runner_captures_text_input_environment_and_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}

    def run(command: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed.update({"command": command, **kwargs})
        return subprocess.CompletedProcess(command, 0, "output\n", "")

    monkeypatch.setattr(subprocess, "run", run)

    result = SubprocessRunner().run(
        ["tool", "argument"],
        input_text="input\n",
        timeout=4.0,
        env={"ONLY": "value"},
    )

    assert result.stdout == "output\n"
    assert observed["command"] == ("tool", "argument")
    assert observed["input"] == "input\n"
    assert observed["env"] == {"ONLY": "value"}
    assert "shell" not in observed


def test_runner_reports_exit_missing_command_and_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["bad"],
            7,
            "",
            "diagnostic",
        ),
    )
    with pytest.raises(CommandError, match="status 7: diagnostic"):
        SubprocessRunner().run(["bad"])
    assert SubprocessRunner().run(["bad"], check=False).returncode == 7

    def missing(*_args: Any, **_kwargs: Any) -> Any:
        raise FileNotFoundError

    monkeypatch.setattr(subprocess, "run", missing)
    with pytest.raises(CommandError, match="not found"):
        SubprocessRunner().run(["missing"])

    def timeout(*_args: Any, **_kwargs: Any) -> Any:
        raise subprocess.TimeoutExpired("slow", 2)

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(CommandError, match="timed out after 2s"):
        SubprocessRunner().run(["slow"], timeout=2)


def test_runner_rejects_empty_command() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        SubprocessRunner().run([])
