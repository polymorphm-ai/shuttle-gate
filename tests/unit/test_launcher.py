from __future__ import annotations

import runpy
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

LAUNCHER = runpy.run_path(str(Path(__file__).resolve().parents[2] / "shuttle-gate"))
LauncherError = cast("type[Exception]", LAUNCHER["LauncherError"])
logs_command = cast("Callable[[list[str], list[str]], list[str]]", LAUNCHER["_logs_command"])


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ([], []),
        (["-f", "--timestamps", "--tail", "200"], ["--follow", "--timestamps", "--tail=200"]),
        (
            ["--no-color", "--no-log-prefix", "--tail=all"],
            ["--no-color", "--no-log-prefix", "--tail=all"],
        ),
    ],
)
def test_logs_maps_allowlisted_options_and_fixes_service_operand(
    arguments: list[str], expected: list[str]
) -> None:
    command = logs_command(["docker", "compose"], arguments)

    logs_index = command.index("logs")
    assert command[logs_index:] == ["logs", *expected, "--", "gateway"]


@pytest.mark.parametrize(
    "arguments",
    [
        ["--since", "1h"],
        ["--tail"],
        ["--tail", "-1"],
        ["--tail=1000001"],
        ["--tail=" + "9" * 100],
        ["--tail=\u0661\u0660"],
        ["gateway"],
    ],
)
def test_logs_rejects_raw_options_and_ambiguous_values(arguments: list[str]) -> None:
    with pytest.raises(LauncherError, match=r"logs|tail"):
        logs_command(["docker", "compose"], arguments)
