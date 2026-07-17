from __future__ import annotations

import hashlib
import json
import runpy
import subprocess
from collections.abc import Callable
from contextlib import nullcontext
from pathlib import Path
from typing import Any, cast

import pytest

LAUNCHER = runpy.run_path(str(Path(__file__).resolve().parents[2] / "shuttle-gate"))
LauncherError = cast("type[Exception]", LAUNCHER["LauncherError"])
logs_command = cast("Callable[[list[str], list[str]], list[str]]", LAUNCHER["_logs_command"])
validated_launch = cast("Callable[[], tuple[str, Path]]", LAUNCHER["_validated_launch"])
lifecycle_lock = cast("Callable[[], object]", LAUNCHER["_lifecycle_lock"])
launcher_up = cast("Callable[[list[str]], int]", LAUNCHER["_up"])
LAUNCHER_GLOBALS = validated_launch.__globals__


def _select_launcher_root(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    monkeypatch.setitem(LAUNCHER_GLOBALS, "ROOT", root)
    monkeypatch.setitem(LAUNCHER_GLOBALS, "COMPOSE_FILE", root / "docker-compose.yml")
    monkeypatch.setitem(LAUNCHER_GLOBALS, "STATE_DIR", root / "state")
    monkeypatch.setitem(LAUNCHER_GLOBALS, "LAUNCH_MANIFEST", root / "state/runtime/launch.json")
    monkeypatch.setitem(LAUNCHER_GLOBALS, "LIFECYCLE_LOCK", root / "state/.lifecycle.lock")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def test_launcher_validates_every_file_bound_to_a_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _select_launcher_root(monkeypatch, tmp_path)
    config = tmp_path / "config.yaml"
    config.write_text("project: test\n", encoding="utf-8")
    config.chmod(0o600)
    identity = tmp_path / "secrets/keys/id_ed25519"
    identity.parent.mkdir(parents=True)
    identity.write_text("private\n", encoding="ascii")
    identity.chmod(0o600)
    known_hosts = tmp_path / "secrets/hosts/known_hosts"
    known_hosts.parent.mkdir(parents=True)
    known_hosts.write_text("host key\n", encoding="ascii")
    runtime = tmp_path / "state/runtime"
    runtime.mkdir(parents=True)
    generation = "gen-" + "1" * 32
    generations = tmp_path / "state/generations"
    generation_root = generations / generation
    generation_root.mkdir(parents=True)
    (generation_root / "manifest.json").write_text(
        json.dumps({"generation": generation, "schema_version": 1}),
        encoding="utf-8",
    )
    (tmp_path / "state/current").symlink_to(f"generations/{generation}")
    override = runtime / ("compose.override-" + "2" * 64 + ".yaml")
    override.write_text("services: {}\n", encoding="utf-8")
    override.chmod(0o600)
    launch = runtime / "launch.json"
    launch.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "project": "test-gate",
                "config_digest": _digest(config),
                "state_generation": generation,
                "ssh_identity": "secrets/keys/id_ed25519",
                "ssh_identity_digest": _digest(identity),
                "ssh_known_hosts": "secrets/hosts/known_hosts",
                "ssh_known_hosts_digest": _digest(known_hosts),
                "compose_override": f"state/runtime/{override.name}",
                "compose_override_digest": _digest(override),
            }
        ),
        encoding="utf-8",
    )
    launch.chmod(0o600)

    assert validated_launch() == ("test-gate", override)

    identity.write_text("changed\n", encoding="ascii")
    with pytest.raises(LauncherError, match="changed"):
        validated_launch()


def test_lifecycle_lock_rejects_concurrent_up_or_down(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _select_launcher_root(monkeypatch, tmp_path)
    first = cast("Any", lifecycle_lock())
    first.__enter__()
    try:
        second = cast("Any", lifecycle_lock())
        with pytest.raises(LauncherError, match="already running"):
            second.__enter__()
    finally:
        first.__exit__(None, None, None)


@pytest.mark.parametrize("already_running", [False, True])
def test_up_resumes_an_existing_plan_or_prepares_once(
    monkeypatch: pytest.MonkeyPatch,
    already_running: bool,
) -> None:
    prepared: list[list[str]] = []
    commands: list[list[str]] = []

    def fake_run(command: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
        del capture
        commands.append(command)
        stdout = "container-id\n" if "ps" in command and already_running else ""
        return subprocess.CompletedProcess(command, 0, stdout, "")

    def fake_tool(arguments: list[str], *, service: str = "tool") -> int:
        del service
        prepared.append(arguments)
        return 0

    monkeypatch.setitem(LAUNCHER_GLOBALS, "_lifecycle_lock", nullcontext)
    monkeypatch.setitem(LAUNCHER_GLOBALS, "_project_compose_prefix", lambda: ["compose", "project"])
    monkeypatch.setitem(LAUNCHER_GLOBALS, "_runtime_compose_prefix", lambda: ["compose", "runtime"])
    monkeypatch.setitem(LAUNCHER_GLOBALS, "_run", fake_run)
    monkeypatch.setitem(LAUNCHER_GLOBALS, "_run_tool", fake_tool)

    assert launcher_up(["--no-build"]) == 0
    assert prepared == ([] if already_running else [["prepare"]])
    assert commands[-1][-4:] == ["--detach", "--wait", "--wait-timeout", "60"]
