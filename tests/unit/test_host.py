from __future__ import annotations

import json
import shutil
import subprocess
from contextlib import nullcontext
from pathlib import Path
from typing import Any

import pytest

import shuttle_gate.host as host
from shuttle_gate.config import ProjectConfig
from shuttle_gate.files import InstancePaths, atomic_write_json, ensure_private_directory
from shuttle_gate.host import HostError, RuntimePaths
from shuttle_gate.state import StateView


def _commands(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host, "_command", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(host, "_system_mounts", lambda: [(Path("/usr"), Path("/usr"))])
    monkeypatch.setattr(host, "_python_mounts", lambda: [])


def _runtime(tmp_path: Path) -> RuntimePaths:
    root = tmp_path / "runtime"
    return RuntimePaths(
        instance_id="1" * 20,
        unit_name=f"shuttle-gate-{'1' * 20}.service",
        root=root,
        inputs=root / "inputs",
        output=root / "output",
        launch=root / "inputs/launch.json",
        bundle=root / "inputs/application.pyz",
    )


def test_runtime_paths_use_private_xdg_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))

    first = host.runtime_paths(Path("/project"))
    second = host.runtime_paths(Path("/other"))

    assert first.root.parent.parent == tmp_path
    assert first.instance_id != second.instance_id
    assert first.unit_name == f"shuttle-gate-{first.instance_id}.service"

    monkeypatch.delenv("XDG_RUNTIME_DIR")
    with pytest.raises(HostError, match="systemd user session"):
        host.runtime_paths(Path("/project"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", "relative")
    with pytest.raises(HostError, match="absolute"):
        host.runtime_paths(Path("/project"))


def test_command_resolution_and_structured_runner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert Path(host._command("sh")).is_absolute()
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(HostError, match="not found"):
        host._command("missing")

    completed = subprocess.CompletedProcess(["command"], 0, "output", "")
    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: completed)
    assert host._run(["command"], capture=True, check=True) is completed
    with pytest.raises(ValueError, match="empty"):
        host._run([])

    failed = subprocess.CompletedProcess(["command"], 9, "", "diagnostic")
    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: failed)
    with pytest.raises(HostError, match="diagnostic"):
        host._run(["command"], check=True)

    def unavailable(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise OSError("unavailable")

    monkeypatch.setattr(subprocess, "run", unavailable)
    with pytest.raises(HostError, match="cannot execute"):
        host._run(["command"])


def test_mount_discovery_is_limited_to_system_and_python_roots() -> None:
    assert (Path("/usr"), Path("/usr")) in host._system_mounts()
    assert any(destination == Path("/etc/resolv.conf") for _, destination in host._system_mounts())
    assert all(
        source == destination or destination == Path("/etc/resolv.conf")
        for source, destination in host._system_mounts()
    )
    assert all(source == destination for source, destination in host._python_mounts())


def test_namespace_commands_have_fixed_boundaries_and_exposure(
    config: ProjectConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _commands(monkeypatch)
    runtime = _runtime(tmp_path)
    root = tmp_path / "project"
    for path in (root / "secrets", root / "state", runtime.inputs, runtime.output):
        path.mkdir(parents=True, exist_ok=True)
    for path in (root / "config.yaml", root / "state/.state.lock", runtime.launch, runtime.bundle):
        path.touch()

    operator = host.bubblewrap_command(
        root,
        ["/python", "-m", "shuttle_gate", "keys", "generate"],
        network_namespace=False,
        project_read_only=False,
    )
    assert "--unshare-user" in operator
    assert "--unshare-net" in operator
    assert ["--bind", str(root.resolve()), "/workspace"] == operator[
        operator.index("--bind") : operator.index("--bind") + 3
    ]
    assert operator[-6:] == ["--", "/python", "-m", "shuttle_gate", "keys", "generate"]

    gateway = host.bubblewrap_command(
        root,
        ["/python", "-m", "shuttle_gate", "runtime"],
        network_namespace=True,
        project_read_only=True,
        runtime=runtime,
    )
    assert "--unshare-user" not in gateway
    assert "--unshare-net" not in gateway
    assert gateway[gateway.index("--cap-add") : gateway.index("--cap-add") + 2] == [
        "--cap-add",
        "CAP_NET_ADMIN",
    ]
    assert str(root.resolve()) not in gateway
    assert ["--bind", str(runtime.output), "/run/shuttle-gate/output"] == gateway[
        gateway.index(str(runtime.output)) - 1 : gateway.index(str(runtime.output)) + 2
    ]
    assert gateway[gateway.index("--chdir") + 1] == "/"
    assert operator[operator.index("--chdir") + 1] == "/workspace"

    pasta = host.pasta_command(gateway, config)
    assert pasta.count("--udp-ports") == 2
    assert "127.0.0.1/51820" in pasta
    assert "::1/51820" in pasta
    assert pasta[pasta.index("--tcp-ports") + 1] == "none"
    assert pasta[pasta.index("--tcp-ns") + 1] == "none"
    assert pasta[pasta.index("--udp-ns") + 1] == "none"
    assert pasta[pasta.index("--dns") + 1] == "none"
    assert pasta[pasta.index("--search") + 1] == "none"
    assert pasta[pasta.index("--") + 1 :] == gateway
    no_ports = host.pasta_command(["inner"])
    assert no_ports[no_ports.index("--udp-ports") + 1] == "none"
    with pytest.raises(ValueError, match="empty"):
        host.bubblewrap_command(
            root,
            [],
            network_namespace=False,
            project_read_only=False,
        )


def test_systemd_service_retries_only_classified_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _commands(monkeypatch)
    command = host.systemd_run_command(
        f"shuttle-gate-{'1' * 20}.service",
        ["/usr/bin/pasta", "--", "/usr/bin/bwrap"],
    )

    assert "--property=Restart=no" in command
    assert "--property=RestartForceExitStatus=75" in command
    assert "--property=KillMode=control-group" in command
    assert "--property=NoNewPrivileges=yes" in command
    assert "--property=TasksMax=256" in command
    assert command[-4:] == ["--", "/usr/bin/pasta", "--", "/usr/bin/bwrap"]


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ([], ["--output", "cat"]),
        (["--timestamps", "--tail", "20"], ["--output", "short-iso-precise", "--lines", "20"]),
        (["--follow", "--tail=all"], ["--output", "cat", "--no-tail", "--follow"]),
    ],
)
def test_logs_map_only_allowlisted_options(
    arguments: list[str], expected: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _commands(monkeypatch)
    command = host.logs_command(f"shuttle-gate-{'1' * 20}.service", arguments)
    for index, token in enumerate(expected):
        assert token in command
        if index and expected[index - 1].startswith("--") and not token.startswith("--"):
            assert command[command.index(expected[index - 1]) + 1] == token


@pytest.mark.parametrize(
    "arguments",
    [["--since", "today"], ["--tail"], ["--tail", "-1"], ["--tail=1000001"]],
)
def test_logs_reject_raw_or_ambiguous_values(
    arguments: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    _commands(monkeypatch)
    with pytest.raises(HostError, match=r"logs|tail"):
        host.logs_command("shuttle-gate-11111111111111111111.service", arguments)


def test_lifecycle_lock_rejects_a_concurrent_transition(tmp_path: Path) -> None:
    first = host.lifecycle_lock(tmp_path)
    first.__enter__()
    try:
        second = host.lifecycle_lock(tmp_path)
        with pytest.raises(HostError, match="already running"):
            second.__enter__()
    finally:
        first.__exit__(None, None, None)


def test_application_bundle_is_deterministic_and_ignores_non_python(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src/shuttle_gate"
    source.mkdir(parents=True)
    (source / "__main__.py").write_text("print('ok')\n", encoding="utf-8")
    (source / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (source / "ignored.txt").write_text("ignored\n", encoding="utf-8")
    first = tmp_path / "one.pyz"
    second = tmp_path / "two.pyz"

    host._build_application_bundle(tmp_path, first)
    host._build_application_bundle(tmp_path, second)

    assert first.read_bytes() == second.read_bytes()
    assert first.stat().st_mode & 0o777 == 0o600

    incomplete = tmp_path / "incomplete"
    incomplete.mkdir()
    with pytest.raises(HostError, match="incomplete"):
        host._build_application_bundle(incomplete, tmp_path / "bad.pyz")


def test_host_binding_validation_checks_addresses_and_port(
    config: ProjectConfig,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _commands(monkeypatch)
    completed = subprocess.CompletedProcess(
        ["ip"],
        0,
        json.dumps(
            [
                {
                    "addr_info": [
                        {"local": "127.0.0.1"},
                        {"local": "::1"},
                    ]
                }
            ]
        ),
        "",
    )
    monkeypatch.setattr(host, "_run", lambda *_args, **_kwargs: completed)
    monkeypatch.setattr(Path, "read_text", lambda *_args, **_kwargs: "1024\n")

    host._check_host_bindings(config)

    missing = subprocess.CompletedProcess(["ip"], 0, "[]", "")
    monkeypatch.setattr(host, "_run", lambda *_args, **_kwargs: missing)
    with pytest.raises(HostError, match="not assigned"):
        host._check_host_bindings(config)


def test_status_reads_bounded_snapshot_and_main_dispatches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = _runtime(tmp_path)
    ensure_private_directory(runtime.output)
    atomic_write_json(
        runtime.output / "status.json",
        {
            "schema_version": 2,
            "state": "ready",
            "routes": ["10.0.0.0/8"],
            "peers": [],
        },
    )
    monkeypatch.setattr(host, "runtime_paths", lambda _root: runtime)
    monkeypatch.setattr(host, "_host_state", lambda _paths: "active")

    assert host._status(tmp_path, ["--json"]) == 0
    assert json.loads(capsys.readouterr().out)["service_state"] == "active"

    called: list[tuple[str, list[str]]] = []

    def dispatch_up(_root: Path, args: list[str]) -> int:
        called.append(("up", list(args)))
        return 0

    monkeypatch.setattr(host, "_up", dispatch_up)
    assert host.main(tmp_path, ["up"]) == 0
    assert called == [("up", [])]


def test_host_state_status_and_readiness_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path)
    _commands(monkeypatch)
    assert host._read_status(runtime) is None
    inactive = subprocess.CompletedProcess(["systemctl"], 1, "", "not found")
    monkeypatch.setattr(host, "_run", lambda *_args, **_kwargs: inactive)
    assert host._host_state(runtime) == "inactive"

    active = subprocess.CompletedProcess(["systemctl"], 0, "active\n", "")
    monkeypatch.setattr(host, "_run", lambda *_args, **_kwargs: active)
    assert host._host_state(runtime) == "active"

    degraded = subprocess.CompletedProcess(["systemctl"], 1, "degraded\n", "")
    monkeypatch.setattr(host, "_run", lambda *_args, **_kwargs: degraded)
    host._check_user_manager()
    offline = subprocess.CompletedProcess(["systemctl"], 1, "offline\n", "")
    monkeypatch.setattr(host, "_run", lambda *_args, **_kwargs: offline)
    with pytest.raises(HostError, match="not ready"):
        host._check_user_manager()

    ensure_private_directory(runtime.output)
    (runtime.output / "status.json").write_text("[]", encoding="utf-8")
    assert host._read_status(runtime) is None
    atomic_write_json(
        runtime.output / "status.json",
        {"schema_version": 2, "launch_id": "a" * 32, "state": "ready"},
    )
    assert host._read_status(runtime) is not None
    (runtime.output / "status.json").write_bytes(b"x" * 65537)
    assert host._read_status(runtime) is None

    monkeypatch.setattr(
        host,
        "_read_status",
        lambda _paths: {"launch_id": "a" * 32, "state": "ready"},
    )
    host._wait_for_state(runtime, "a" * 32, 1)

    statuses = iter(
        [
            {"launch_id": "a" * 32, "state": "retrying", "error": "temporary"},
            {"launch_id": "a" * 32, "state": "ready"},
        ]
    )
    monkeypatch.setattr(host, "_read_status", lambda _paths: next(statuses))
    monkeypatch.setattr(host, "_host_state", lambda _paths: "activating")
    host._wait_for_state(runtime, "a" * 32, 1)

    monkeypatch.setattr(
        host,
        "_read_status",
        lambda _paths: {"launch_id": "a" * 32, "state": "failed", "error": "bad"},
    )
    with pytest.raises(HostError, match="bad"):
        host._wait_for_state(runtime, "a" * 32, 1)

    monkeypatch.setattr(host, "_read_status", lambda _paths: None)
    monkeypatch.setattr(host, "_host_state", lambda _paths: "inactive")
    with pytest.raises(HostError, match="stopped before readiness"):
        host._wait_for_state(runtime, "a" * 32, 1)


def test_status_text_down_logs_and_operator_paths(
    config: ProjectConfig,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    runtime = _runtime(tmp_path)
    _commands(monkeypatch)
    monkeypatch.setattr(host, "runtime_paths", lambda _root: runtime)
    monkeypatch.setattr(host, "_host_state", lambda _paths: "active")
    monkeypatch.setattr(
        host,
        "_read_status",
        lambda _paths: {
            "schema_version": 2,
            "state": "ready",
            "wireguard_interface": "wg0",
            "routes": ["10.0.0.0/8"],
            "peers": [
                {
                    "name": "phone",
                    "latest_handshake": 1,
                    "received_bytes": 2,
                    "sent_bytes": 3,
                }
            ],
        },
    )
    assert host._status(tmp_path, []) == 0
    assert "peer phone" in capsys.readouterr().out
    with pytest.raises(HostError, match="status"):
        host._status(tmp_path, ["raw"])

    for path in (runtime.inputs, runtime.output):
        path.mkdir(parents=True, exist_ok=True)
    (runtime.inputs / "launch.json").touch()
    (runtime.inputs / "application.pyz").touch()
    (runtime.inputs / ".launch.json.abcdefgh").touch()
    (runtime.output / "status.json").touch()
    monkeypatch.setattr(host, "lifecycle_lock", lambda _root: nullcontext())
    monkeypatch.setattr(host, "_host_state", lambda _paths: "inactive")
    monkeypatch.setattr(
        host,
        "_run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "", ""),
    )
    assert host._down(tmp_path, []) == 0
    assert not runtime.root.exists()
    with pytest.raises(HostError, match="down"):
        host._down(tmp_path, ["raw"])

    unexpected = _runtime(tmp_path)
    unexpected.inputs.mkdir(parents=True)
    (unexpected.inputs / "unowned").touch()
    with pytest.raises(HostError, match="unexpected runtime object"):
        host._remove_known_runtime_files(unexpected)

    assert host._logs(tmp_path, ["--help"]) == 0
    assert "usage:" in capsys.readouterr().out

    calls: list[list[str]] = []
    monkeypatch.setattr(host, "load_config", lambda _path: config)
    monkeypatch.setattr(host, "_check_host_bindings", lambda _config: None)
    monkeypatch.setattr(host, "_check_user_manager", lambda: None)
    sandbox_options: list[dict[str, Any]] = []

    def sandbox(*_args: Any, **kwargs: Any) -> list[str]:
        sandbox_options.append(kwargs)
        return ["bwrap"]

    monkeypatch.setattr(host, "bubblewrap_command", sandbox)
    pasta_configs: list[ProjectConfig | None] = []

    def pasta(inner: list[str], selected: ProjectConfig | None = None) -> list[str]:
        pasta_configs.append(selected)
        return ["pasta", *inner]

    monkeypatch.setattr(host, "pasta_command", pasta)

    def record(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(host, "_run", record)
    assert host._operator(tmp_path, ["keys", "generate"]) == 0
    assert calls[-1] == ["bwrap"]
    assert host._operator(tmp_path, ["doctor"]) == 0
    assert calls[-1] == ["pasta", "bwrap"]
    assert sandbox_options[-1]["project_read_only"] is True
    assert pasta_configs[-1] is config


def test_dispatch_and_entrypoint_error_translation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert host.main(tmp_path, ["--help"]) == 0
    assert "usage:" in capsys.readouterr().out
    monkeypatch.setattr(host, "_down", lambda _root, _args: 10)
    monkeypatch.setattr(host, "_status", lambda _root, _args: 11)
    monkeypatch.setattr(host, "_logs", lambda _root, _args: 12)
    monkeypatch.setattr(host, "_operator", lambda _root, _args: 13)
    assert host.main(tmp_path, ["down"]) == 10
    assert host.main(tmp_path, ["status"]) == 11
    assert host.main(tmp_path, ["logs"]) == 12
    assert host.main(tmp_path, ["version"]) == 13

    monkeypatch.setattr(host, "main", lambda _root: (_ for _ in ()).throw(HostError("bad")))
    with pytest.raises(SystemExit) as raised:
        host.entrypoint(tmp_path)
    assert raised.value.code == 2
    assert capsys.readouterr().err == "shuttle-gate error: bad\n"


def test_up_prepares_and_starts_once(
    config: ProjectConfig,
    instance: InstancePaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path)
    commands: list[list[str]] = []
    monkeypatch.setattr(host, "runtime_paths", lambda _root: runtime)
    monkeypatch.setattr(host, "load_config", lambda _path: config)
    monkeypatch.setattr(host, "_command", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(host, "_check_host_bindings", lambda _config: None)
    monkeypatch.setattr(host, "_host_state", lambda _paths: "inactive")
    monkeypatch.setattr(host, "lifecycle_lock", lambda _root: nullcontext())
    monkeypatch.setattr(
        host, "_build_application_bundle", lambda _root, path: path.write_text("app")
    )
    monkeypatch.setattr(
        host,
        "prepare_launch",
        lambda *_args, **_kwargs: {"launch_id": "2" * 32},
    )
    monkeypatch.setattr(host, "bubblewrap_command", lambda *_args, **_kwargs: ["bwrap"])
    monkeypatch.setattr(host, "pasta_command", lambda *_args, **_kwargs: ["pasta"])
    monkeypatch.setattr(host, "systemd_run_command", lambda *_args, **_kwargs: ["systemd-run"])
    monkeypatch.setattr(host, "_wait_for_state", lambda *_args, **_kwargs: None)

    def run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "running\n", "")

    monkeypatch.setattr(host, "_run", run)

    assert host._up(instance.root, []) == 0
    assert ["systemd-run"] in commands
    assert runtime.inputs.is_dir()


def test_up_resumes_only_a_valid_active_launch(
    config: ProjectConfig,
    instance: InstancePaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _runtime(tmp_path)
    waited: list[str] = []
    monkeypatch.setattr(host, "runtime_paths", lambda _root: runtime)
    monkeypatch.setattr(host, "load_config", lambda _path: config)
    monkeypatch.setattr(host, "_command", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(host, "_check_host_bindings", lambda _config: None)
    monkeypatch.setattr(host, "_host_state", lambda _paths: "active")
    monkeypatch.setattr(host, "lifecycle_lock", lambda _root: nullcontext())
    generation = "gen-" + "1" * 32
    monkeypatch.setattr(
        host,
        "locked_state_view",
        lambda paths: nullcontext(
            StateView(paths=paths.with_data(paths.state / generation), generation=generation)
        ),
    )
    monkeypatch.setattr(
        host,
        "validate_launch_manifest",
        lambda *_args, **_kwargs: {"launch_id": "3" * 32},
    )
    monkeypatch.setattr(
        host,
        "_wait_for_state",
        lambda _paths, launch_id, _timeout: waited.append(launch_id),
    )
    monkeypatch.setattr(
        host,
        "_run",
        lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "running", ""),
    )

    assert host._up(instance.root, []) == 0
    assert waited == ["3" * 32]
    with pytest.raises(HostError, match="usage"):
        host._up(instance.root, ["raw"])
