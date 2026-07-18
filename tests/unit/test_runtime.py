from __future__ import annotations

import json
import os
import shlex
import signal
import socket
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import pytest

import shuttle_gate.runtime as runtime_module
from shuttle_gate.config import ProjectConfig
from shuttle_gate.errors import RuntimeFailure, TransientRuntimeFailure
from shuttle_gate.files import InstancePaths, atomic_write, atomic_write_json
from shuttle_gate.keys import generate_missing_keys
from shuttle_gate.launch import prepare_launch
from shuttle_gate.runner import CommandResult
from shuttle_gate.runtime import (
    REMOTE_PYTHON_CHECK_CODE,
    REMOTE_PYTHON_CHECK_SCRIPT,
    GatewayRuntime,
    _stop_process,
    doctor_checks,
    healthcheck,
    nft_filter,
    read_runtime_status,
    remote_python_check,
    resolve_ssh_addresses,
    run_gateway,
    runtime_paths,
    runtime_status,
    ssh_arguments,
    sshuttle_arguments,
    sshuttle_target,
)
from shuttle_gate.sshuttle_entry import ADAPTER_FAILURE_EXIT

from .conftest import config_data
from .fakes import FakeRunner


class FakeProcess:
    def __init__(self, pid: int = 123, returncode: int | None = None) -> None:
        self.pid = pid
        self.returncode = returncode
        self.terminated = False
        self.killed = False
        self.timeout_once = False

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float) -> int:
        if self.timeout_once:
            self.timeout_once = False
            raise subprocess.TimeoutExpired("fake", timeout)
        self.returncode = 0
        return 0

    def kill(self) -> None:
        self.killed = True


class FailingCleanupRunner:
    def __init__(self) -> None:
        self.delegate = FakeRunner()
        self.failed = False

    def run(
        self,
        args: Sequence[str],
        *,
        input_text: str | None = None,
        timeout: float = 30.0,
        check: bool = True,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        if not self.failed:
            self.failed = True
            raise RuntimeError("first cleanup command failed")
        return self.delegate.run(
            args,
            input_text=input_text,
            timeout=timeout,
            check=check,
            env=env,
        )


def as_process(process: FakeProcess) -> subprocess.Popen[bytes]:
    return cast("subprocess.Popen[bytes]", process)


def test_ssh_arguments_enforce_noninteractive_strict_auth(
    config: ProjectConfig,
    instance: InstancePaths,
) -> None:
    arguments = ssh_arguments(config, instance)
    joined = " ".join(arguments)

    assert "BatchMode=yes" in joined
    assert "PasswordAuthentication=no" in joined
    assert "StrictHostKeyChecking=yes" in joined
    assert f"UserKnownHostsFile={instance.secrets / 'known_hosts'}" in joined
    assert "private" not in joined


def test_remote_python_check_is_bounded_and_read_only(
    config: ProjectConfig,
    instance: InstancePaths,
) -> None:
    runner = FakeRunner()

    remote_python_check(config, instance, runner)

    command = runner.calls[0][0]
    assert command[0] == "ssh"
    assert command[-3:-1] == ("--", "tester@ssh.example.test")
    remote_tokens = shlex.split(command[-1])
    assert remote_tokens == [
        "sh",
        "-c",
        REMOTE_PYTHON_CHECK_SCRIPT,
        "shuttle-gate-python-check",
        "python3",
        REMOTE_PYTHON_CHECK_CODE,
    ]
    assert "python3" not in REMOTE_PYTHON_CHECK_SCRIPT
    assert not {"touch", ">", "tee", "install"}.intersection(remote_tokens)


def test_sshuttle_command_uses_native_method_shim_and_safe_exclusions(
    config: ProjectConfig,
    instance: InstancePaths,
) -> None:
    command = sshuttle_arguments(config, instance, ["192.0.2.10", "2001:db8::10"])
    rendered = " ".join(command)

    assert "--method tproxy" in rendered
    assert "--listen 0.0.0.0:0,[::]:0" in rendered
    assert "--tmark 0x1" in rendered
    assert "--to-ns fd20:1234::53" in rendered
    assert "192.0.2.10/32" in command
    assert "2001:db8::10/128" in command
    assert "224.0.0.0/4" in command
    assert "ff00::/8" in command
    assert "10.0.0.0/8" in command
    assert "fd20:1234::/48" in command
    assert "auto-hosts" not in rendered


def test_sshuttle_target_brackets_ipv6_remote() -> None:
    data = config_data()
    data["ssh"]["host"] = "2001:db8::22"
    config = ProjectConfig.model_validate(data)

    assert sshuttle_target(config) == "tester@[2001:db8::22]:2222"


def test_nft_filter_drops_every_uncaptured_forward() -> None:
    rendered = nft_filter()

    assert 'iifname "wg0" meta mark != 0x1 counter drop' in rendered
    assert "direct WireGuard access to namespace" in rendered
    assert "type filter hook forward priority filter; policy drop" in rendered
    assert "uncaptured WireGuard traffic" in rendered
    assert " counter accept" not in rendered


def test_runtime_cleanup_is_idempotent(
    config: ProjectConfig, instance: InstancePaths, tmp_path: Path
) -> None:
    runner = FakeRunner()
    runtime = GatewayRuntime(config, instance, tmp_path / "run", runner=runner)

    runtime.cleanup()
    runtime.cleanup()

    commands = [call[0] for call in runner.calls]
    assert ("ip", "link", "del", "dev", "wg0") in commands
    assert ("nft", "delete", "table", "inet", "shuttle_gate") in commands
    assert all(not check for _args, _input, check in runner.calls)


def test_runtime_cleanup_continues_after_an_independent_failure(
    config: ProjectConfig, instance: InstancePaths, tmp_path: Path
) -> None:
    runner = FailingCleanupRunner()
    runtime = GatewayRuntime(config, instance, tmp_path / "run", runner=runner)

    with pytest.raises(RuntimeFailure, match="cleanup was incomplete"):
        runtime.cleanup()

    commands = [call[0] for call in runner.delegate.calls]
    assert ("ip", "link", "del", "dev", "wg0") in commands
    assert ("ip", "-4", "route", "flush", "table", "100") in commands


def test_namespace_sysctls_are_fixed_and_failure_is_fatal(
    config: ProjectConfig,
    instance: InstancePaths,
    tmp_path: Path,
) -> None:
    sysctls = tmp_path / "sys"
    values = (
        "net/ipv4/conf/all/src_valid_mark",
        "net/ipv4/ip_forward",
        "net/ipv6/bindv6only",
        "net/ipv6/conf/all/forwarding",
    )
    for relative in values:
        path = sysctls / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("0\n", encoding="ascii")
    gateway = GatewayRuntime(config, instance, tmp_path / "runtime", sysctl_root=sysctls)

    gateway._configure_namespace()

    assert all((sysctls / relative).read_text(encoding="ascii") == "1\n" for relative in values)

    ipv4_data = config_data()
    ipv4_data["wireguard"]["gateway_addresses"] = ["10.77.0.1/24"]
    for peer in ipv4_data["wireguard"]["peers"]:
        peer["addresses"] = [address for address in peer["addresses"] if ":" not in address]
    ipv4_data["routing"]["networks"] = ["10.0.0.0/8"]
    ipv4_data["dns"] = {"enabled": False}
    ipv4 = ProjectConfig.model_validate(ipv4_data)
    ipv4_sysctls = tmp_path / "ipv4-sys"
    for relative in values[:2]:
        path = ipv4_sysctls / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("0\n", encoding="ascii")
    GatewayRuntime(
        ipv4,
        instance,
        tmp_path / "ipv4-runtime",
        sysctl_root=ipv4_sysctls,
    )._configure_namespace()

    gateway.sysctl_root = tmp_path / "missing"
    with pytest.raises(RuntimeFailure, match="sysctl"):
        gateway._configure_namespace()


def test_runtime_paths_honor_sandbox_overrides(
    config: ProjectConfig,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SHUTTLE_GATE_CONFIG", str(tmp_path / "custom.yaml"))
    monkeypatch.setenv("SHUTTLE_GATE_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("SHUTTLE_GATE_RUNTIME", str(tmp_path / "runtime"))
    monkeypatch.setenv("SHUTTLE_GATE_LAUNCH", str(tmp_path / "launch.json"))
    monkeypatch.setenv("SHUTTLE_GATE_BUNDLE", str(tmp_path / "application.pyz"))

    config_path, paths, runtime_dir, launch_path, bundle_path = runtime_paths()

    assert config_path == tmp_path / "custom.yaml"
    assert paths.state == tmp_path / "state"
    assert paths.secrets == Path("/secrets")
    assert runtime_dir == tmp_path / "runtime"
    assert launch_path == tmp_path / "launch.json"
    assert bundle_path == tmp_path / "application.pyz"
    arguments = ssh_arguments(config, paths)
    assert "/secrets/id_ed25519" in arguments
    assert "UserKnownHostsFile=/secrets/known_hosts" in arguments


def test_wireguard_and_policy_setup_use_exact_dual_stack_commands(
    config: ProjectConfig,
    instance: InstancePaths,
    tmp_path: Path,
) -> None:
    runner = FakeRunner()
    generate_missing_keys(config, instance, runner)
    gateway = GatewayRuntime(config, instance, tmp_path / "runtime", runner=runner)

    gateway._setup_wireguard()
    gateway._setup_policy_routing()

    commands = [call[0] for call in runner.calls]
    assert ("ip", "link", "add", "dev", "wg0", "type", "wireguard") in commands
    assert ("ip", "-4", "address", "add", "10.77.0.1/24", "dev", "wg0") in commands
    assert ("ip", "-6", "address", "add", "fd77::1/64", "dev", "wg0") in commands
    assert any(
        command[:4] == ("wg", "setconf", "wg0", str(tmp_path / "runtime" / "wireguard.conf"))
        for command in commands
    )
    assert any(command[:5] == ("ip", "-4", "route", "replace", "local") for command in commands)
    assert any(command[:5] == ("ip", "-6", "rule", "add", "fwmark") for command in commands)


def test_start_writes_ready_status_and_rolls_back_on_failure(
    config: ProjectConfig,
    instance: InstancePaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = FakeRunner()
    generate_missing_keys(config, instance, runner)
    sshuttle = FakeProcess(pid=201)
    monkeypatch.setattr(
        runtime_module,
        "remote_python_check",
        lambda _config, _paths, _runner: None,
    )
    monkeypatch.setattr(runtime_module, "resolve_ssh_addresses", lambda _config: ("192.0.2.1",))

    def start_sshuttle(gateway: GatewayRuntime, _excluded: Any) -> None:
        gateway.sshuttle = as_process(sshuttle)

    monkeypatch.setattr(GatewayRuntime, "_start_sshuttle", start_sshuttle)
    gateway = GatewayRuntime(
        config,
        instance,
        tmp_path / "runtime",
        runner=runner,
        launch_id="1" * 32,
    )

    gateway.start()

    status = read_runtime_status(tmp_path / "runtime")
    assert status["state"] == "ready"
    assert status["schema_version"] == 2
    assert status["launch_id"] == "1" * 32
    assert status["sshuttle_pid"] == 201
    commands = [call[0] for call in runner.calls]
    assert commands.index(("nft", "--file", "-")) < commands.index(
        ("ip", "link", "add", "dev", "wg0", "type", "wireguard")
    )
    assert commands.index(("ip", "link", "set", "dev", "wg0", "up")) < commands.index(
        ("nft", "list", "table", "inet", "shuttle_gate")
    )

    failed = GatewayRuntime(config, instance, tmp_path / "failed", runner=runner)
    monkeypatch.setattr(
        GatewayRuntime,
        "_setup_wireguard",
        lambda _gateway: (_ for _ in ()).throw(RuntimeError("setup failed")),
    )
    with pytest.raises(RuntimeError, match="setup failed"):
        failed.start()
    assert ("ip", "link", "del", "dev", "wg0") in [call[0] for call in runner.calls]


def test_supervision_detects_child_exit_and_stop_signal(
    config: ProjectConfig,
    instance: InstancePaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = GatewayRuntime(config, instance, tmp_path)
    gateway.sshuttle = as_process(FakeProcess(returncode=4))
    monkeypatch.setattr(gateway.stopping, "wait", lambda _timeout: False)
    with pytest.raises(RuntimeFailure, match="sshuttle"):
        gateway.supervise()

    gateway.request_stop(15, None)
    assert gateway.stopping.is_set()


class FakeNotifySocket:
    def __init__(self, messages: list[bytes | TimeoutError]) -> None:
        self.messages = messages
        self.closed = False
        self.bound: str | None = None

    def bind(self, path: str) -> None:
        self.bound = path

    def settimeout(self, _timeout: float) -> None:
        return

    def recv(self, _size: int) -> bytes:
        value = self.messages.pop(0)
        if isinstance(value, TimeoutError):
            raise value
        return value

    def close(self) -> None:
        self.closed = True


def test_sshuttle_start_waits_for_ready_and_reports_early_exit(
    config: ProjectConfig,
    instance: InstancePaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ready_socket = FakeNotifySocket([TimeoutError(), b"READY=1\n"])
    process = FakeProcess()
    monkeypatch.setattr(socket, "socket", lambda *_args: ready_socket)
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda _args, env: as_process(process),
    )
    gateway = GatewayRuntime(config, instance, tmp_path)
    gateway._start_sshuttle(("192.0.2.1",))
    assert ready_socket.closed
    assert gateway.sshuttle is not None

    exit_socket = FakeNotifySocket([b"unused"])
    monkeypatch.setattr(socket, "socket", lambda *_args: exit_socket)
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda _args, env: as_process(FakeProcess(returncode=9)),
    )
    with pytest.raises(RuntimeFailure, match="status 9"):
        gateway._start_sshuttle(())
    assert exit_socket.closed

    permanent_socket = FakeNotifySocket([b"unused"])
    monkeypatch.setattr(socket, "socket", lambda *_args: permanent_socket)
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda _args, env: as_process(FakeProcess(returncode=ADAPTER_FAILURE_EXIT)),
    )
    with pytest.raises(RuntimeFailure, match=f"status {ADAPTER_FAILURE_EXIT}") as raised:
        gateway._start_sshuttle(())
    assert not isinstance(raised.value, TransientRuntimeFailure)
    assert permanent_socket.closed


def test_stop_process_escalates_after_timeout() -> None:
    process = FakeProcess()
    process.timeout_once = True

    _stop_process(as_process(process))

    assert process.terminated
    assert process.killed
    _stop_process(None)
    _stop_process(as_process(FakeProcess(returncode=0)))


def test_read_runtime_status_is_bounded(tmp_path: Path) -> None:
    atomic_write_json(tmp_path / "status.json", {"schema_version": 2, "state": "ready"})
    assert read_runtime_status(tmp_path)["state"] == "ready"

    (tmp_path / "status.json").write_bytes(b"x" * 65537)
    with pytest.raises(RuntimeFailure, match="bounded regular"):
        read_runtime_status(tmp_path)

    (tmp_path / "status.json").write_text("[]", encoding="utf-8")
    with pytest.raises(RuntimeFailure, match="invalid format"):
        read_runtime_status(tmp_path)

    (tmp_path / "status.json").write_bytes(b"\xff")
    with pytest.raises(RuntimeFailure, match="unavailable"):
        read_runtime_status(tmp_path)

    (tmp_path / "status.json").unlink()
    target = tmp_path / "status-target.json"
    atomic_write_json(target, {"schema_version": 2, "state": "ready"})
    (tmp_path / "status.json").symlink_to(target)
    with pytest.raises(RuntimeFailure, match="bounded regular"):
        read_runtime_status(tmp_path)

    (tmp_path / "status.json").unlink()
    with pytest.raises(RuntimeFailure, match="unavailable"):
        read_runtime_status(tmp_path)


def test_resolve_ssh_addresses_deduplicates(
    monkeypatch: pytest.MonkeyPatch, config: ProjectConfig
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 22)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 22)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 22, 0, 0)),
        ],
    )

    assert resolve_ssh_addresses(config) == ("192.0.2.1", "2001:db8::1")

    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [])
    with pytest.raises(RuntimeFailure, match="no addresses"):
        resolve_ssh_addresses(config)

    def fail_resolution(*_args: Any, **_kwargs: Any) -> Any:
        raise socket.gaierror("failed")

    monkeypatch.setattr(socket, "getaddrinfo", fail_resolution)
    with pytest.raises(RuntimeFailure, match="cannot resolve"):
        resolve_ssh_addresses(config)


def test_healthcheck_validates_processes_and_interface(
    instance: InstancePaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHUTTLE_GATE_CONFIG", str(instance.config))
    monkeypatch.setenv("SHUTTLE_GATE_RUNTIME", str(tmp_path))
    atomic_write_json(
        tmp_path / "status.json",
        {
            "schema_version": 2,
            "state": "ready",
            "sshuttle_pid": os.getpid(),
        },
    )
    fake = FakeRunner()
    for family in ("-4", "-6"):
        command = ("ip", family, "rule", "show", "priority", "100")
        fake.results[command] = CommandResult(
            command,
            0,
            "100: from all fwmark 0x1 lookup 100\n",
            "",
        )
    monkeypatch.setattr(runtime_module, "SubprocessRunner", lambda: fake)
    assert healthcheck() == 0

    atomic_write_json(tmp_path / "status.json", {"schema_version": 2, "state": "stopping"})
    assert healthcheck() == 1
    atomic_write_json(
        tmp_path / "status.json",
        {"schema_version": 2, "state": "ready", "sshuttle_pid": "bad"},
    )
    assert healthcheck() == 1


def test_runtime_status_snapshot_maps_public_keys_without_exposing_secrets(
    config: ProjectConfig,
    instance: InstancePaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generate_missing_keys(config, instance, FakeRunner())
    runtime_dir = tmp_path / "runtime"
    phone_public = (instance.peer_dir("phone") / "public.key").read_text().strip()
    dump = (
        "server-private\tserver-public\t51820\toff\n"
        "bad\n"
        f"{phone_public}\tpsk\t192.0.2.2:1234\t10.77.0.2/32\t123\t10\t20\t25\n"
        "unknown\tpsk\t(none)\t\t0\t0\t0\toff\n"
    )
    fake = FakeRunner()
    fake.results[("wg", "show", "wg0", "dump")] = CommandResult(
        ("wg", "show", "wg0", "dump"), 0, dump, ""
    )
    gateway = GatewayRuntime(
        config,
        instance,
        runtime_dir,
        runner=fake,
        launch_id="2" * 32,
        sshuttle=as_process(FakeProcess(pid=os.getpid())),
    )
    gateway._write_status("ready")
    monkeypatch.setenv("SHUTTLE_GATE_RUNTIME", str(runtime_dir))

    value = runtime_status()

    assert value["peers"][0]["name"] == "phone"
    assert value["peers"][1]["name"] == "unknown"
    assert value["peers"][1]["endpoint"] is None
    assert value["peers"][1]["persistent_keepalive"] == 0
    assert "server-private" not in json.dumps(value)

    invalid_dump = dump.replace("\t123\t10\t20\t25\n", "\tinvalid\t10\t20\t25\n")
    fake.results[("wg", "show", "wg0", "dump")] = CommandResult(
        ("wg", "show", "wg0", "dump"), 0, invalid_dump, ""
    )
    with pytest.raises(RuntimeFailure, match="invalid handshake time"):
        gateway._write_status("ready")


def test_run_gateway_always_cleans_runtime(
    config: ProjectConfig,
    instance: InstancePaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    generate_missing_keys(config, instance, FakeRunner())
    bundle = tmp_path / "application.pyz"
    launch = tmp_path / "launch.json"
    atomic_write(bundle, "application\n", 0o600)
    prepare_launch(
        config,
        instance,
        launch,
        bundle,
        instance_id="1" * 20,
        unit_name=f"shuttle-gate-{'1' * 20}.service",
    )

    class FakeGateway:
        def __init__(self, **_kwargs: Any) -> None:
            return

        def request_stop(self, _signum: int, _frame: object) -> None:
            return

        def start(self) -> None:
            events.append("start")

        def supervise(self) -> None:
            events.append("supervise")

        def cleanup(self) -> None:
            events.append("cleanup")

        def _write_status(
            self,
            state: str,
            ignore_errors: bool = False,
            error: str | None = None,
        ) -> None:
            del ignore_errors, error
            events.append(f"status:{state}")

    monkeypatch.setattr(
        runtime_module,
        "runtime_paths",
        lambda: (instance.config, instance, tmp_path, launch, bundle),
    )
    monkeypatch.setattr(runtime_module, "load_config", lambda _path: config)
    monkeypatch.setattr(runtime_module, "GatewayRuntime", FakeGateway)
    monkeypatch.setattr(signal, "signal", lambda *_args: None)

    assert run_gateway() == 0
    assert events == ["start", "supervise", "cleanup", "status:stopped"]

    class TransientGateway(FakeGateway):
        def supervise(self) -> None:
            events.append("supervise")
            raise TransientRuntimeFailure("retry safely")

    events.clear()
    monkeypatch.setattr(runtime_module, "GatewayRuntime", TransientGateway)
    with pytest.raises(TransientRuntimeFailure, match="retry safely"):
        run_gateway()
    assert events == ["start", "supervise", "cleanup", "status:retrying"]


def test_doctor_checks_use_operator_paths_and_clean_up_tproxy_chains(
    config: ProjectConfig,
    instance: InstancePaths,
) -> None:
    runner = FakeRunner()
    messages = doctor_checks(config, instance, runner)

    assert messages[-1].endswith("ok")
    commands = [call[0] for call in runner.calls]
    assert ("ip", "link", "del", "dev", "sg-doctor0") in commands
    assert ("nft", "delete", "table", "ip", "shuttle_gate_tproxy_12001") in commands
    assert ("nft", "delete", "table", "ip6", "shuttle_gate_tproxy_12002") in commands
    assert any(command == ("nft", "--check", "--file", "-") for command in commands)
    ssh_command = next(command for command in commands if command[0] == "ssh")
    assert str(instance.secrets / "id_ed25519") in ssh_command
    assert f"UserKnownHostsFile={instance.secrets / 'known_hosts'}" in ssh_command
