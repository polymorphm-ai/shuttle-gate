"""Gateway network setup, supervision, health, and status."""

from __future__ import annotations

import json
import os
import shlex
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from contextlib import suppress
from dataclasses import dataclass, field
from ipaddress import IPv6Address, ip_address
from pathlib import Path
from typing import Any

from .config import ProjectConfig, effective_routes, load_config
from .errors import CommandError, RuntimeFailure, ShuttleGateError, TransientRuntimeFailure
from .files import InstancePaths, atomic_write, atomic_write_json, mounted_secret_path
from .keys import load_peer_keys, load_server_keys
from .launch import validate_launch_manifest
from .nft_tproxy import PROXY_INGRESS_INTERFACE, render_tproxy_table
from .render import render_server_config
from .runner import Runner, SubprocessRunner
from .sshuttle_entry import ADAPTER_FAILURE_EXIT
from .state import locked_state_view

INTERFACE = PROXY_INGRESS_INTERFACE
TPROXY_TABLE = "100"
TPROXY_MARK = "0x1"
TPROXY_PRIORITY = "100"
NFT_TABLE = "shuttle_gate"
STATUS_FILE = "status.json"
NOTIFY_FILE = "sshuttle-notify.sock"
PROCESS_STOP_SECONDS = 10.0
MULTICAST_EXCLUSIONS = ("224.0.0.0/4", "255.255.255.255/32", "ff00::/8")
REMOTE_PYTHON_CHECK_CODE = "import sys;raise SystemExit(0 if sys.version_info>=(3,9) else 3)"
REMOTE_PYTHON_CHECK_SCRIPT = 'exec "$1" -B -c "$2"'


def runtime_paths() -> tuple[Path, InstancePaths, Path, Path, Path]:
    """Resolve fixed sandbox mount paths from the controlled environment."""

    config_path = Path(os.environ.get("SHUTTLE_GATE_CONFIG", "/config/config.yaml"))
    state_path = Path(os.environ.get("SHUTTLE_GATE_STATE", "/state"))
    runtime_path = Path(os.environ.get("SHUTTLE_GATE_RUNTIME", "/run/shuttle-gate"))
    launch_path = Path(os.environ.get("SHUTTLE_GATE_LAUNCH", "/run/shuttle-gate/launch.json"))
    bundle_path = Path(os.environ.get("SHUTTLE_GATE_BUNDLE", "/opt/shuttle-gate/application.pyz"))
    paths = InstancePaths(
        root=Path("/"),
        config=config_path,
        state=state_path,
        secrets=Path("/secrets"),
    )
    return config_path, paths, runtime_path, launch_path, bundle_path


def ssh_arguments(config: ProjectConfig, paths: InstancePaths) -> list[str]:
    """Build strict SSH arguments using this execution context's secret paths."""

    identity = mounted_secret_path(paths, config.ssh.identity_file)
    known_hosts = mounted_secret_path(paths, config.ssh.known_hosts_file)
    return [
        "ssh",
        "-F",
        "/dev/null",
        "-p",
        str(config.ssh.port),
        "-i",
        str(identity),
        "-o",
        "BatchMode=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        f"ConnectTimeout={config.ssh.connect_timeout_seconds}",
        "-o",
        f"ServerAliveInterval={config.ssh.server_alive_interval_seconds}",
        "-o",
        f"ServerAliveCountMax={config.ssh.server_alive_count_max}",
        "-o",
        "LogLevel=ERROR",
    ]


def ssh_target(config: ProjectConfig) -> str:
    """Return the validated SSH destination."""

    return f"{config.ssh.user}@{config.ssh.host}"


def sshuttle_target(config: ProjectConfig) -> str:
    """Return sshuttle's remote syntax, including an unambiguous IPv6 port."""

    host = config.ssh.host
    try:
        address = ip_address(host)
    except ValueError:
        rendered_host = host
    else:
        rendered_host = f"[{address}]" if isinstance(address, IPv6Address) else str(address)
    return f"{config.ssh.user}@{rendered_host}:{config.ssh.port}"


def remote_python_check(config: ProjectConfig, paths: InstancePaths, runner: Runner) -> None:
    """Verify authentication and Python without writing remote state."""

    remote_command = shlex.join(
        [
            "sh",
            "-c",
            REMOTE_PYTHON_CHECK_SCRIPT,
            "shuttle-gate-python-check",
            config.ssh.remote_python,
            REMOTE_PYTHON_CHECK_CODE,
        ]
    )
    runner.run(
        [*ssh_arguments(config, paths), "--", ssh_target(config), remote_command],
        timeout=float(config.ssh.connect_timeout_seconds + 10),
    )


def sshuttle_arguments(
    config: ProjectConfig,
    paths: InstancePaths,
) -> list[str]:
    """Build sshuttle's dual-stack native nftables TPROXY command."""

    families = {address.version for address in config.wireguard.gateway_addresses}
    listeners: list[str] = []
    if 4 in families:
        listeners.append("0.0.0.0:0")
    if 6 in families:
        listeners.append("[::]:0")
    command = [
        sys.executable,
        "-m",
        "shuttle_gate.sshuttle_entry",
        "--method",
        # sshuttle fixes the method name to "tproxy".  Our entrypoint injects
        # the native module in memory before sshuttle resolves this name.
        "tproxy",
        "--tmark",
        TPROXY_MARK,
        "--listen",
        ",".join(listeners),
        "--remote",
        sshuttle_target(config),
        "--python",
        config.ssh.remote_python,
        "--ssh-cmd",
        shlex.join(ssh_arguments(config, paths)),
        "--verbose",
    ]
    for network in MULTICAST_EXCLUSIONS:
        if (":" in network and 6 in families) or (":" not in network and 4 in families):
            command.extend(["--exclude", network])
    for gateway in config.wireguard.gateway_addresses:
        command.extend(["--exclude", str(gateway.network)])
    command.extend(str(route) for route in effective_routes(config))
    return command


def nft_filter() -> str:
    """Reject direct namespace access and uncaptured forwarding from peers."""

    rules = [
        f"table inet {NFT_TABLE} {{",
        "  chain input {",
        "    type filter hook input priority filter; policy accept;",
        (
            f'    iifname "{INTERFACE}" meta mark != {TPROXY_MARK} counter drop '
            'comment "direct WireGuard access to namespace"'
        ),
        "  }",
        "  chain forward {",
        "    type filter hook forward priority filter; policy drop;",
        f'    iifname "{INTERFACE}" counter drop comment "uncaptured WireGuard traffic"',
        "    counter drop",
        "  }",
        "}",
    ]
    return "\n".join(rules) + "\n"


def _wireguard_number(value: str, label: str, *, allow_off: bool = False) -> int:
    """Parse one non-negative field from stable `wg show ... dump` output."""

    if allow_off and value == "off":
        return 0
    try:
        number = int(value)
    except ValueError as exc:
        raise RuntimeFailure(f"WireGuard reported an invalid {label}") from exc
    if number < 0:
        raise RuntimeFailure(f"WireGuard reported an invalid {label}")
    return number


@dataclass
class GatewayRuntime:
    """Own and clean every mutable object in the gateway namespace."""

    config: ProjectConfig
    paths: InstancePaths
    runtime_dir: Path
    runner: Runner = field(default_factory=SubprocessRunner)
    launch_id: str = "unknown"
    sysctl_root: Path | None = None
    sshuttle: subprocess.Popen[bytes] | None = None
    stopping: threading.Event = field(default_factory=threading.Event)

    def start(self) -> None:
        """Start all components or roll back completely."""

        self.runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.runtime_dir.chmod(0o700)
        self.cleanup()
        self._write_status("starting")
        try:
            self._configure_namespace()
            try:
                remote_python_check(self.config, self.paths, self.runner)
            except CommandError as exc:
                raise TransientRuntimeFailure(str(exc)) from exc
            rules = nft_filter()
            self.runner.run(["nft", "--check", "--file", "-"], input_text=rules)
            self.runner.run(["nft", "--file", "-"], input_text=rules)
            self._setup_wireguard()
            self._setup_policy_routing()
            self._start_sshuttle()
            self._activate_wireguard()
            self._verify_postconditions()
            self._write_status("ready")
        except BaseException:
            with suppress(RuntimeFailure):
                self.cleanup()
            raise

    def supervise(self) -> None:
        """Wait for a stop signal or unexpected child exit."""

        while not self.stopping.wait(1.0):
            if self.sshuttle is None or self.sshuttle.poll() is not None:
                raise TransientRuntimeFailure("sshuttle exited unexpectedly")
            self._write_status("ready")

    def request_stop(self, _signum: int, _frame: object) -> None:
        """Signal handler that leaves cleanup to the main thread."""

        self.stopping.set()

    def cleanup(self) -> None:
        """Idempotently remove owned processes and network state."""

        self._write_status("stopping", ignore_errors=True)
        failures: list[Exception] = []

        def stop_process(process: subprocess.Popen[bytes] | None) -> None:
            try:
                _stop_process(process)
            except Exception as exc:  # cleanup must continue through independent effects
                failures.append(exc)

        def run_cleanup(command: list[str]) -> None:
            try:
                self.runner.run(command, check=False)
            except Exception as exc:
                failures.append(exc)

        stop_process(self.sshuttle)
        self.sshuttle = None
        run_cleanup(["nft", "delete", "table", "inet", NFT_TABLE])
        for family in ("-6", "-4"):
            run_cleanup(
                [
                    "ip",
                    family,
                    "rule",
                    "del",
                    "fwmark",
                    TPROXY_MARK,
                    "lookup",
                    TPROXY_TABLE,
                    "priority",
                    TPROXY_PRIORITY,
                ]
            )
            run_cleanup(["ip", family, "route", "flush", "table", TPROXY_TABLE])
        run_cleanup(["ip", "link", "del", "dev", INTERFACE])
        if failures:
            raise RuntimeFailure(
                "cleanup was incomplete; namespace destruction is the final boundary"
            ) from failures[0]

    def _configure_namespace(self) -> None:
        """Set fixed network-namespace sysctls without a host sysctl utility."""

        if self.sysctl_root is None:
            return
        families = {route.version for route in effective_routes(self.config)}
        values = {
            # Transparent UDP replies retain low remote source ports.
            "net/ipv4/ip_unprivileged_port_start": "0\n",
        }
        if 4 in families:
            values.update(
                {
                    # The TPROXY mark applies in only one routing direction.
                    "net/ipv4/conf/all/src_valid_mark": "0\n",
                    "net/ipv4/conf/default/src_valid_mark": "0\n",
                }
            )
        if 6 in families:
            values.update(
                {
                    "net/ipv6/bindv6only": "1\n",
                }
            )
        for relative, value in values.items():
            try:
                (self.sysctl_root / relative).write_text(value, encoding="ascii")
            except OSError as exc:
                raise RuntimeFailure(
                    f"cannot configure namespace sysctl {relative}: {exc}"
                ) from exc

    def _setup_wireguard(self) -> None:
        self.runner.run(["ip", "link", "del", "dev", INTERFACE], check=False)
        self.runner.run(["ip", "link", "add", "dev", INTERFACE, "type", "wireguard"])
        for interface in self.config.wireguard.gateway_addresses:
            family = "-6" if interface.version == 6 else "-4"
            self.runner.run(["ip", family, "address", "add", str(interface), "dev", INTERFACE])
        server = load_server_keys(self.paths)
        peers: dict[str, tuple[str, str]] = {}
        for peer in self.config.wireguard.peers:
            pair, preshared = load_peer_keys(self.paths, peer.name)
            peers[peer.name] = (pair.public, preshared)
        private_config = render_server_config(self.config, server.private, peers)
        config_path = self.runtime_dir / "wireguard.conf"
        atomic_write(config_path, private_config, 0o600)
        self.runner.run(["wg", "setconf", INTERFACE, str(config_path)])
        self.runner.run(
            ["ip", "link", "set", "dev", INTERFACE, "mtu", str(self.config.wireguard.mtu)]
        )

    def _activate_wireguard(self) -> None:
        """Expose the phone-facing interface only after the tunnel is ready."""

        self.runner.run(["ip", "link", "set", "dev", INTERFACE, "up"])

    def _verify_postconditions(self) -> None:
        """Verify externally visible state before publishing readiness."""

        if self.sshuttle is None or self.sshuttle.poll() is not None:
            raise RuntimeFailure("sshuttle is not running after startup")
        for command in (
            ["ip", "link", "show", "dev", INTERFACE],
            ["wg", "show", INTERFACE, "dump"],
            ["nft", "list", "table", "inet", NFT_TABLE],
        ):
            self.runner.run(command)

    def _setup_policy_routing(self) -> None:
        families = {route.version for route in effective_routes(self.config)}
        for version in sorted(families):
            family = "-6" if version == 6 else "-4"
            self.runner.run(
                [
                    "ip",
                    family,
                    "rule",
                    "del",
                    "fwmark",
                    TPROXY_MARK,
                    "lookup",
                    TPROXY_TABLE,
                    "priority",
                    TPROXY_PRIORITY,
                ],
                check=False,
            )
            self.runner.run(
                [
                    "ip",
                    family,
                    "route",
                    "replace",
                    "local",
                    "default",
                    "dev",
                    "lo",
                    "table",
                    TPROXY_TABLE,
                ]
            )
            self.runner.run(
                [
                    "ip",
                    family,
                    "rule",
                    "add",
                    "fwmark",
                    TPROXY_MARK,
                    "lookup",
                    TPROXY_TABLE,
                    "priority",
                    TPROXY_PRIORITY,
                ]
            )

    def _start_sshuttle(self) -> None:
        notify_path = self.runtime_dir / NOTIFY_FILE
        notify_path.unlink(missing_ok=True)
        notify_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            notify_socket.bind(str(notify_path))
            notify_socket.settimeout(0.25)
            environment = os.environ.copy()
            environment["NOTIFY_SOCKET"] = str(notify_path)
            self.sshuttle = subprocess.Popen(
                sshuttle_arguments(self.config, self.paths), env=environment
            )
            deadline = time.monotonic() + self.config.backend.startup_timeout_seconds
            while time.monotonic() < deadline:
                if self.sshuttle.poll() is not None:
                    failure_message = (
                        f"sshuttle exited during startup with status {self.sshuttle.returncode}"
                    )
                    if self.sshuttle.returncode == ADAPTER_FAILURE_EXIT:
                        raise RuntimeFailure(failure_message)
                    raise TransientRuntimeFailure(failure_message)
                try:
                    message = notify_socket.recv(4096)
                except TimeoutError:
                    continue
                if b"READY=1" in message:
                    return
            raise TransientRuntimeFailure(
                f"sshuttle did not become ready within {self.config.backend.startup_timeout_seconds}s"
            )
        finally:
            notify_socket.close()
            notify_path.unlink(missing_ok=True)

    def _peer_status(self) -> list[dict[str, Any]]:
        peer_names: dict[str, str] = {}
        for peer in self.config.wireguard.peers:
            pair, _preshared = load_peer_keys(self.paths, peer.name)
            peer_names[pair.public] = peer.name
        dump = self.runner.run(["wg", "show", INTERFACE, "dump"]).stdout.splitlines()
        peers: list[dict[str, Any]] = []
        for line in dump[1:]:
            columns = line.split("\t")
            if len(columns) < 8:
                continue
            public_key = columns[0]
            endpoint = None if columns[2] in {"", "(none)"} else columns[2]
            peers.append(
                {
                    "name": peer_names.get(public_key, "unknown"),
                    "public_key": public_key,
                    "endpoint": endpoint,
                    "allowed_ips": columns[3].split(",") if columns[3] else [],
                    "latest_handshake": _wireguard_number(columns[4], "handshake time"),
                    "received_bytes": _wireguard_number(columns[5], "received byte count"),
                    "sent_bytes": _wireguard_number(columns[6], "sent byte count"),
                    "persistent_keepalive": _wireguard_number(
                        columns[7],
                        "persistent keepalive",
                        allow_off=True,
                    ),
                }
            )
        return peers

    def _write_status(
        self,
        state: str,
        ignore_errors: bool = False,
        error: str | None = None,
    ) -> None:
        value: dict[str, Any] = {
            "schema_version": 2,
            "launch_id": self.launch_id,
            "state": state,
            "sshuttle_pid": self.sshuttle.pid if self.sshuttle is not None else None,
            "health": "ok" if state == "ready" else "degraded",
            "wireguard_interface": INTERFACE,
            "routes": [str(route) for route in effective_routes(self.config)],
            "peers": self._peer_status() if state == "ready" else [],
        }
        if error is not None:
            value["error"] = error[:4096]
        try:
            atomic_write_json(self.runtime_dir / STATUS_FILE, value, 0o600)
        except OSError:
            if not ignore_errors:
                raise


def _stop_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=PROCESS_STOP_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=PROCESS_STOP_SECONDS)


def run_gateway() -> int:
    """Run the long-lived gateway and preserve a terminal status snapshot."""

    config_path, paths, runtime_dir, launch_path, bundle_path = runtime_paths()
    config = load_config(config_path)
    with locked_state_view(paths) as view:
        manifest = validate_launch_manifest(
            config,
            view.paths,
            view.generation,
            launch_path,
            bundle_path,
        )
        launch_id = manifest.get("launch_id")
        if not isinstance(launch_id, str):
            raise RuntimeFailure("launch identifier is invalid")
        runtime = GatewayRuntime(
            config=config,
            paths=view.paths,
            runtime_dir=runtime_dir,
            launch_id=launch_id,
            sysctl_root=Path("/proc/sys"),
        )
        signal.signal(signal.SIGTERM, runtime.request_stop)
        signal.signal(signal.SIGINT, runtime.request_stop)
        try:
            runtime.start()
            runtime.supervise()
        except BaseException as exc:
            cleanup_error: RuntimeFailure | None = None
            try:
                runtime.cleanup()
            except RuntimeFailure as failure:
                cleanup_error = failure
            if isinstance(exc, ShuttleGateError):
                message = str(exc)
            else:
                message = f"unexpected runtime failure: {type(exc).__name__}"
            if cleanup_error is not None:
                message += f"; {cleanup_error}"
            terminal_state = "retrying" if isinstance(exc, TransientRuntimeFailure) else "failed"
            runtime._write_status(terminal_state, ignore_errors=True, error=message)
            raise
        runtime.cleanup()
        runtime._write_status("stopped", ignore_errors=True)
        return 0


def read_runtime_status(runtime_dir: Path) -> dict[str, Any]:
    """Read and validate the bounded non-secret runtime state file."""

    path = runtime_dir / STATUS_FILE
    try:
        info = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 64 * 1024:
            raise RuntimeFailure("runtime status must be a bounded regular file")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeFailure(f"runtime status is unavailable: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 2:
        raise RuntimeFailure("runtime status has an invalid format")
    return value


def healthcheck() -> int:
    """Return success only for a live ready gateway."""

    config_path, _paths, runtime_dir, _launch_path, _bundle_path = runtime_paths()
    try:
        config = load_config(config_path)
        status = read_runtime_status(runtime_dir)
        if status.get("state") != "ready":
            return 1
        pid = status.get("sshuttle_pid")
        if not isinstance(pid, int):
            return 1
        os.kill(pid, 0)
        runner = SubprocessRunner()
        checks = (
            ["ip", "link", "show", "dev", INTERFACE],
            ["nft", "list", "table", "inet", NFT_TABLE],
        )
        if any(runner.run(command, check=False).returncode != 0 for command in checks):
            return 1
        for version in {route.version for route in effective_routes(config)}:
            family = "-6" if version == 6 else "-4"
            rule = runner.run(
                ["ip", family, "rule", "show", "priority", TPROXY_PRIORITY],
                check=False,
            )
            if "fwmark 0x1 lookup 100" not in rule.stdout:
                return 1
        return 0
    except OSError, RuntimeFailure:
        return 1


def runtime_status() -> dict[str, Any]:
    """Return the current secret-free snapshot from inside the namespace."""

    _config_path, _paths, runtime_dir, _launch_path, _bundle_path = runtime_paths()
    return read_runtime_status(runtime_dir)


def doctor_checks(
    config: ProjectConfig,
    paths: InstancePaths,
    runner: Runner,
) -> list[str]:
    """Run reversible kernel checks in the disposable doctor namespace."""

    messages: list[str] = []
    interface = "sg-doctor0"
    try:
        runner.run(["ip", "link", "add", "dev", interface, "type", "wireguard"])
    finally:
        runner.run(["ip", "link", "del", "dev", interface], check=False)
    messages.append("kernel WireGuard: ok")

    families = {route.version for route in effective_routes(config)}
    checks: list[tuple[int, int, list[tuple[int, int, bool, str, int, int]]]] = []
    if 4 in families:
        checks.append((socket.AF_INET, 12001, [(socket.AF_INET, 8, False, "10.0.0.0", 0, 0)]))
    if 6 in families:
        checks.append((socket.AF_INET6, 12002, [(socket.AF_INET6, 48, False, "fd00::", 0, 0)]))
    for family, port, subnets in checks:
        rules = render_tproxy_table(
            port=port,
            family=family,
            subnets=subnets,
            udp=True,
            mark="0x7fff",
        )
        nft_family = "ip" if family == socket.AF_INET else "ip6"
        try:
            runner.run(["nft", "--check", "--file", "-"], input_text=rules)
            runner.run(["nft", "--file", "-"], input_text=rules)
        finally:
            runner.run(
                ["nft", "delete", "table", nft_family, f"shuttle_gate_tproxy_{port}"],
                check=False,
            )
    rendered_families = "/".join(f"IPv{family}" for family in sorted(families))
    messages.append(f"native nftables {rendered_families} TPROXY: ok")
    remote_python_check(config, paths, runner)
    messages.append("SSH authentication and remote Python >= 3.9: ok")
    return messages
