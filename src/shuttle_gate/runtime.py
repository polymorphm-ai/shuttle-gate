"""Gateway network setup, supervision, health, and status."""

from __future__ import annotations

import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from ipaddress import IPv6Address, ip_address
from pathlib import Path
from typing import Any

from .compose import validate_launch_manifest
from .config import ProjectConfig, effective_routes, load_config
from .errors import RuntimeFailure
from .files import InstancePaths, atomic_write, atomic_write_json, container_secret_path
from .keys import load_peer_keys, load_server_keys
from .nft_tproxy import render_tproxy_table
from .render import render_server_config
from .runner import Runner, SubprocessRunner
from .state import locked_state_view

INTERFACE = "wg0"
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


def runtime_paths() -> tuple[Path, InstancePaths, Path]:
    """Resolve fixed container mount paths from the environment."""

    config_path = Path(os.environ.get("SHUTTLE_GATE_CONFIG", "/config/config.yaml"))
    state_path = Path(os.environ.get("SHUTTLE_GATE_STATE", "/state"))
    runtime_path = Path(os.environ.get("SHUTTLE_GATE_RUNTIME", "/run/shuttle-gate"))
    paths = InstancePaths(
        root=Path("/"),
        config=config_path,
        state=state_path,
        secrets=Path("/secrets"),
    )
    return config_path, paths, runtime_path


def ssh_arguments(config: ProjectConfig) -> list[str]:
    """Build deterministic strict SSH arguments using container secret mounts."""

    identity = container_secret_path(config.ssh.identity_file)
    known_hosts = container_secret_path(config.ssh.known_hosts_file)
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


def remote_python_check(config: ProjectConfig, runner: Runner) -> None:
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
        [*ssh_arguments(config), "--", ssh_target(config), remote_command],
        timeout=float(config.ssh.connect_timeout_seconds + 10),
    )


def resolve_ssh_addresses(config: ProjectConfig) -> tuple[str, ...]:
    """Resolve every SSH endpoint address for tunnel-recursion exclusions."""

    try:
        answers = socket.getaddrinfo(
            config.ssh.host,
            config.ssh.port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise RuntimeFailure(f"cannot resolve SSH host {config.ssh.host}: {exc}") from exc
    addresses = sorted({str(answer[4][0]).split("%", 1)[0] for answer in answers})
    if not addresses:
        raise RuntimeFailure(f"SSH host resolved to no addresses: {config.ssh.host}")
    return tuple(addresses)


def sshuttle_arguments(config: ProjectConfig, excluded_addresses: Sequence[str]) -> list[str]:
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
        "sshuttle",
        "--method",
        # sshuttle's CLI fixes the method name to "tproxy".  The runtime image
        # replaces that module with shuttle-gate's native nftables method.
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
        shlex.join(ssh_arguments(config)),
        "--verbose",
    ]
    if config.dns.enabled and config.dns.upstream is not None:
        upstream = str(config.dns.upstream)
        command.extend(["--ns-hosts", upstream, "--to-ns", upstream])
    for address in excluded_addresses:
        width = "32" if ":" not in address else "128"
        command.extend(["--exclude", f"{address}/{width}"])
    for network in MULTICAST_EXCLUSIONS:
        if (":" in network and 6 in families) or (":" not in network and 4 in families):
            command.extend(["--exclude", network])
    for gateway in config.wireguard.gateway_addresses:
        command.extend(["--exclude", str(gateway.network)])
    command.extend(str(route) for route in effective_routes(config))
    return command


def dnsmasq_arguments(config: ProjectConfig) -> list[str]:
    """Build a private-interface-only DNS forwarder command."""

    if not config.dns.enabled or config.dns.upstream is None:
        raise ValueError("DNS is disabled")
    addresses = ",".join(str(interface.ip) for interface in config.wireguard.gateway_addresses)
    return [
        "dnsmasq",
        "--keep-in-foreground",
        "--bind-interfaces",
        "--no-resolv",
        "--no-hosts",
        "--cache-size=150",
        f"--listen-address={addresses}",
        f"--server={config.dns.upstream}",
        "--log-facility=-",
        "--log-async=5",
    ]


def nft_filter(config: ProjectConfig) -> str:
    """Drop every packet that escaped local transparent-proxy delivery."""

    rules = [
        f"table inet {NFT_TABLE} {{",
        "  chain forward {",
        "    type filter hook forward priority filter; policy drop;",
        '    iifname "wg0" counter drop comment "uncaptured WireGuard traffic"',
        "    counter drop",
        "  }",
        "}",
    ]
    return "\n".join(rules) + "\n"


@dataclass
class GatewayRuntime:
    """Own and clean every mutable object in the gateway namespace."""

    config: ProjectConfig
    paths: InstancePaths
    runtime_dir: Path
    runner: Runner = field(default_factory=SubprocessRunner)
    sshuttle: subprocess.Popen[bytes] | None = None
    dnsmasq: subprocess.Popen[bytes] | None = None
    stopping: threading.Event = field(default_factory=threading.Event)

    def start(self) -> None:
        """Start all components or roll back completely."""

        self.runtime_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.runtime_dir.chmod(0o700)
        self.cleanup()
        self._write_status("starting")
        try:
            remote_python_check(self.config, self.runner)
            rules = nft_filter(self.config)
            self.runner.run(["nft", "--check", "--file", "-"], input_text=rules)
            self.runner.run(["nft", "--file", "-"], input_text=rules)
            self._setup_wireguard()
            self._setup_policy_routing()
            excluded = resolve_ssh_addresses(self.config)
            self._start_sshuttle(excluded)
            if self.config.dns.enabled:
                self.dnsmasq = subprocess.Popen(dnsmasq_arguments(self.config))
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
                raise RuntimeFailure("sshuttle exited unexpectedly")
            if self.dnsmasq is not None and self.dnsmasq.poll() is not None:
                raise RuntimeFailure("dnsmasq exited unexpectedly")

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

        for process in (self.dnsmasq, self.sshuttle):
            stop_process(process)
        self.dnsmasq = None
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
        status = self.runtime_dir / STATUS_FILE
        try:
            status.unlink(missing_ok=True)
        except Exception as exc:
            failures.append(exc)
        if failures:
            raise RuntimeFailure(
                "cleanup was incomplete; container namespace destruction is the final boundary"
            ) from failures[0]

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
        if self.config.dns.enabled and (self.dnsmasq is None or self.dnsmasq.poll() is not None):
            raise RuntimeFailure("dnsmasq is not running after startup")
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

    def _start_sshuttle(self, excluded: Sequence[str]) -> None:
        notify_path = self.runtime_dir / NOTIFY_FILE
        notify_path.unlink(missing_ok=True)
        notify_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            notify_socket.bind(str(notify_path))
            notify_socket.settimeout(0.25)
            environment = os.environ.copy()
            environment["NOTIFY_SOCKET"] = str(notify_path)
            self.sshuttle = subprocess.Popen(
                sshuttle_arguments(self.config, excluded), env=environment
            )
            deadline = time.monotonic() + self.config.backend.startup_timeout_seconds
            while time.monotonic() < deadline:
                if self.sshuttle.poll() is not None:
                    raise RuntimeFailure(
                        f"sshuttle exited during startup with status {self.sshuttle.returncode}"
                    )
                try:
                    message = notify_socket.recv(4096)
                except TimeoutError:
                    continue
                if b"READY=1" in message:
                    return
            raise RuntimeFailure(
                f"sshuttle did not become ready within {self.config.backend.startup_timeout_seconds}s"
            )
        finally:
            notify_socket.close()
            notify_path.unlink(missing_ok=True)

    def _write_status(self, state: str, ignore_errors: bool = False) -> None:
        value = {
            "schema_version": 1,
            "state": state,
            "sshuttle_pid": self.sshuttle.pid if self.sshuttle is not None else None,
            "dnsmasq_pid": self.dnsmasq.pid if self.dnsmasq is not None else None,
            "dns_enabled": self.config.dns.enabled,
        }
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
    """Container entrypoint for the long-running gateway."""

    config_path, paths, runtime_dir = runtime_paths()
    config = load_config(config_path)
    with locked_state_view(paths) as view:
        validate_launch_manifest(config, view.paths, view.generation)
        runtime = GatewayRuntime(config=config, paths=view.paths, runtime_dir=runtime_dir)
        signal.signal(signal.SIGTERM, runtime.request_stop)
        signal.signal(signal.SIGINT, runtime.request_stop)
        try:
            runtime.start()
            runtime.supervise()
            return 0
        finally:
            runtime.cleanup()


def read_runtime_status(runtime_dir: Path) -> dict[str, Any]:
    """Read and validate the bounded non-secret runtime state file."""

    path = runtime_dir / STATUS_FILE
    try:
        if path.stat().st_size > 64 * 1024:
            raise RuntimeFailure("runtime status file is unexpectedly large")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
        raise RuntimeFailure(f"runtime status is unavailable: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise RuntimeFailure("runtime status has an invalid format")
    return value


def healthcheck() -> int:
    """Return success only for a live ready gateway."""

    config_path, _paths, runtime_dir = runtime_paths()
    try:
        config = load_config(config_path)
        status = read_runtime_status(runtime_dir)
        if status.get("state") != "ready":
            return 1
        for key in ("sshuttle_pid", "dnsmasq_pid"):
            pid = status.get(key)
            if pid is None and key == "dnsmasq_pid" and not status.get("dns_enabled"):
                continue
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
    """Return operator status without private or preshared WireGuard keys."""

    config_path, paths, runtime_dir = runtime_paths()
    config = load_config(config_path)
    status = read_runtime_status(runtime_dir)
    peer_names: dict[str, str] = {}
    for peer in config.wireguard.peers:
        pair, _preshared = load_peer_keys(paths, peer.name)
        peer_names[pair.public] = peer.name
    dump = SubprocessRunner().run(["wg", "show", INTERFACE, "dump"]).stdout.splitlines()
    peers: list[dict[str, Any]] = []
    for line in dump[1:]:
        columns = line.split("\t")
        if len(columns) < 8:
            continue
        public_key = columns[0]
        peers.append(
            {
                "name": peer_names.get(public_key, "unknown"),
                "public_key": public_key,
                "endpoint": columns[2] or None,
                "allowed_ips": columns[3].split(",") if columns[3] else [],
                "latest_handshake": int(columns[4]),
                "received_bytes": int(columns[5]),
                "sent_bytes": int(columns[6]),
                "persistent_keepalive": int(columns[7]),
            }
        )
    return {
        **status,
        "health": "ok" if healthcheck() == 0 else "degraded",
        "wireguard_interface": INTERFACE,
        "peers": peers,
        "routes": [str(route) for route in effective_routes(config)],
    }


def doctor_checks(config: ProjectConfig, runner: Runner) -> list[str]:
    """Run reversible kernel checks in the disposable doctor namespace."""

    messages: list[str] = []
    interface = "sg-doctor0"
    try:
        runner.run(["ip", "link", "add", "dev", interface, "type", "wireguard"])
    finally:
        runner.run(["ip", "link", "del", "dev", interface], check=False)
    messages.append("kernel WireGuard: ok")

    checks = (
        (socket.AF_INET, 12001, [(socket.AF_INET, 8, False, "10.0.0.0", 0, 0)]),
        (socket.AF_INET6, 12002, [(socket.AF_INET6, 48, False, "fd00::", 0, 0)]),
    )
    for family, port, subnets in checks:
        rules = render_tproxy_table(
            port=port,
            dns_port=12003,
            name_servers=[],
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
    messages.append("native nftables IPv4/IPv6 TPROXY: ok")
    remote_python_check(config, runner)
    messages.append("SSH authentication and remote Python >= 3.9: ok")
    return messages
