"""Rootless host launcher and namespace lifecycle."""

from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import zipfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from .config import ProjectConfig, load_config
from .errors import ShuttleGateError, StateError
from .files import InstancePaths, atomic_write_bytes, ensure_private_directory
from .launch import prepare_launch, validate_launch_manifest
from .state import locked_state_view

STATUS_FILE = "status.json"
LIFECYCLE_LOCK = ".lifecycle.lock"
APP_BUNDLE = "application.pyz"
LAUNCH_FILE = "launch.json"
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
REQUIRED_RUNTIME_COMMANDS = (
    "bwrap",
    "ip",
    "journalctl",
    "nft",
    "pasta",
    "ssh",
    "ssh-keygen",
    "systemctl",
    "systemd-run",
    "wg",
)
LOGS_USAGE = "usage: ./shuttle-gate logs [--follow] [--timestamps] [--tail LINES|all]"
MAX_LOG_TAIL_LINES = 1_000_000
READY_POLL_SECONDS = 0.2
STOP_TIMEOUT_SECONDS = 30.0
TEMPORARY_SUFFIX_PATTERN = re.compile(r"^[a-z0-9_]{8}$")


class HostError(ShuttleGateError):
    """A stable host-lifecycle error safe to show to the operator."""


@dataclass(frozen=True)
class RuntimePaths:
    """Private volatile paths for one checkout."""

    instance_id: str
    unit_name: str
    root: Path
    inputs: Path
    output: Path
    launch: Path
    bundle: Path


def _fail(message: str, exit_code: int = 2) -> NoReturn:
    print(f"shuttle-gate error: {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def _command(name: str) -> str:
    value = shutil.which(name)
    if value is None:
        raise HostError(f"required command was not found: {name}")
    # Preserve argv[0] symlink names: the passt multi-call binary selects
    # pasta mode from that name and would become passt if resolved here.
    return str(Path(value).absolute())


def _run(
    command: Sequence[str],
    *,
    capture: bool = False,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run one structured host command without shell parsing."""

    if not command:
        raise ValueError("command must not be empty")
    environment = {"PATH": SYSTEM_PATH, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    for name in ("DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    try:
        completed = subprocess.run(
            list(command),
            check=False,
            text=True,
            capture_output=capture,
            env=environment,
        )
    except OSError as exc:
        raise HostError(f"cannot execute {command[0]}: {exc}") from exc
    if check and completed.returncode != 0:
        diagnostic = (completed.stderr or completed.stdout).strip()[:4096]
        suffix = f": {diagnostic}" if diagnostic else ""
        raise HostError(
            f"{Path(command[0]).name} failed with status {completed.returncode}{suffix}"
        )
    return completed


def runtime_paths(root: Path) -> RuntimePaths:
    """Derive private XDG runtime paths and a collision-resistant unit name."""

    resolved = root.resolve()
    instance_id = hashlib.sha256(os.fsencode(resolved)).hexdigest()[:20]
    xdg_value = os.environ.get("XDG_RUNTIME_DIR")
    if not xdg_value:
        raise HostError("XDG_RUNTIME_DIR is unavailable; a systemd user session is required")
    xdg = Path(xdg_value)
    if not xdg.is_absolute():
        raise HostError("XDG_RUNTIME_DIR must be an absolute path")
    base = xdg / "shuttle-gate" / instance_id
    return RuntimePaths(
        instance_id=instance_id,
        unit_name=f"shuttle-gate-{instance_id}.service",
        root=base,
        inputs=base / "inputs",
        output=base / "output",
        launch=base / "inputs" / LAUNCH_FILE,
        bundle=base / "inputs" / APP_BUNDLE,
    )


def _prepare_runtime_directories(paths: RuntimePaths) -> None:
    ensure_private_directory(paths.root.parent)
    ensure_private_directory(paths.root)
    ensure_private_directory(paths.inputs)
    ensure_private_directory(paths.output)


def _add_parent_directories(arguments: list[str], destinations: set[Path]) -> None:
    parents: set[Path] = set()
    for destination in destinations:
        current = destination.parent
        while current != Path("/"):
            parents.add(current)
            current = current.parent
    for parent in sorted(parents, key=lambda item: (len(item.parts), str(item))):
        arguments.extend(["--dir", str(parent)])


def _system_mounts() -> list[tuple[Path, Path]]:
    mounts: list[tuple[Path, Path]] = []
    for value in ("/usr", "/bin", "/sbin", "/lib", "/lib64"):
        source = Path(value)
        if source.exists():
            mounts.append((source, source))
    for value in (
        "/etc/gai.conf",
        "/etc/group",
        "/etc/hosts",
        "/etc/localtime",
        "/etc/nsswitch.conf",
        "/etc/passwd",
    ):
        source = Path(value)
        if source.exists():
            mounts.append((source, source))
    # A stub resolver on host loopback is unreachable from a private network
    # namespace. Prefer systemd-resolved's uplink file when available; otherwise
    # preserve the host resolver file at the conventional sandbox destination.
    uplink_resolver = Path("/run/systemd/resolve/resolv.conf")
    resolver = uplink_resolver if uplink_resolver.is_file() else Path("/etc/resolv.conf")
    if resolver.exists():
        mounts.append((resolver.resolve(strict=True), Path("/etc/resolv.conf")))
    return mounts


def _python_mounts() -> list[tuple[Path, Path]]:
    mounts: list[tuple[Path, Path]] = []
    # Preserve uv's stable managed-Python alias: environment interpreters use
    # that absolute path as their symlink target, while resolve() would mount
    # only the versioned target and leave the alias absent in the sandbox.
    roots = {Path(sys.prefix), Path(sys.base_prefix)}
    interpreter = Path(sys.prefix) / "bin" / "python"
    if interpreter.is_symlink():
        target = Path(os.readlink(interpreter))
        if target.is_absolute() and len(target.parents) >= 2:
            roots.add(target.parents[1])
    for source in sorted(roots, key=str):
        try:
            source.relative_to("/usr")
        except ValueError:
            mounts.append((source, source))
    return mounts


def bubblewrap_command(
    root: Path,
    command: Sequence[str],
    *,
    network_namespace: bool,
    project_read_only: bool,
    runtime: RuntimePaths | None = None,
) -> list[str]:
    """Build the auditable filesystem/process sandbox command."""

    if not command:
        raise ValueError("sandbox command must not be empty")
    mounts = [*_system_mounts(), *_python_mounts()]
    project_mode = "--ro-bind" if project_read_only else "--bind"
    if runtime is None:
        mounts.append((root.resolve(), Path("/workspace")))
    else:
        mounts.extend(
            [
                (runtime.bundle, Path("/opt/shuttle-gate/application.pyz")),
                (runtime.launch, Path("/run/shuttle-gate/launch.json")),
                (root / "config.yaml", Path("/config/config.yaml")),
                (root / "secrets", Path("/secrets")),
                (root / "state", Path("/state")),
                (runtime.output, Path("/run/shuttle-gate/output")),
            ]
        )

    arguments = [_command("bwrap")]
    if runtime is None and not network_namespace:
        arguments.extend(["--unshare-user", "--uid", "0", "--gid", "0"])
    arguments.extend(["--unshare-pid", "--unshare-ipc", "--unshare-uts"])
    if not network_namespace:
        arguments.append("--unshare-net")
    arguments.extend(
        [
            "--hostname",
            "shuttle-gate",
            "--new-session",
            "--die-with-parent",
            "--cap-drop",
            "ALL",
        ]
    )
    if network_namespace:
        arguments.extend(["--cap-add", "CAP_NET_ADMIN"])
    arguments.extend(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"])
    if runtime is None:
        arguments.extend(["--tmpfs", "/run"])

    destinations = {destination for _source, destination in mounts}
    destinations.add(Path("/tmp/home"))
    if runtime is not None:
        destinations.update(
            {
                Path("/config/config.yaml"),
                Path("/opt/shuttle-gate/application.pyz"),
                Path("/run/shuttle-gate/launch.json"),
                Path("/run/shuttle-gate/output"),
            }
        )
    _add_parent_directories(arguments, destinations)
    arguments.extend(["--dir", "/tmp/home"])

    for source, destination in mounts:
        mode = "--ro-bind"
        if destination == Path("/workspace"):
            mode = project_mode
        elif runtime is not None and destination == Path("/run/shuttle-gate/output"):
            mode = "--bind"
        arguments.extend([mode, str(source), str(destination)])

    if runtime is not None:
        lock = root / "state" / ".state.lock"
        arguments.extend(["--bind", str(lock), "/state/.state.lock"])

    python_path = "/opt/shuttle-gate/application.pyz" if runtime is not None else "/workspace/src"
    arguments.extend(
        [
            "--clearenv",
            "--setenv",
            "HOME",
            "/tmp/home",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "LC_ALL",
            "C.UTF-8",
            "--setenv",
            "PATH",
            SYSTEM_PATH,
            "--setenv",
            "PYTHONDONTWRITEBYTECODE",
            "1",
            "--setenv",
            "PYTHONPATH",
            python_path,
            "--setenv",
            "SHUTTLE_GATE_ROOT",
            "/workspace",
        ]
    )
    if runtime is not None:
        arguments.extend(
            [
                "--setenv",
                "SHUTTLE_GATE_CONFIG",
                "/config/config.yaml",
                "--setenv",
                "SHUTTLE_GATE_STATE",
                "/state",
                "--setenv",
                "SHUTTLE_GATE_RUNTIME",
                "/run/shuttle-gate/output",
                "--setenv",
                "SHUTTLE_GATE_LAUNCH",
                "/run/shuttle-gate/launch.json",
                "--setenv",
                "SHUTTLE_GATE_BUNDLE",
                "/opt/shuttle-gate/application.pyz",
            ]
        )
    working_directory = "/workspace" if runtime is None else "/"
    arguments.extend(["--chdir", working_directory, "--", *command])
    return arguments


def pasta_command(inner: Sequence[str], config: ProjectConfig | None = None) -> list[str]:
    """Build a foreground pasta command with no implicit port exposure."""

    arguments = [
        _command("pasta"),
        "--quiet",
        "--foreground",
        "--tcp-ports",
        "none",
        "--tcp-ns",
        "none",
        "--udp-ns",
        "none",
        "--dns",
        "none",
        "--search",
        "none",
        "--no-map-gw",
        "--config-net",
    ]
    if config is None:
        arguments.extend(["--udp-ports", "none"])
    else:
        for address in config.wireguard.bind_addresses:
            arguments.extend(["--udp-ports", f"{address}/{config.wireguard.listen_port}"])
    arguments.extend(["--", *inner])
    return arguments


def systemd_run_command(unit_name: str, inner: Sequence[str]) -> list[str]:
    """Build one bounded transient user-service request."""

    return [
        _command("systemd-run"),
        "--user",
        f"--unit={unit_name}",
        "--collect",
        "--service-type=exec",
        "--expand-environment=no",
        "--property=KillMode=control-group",
        "--property=LimitNOFILE=65536",
        "--property=NoNewPrivileges=yes",
        "--property=TasksMax=256",
        "--property=TimeoutStopSec=20s",
        "--property=UMask=0077",
        "--property=Restart=no",
        "--property=RestartForceExitStatus=75",
        "--property=RestartSec=5s",
        "--property=StartLimitIntervalSec=60s",
        "--property=StartLimitBurst=3",
        "--description=Rootless shuttle-gate gateway",
        "--",
        *inner,
    ]


def _build_application_bundle(root: Path, destination: Path) -> None:
    """Create a deterministic immutable zip import bundle from tracked source."""

    source_root = root / "src" / "shuttle_gate"
    files = sorted(source_root.rglob("*.py"))
    if source_root / "__main__.py" not in files:
        raise HostError("application source is incomplete")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for source in files:
            info = source.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise HostError(f"application source must be a regular file: {source}")
            relative = source.relative_to(source_root)
            entry = zipfile.ZipInfo(
                str(Path("shuttle_gate") / relative),
                date_time=(1980, 1, 1, 0, 0, 0),
            )
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100444 << 16
            archive.writestr(entry, source.read_bytes())
    atomic_write_bytes(destination, output.getvalue(), 0o600)


def _host_state(paths: RuntimePaths) -> str:
    result = _run(
        [
            _command("systemctl"),
            "--user",
            "show",
            "--property=ActiveState",
            "--value",
            "--",
            paths.unit_name,
        ],
        capture=True,
    )
    if result.returncode != 0:
        return "inactive"
    value = result.stdout.strip()
    return value if value else "inactive"


def _check_user_manager() -> None:
    """Require a reachable user manager without rejecting unrelated failures."""

    result = _run(
        [_command("systemctl"), "--user", "is-system-running"],
        capture=True,
    )
    state = result.stdout.strip()
    if state not in {"running", "degraded"}:
        detail = (result.stderr or result.stdout).strip()[:4096]
        suffix = f": {detail}" if detail else ""
        raise HostError(f"systemd user manager is not ready{suffix}")


def _read_status(paths: RuntimePaths) -> dict[str, Any] | None:
    path = paths.output / STATUS_FILE
    try:
        info = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 64 * 1024:
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError:
        return None
    if not isinstance(value, dict) or value.get("schema_version") != 2:
        return None
    return value


def _wait_for_state(paths: RuntimePaths, launch_id: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = _read_status(paths)
        if status is not None and status.get("launch_id") == launch_id:
            if status.get("state") == "ready":
                return
            if status.get("state") == "failed":
                error = status.get("error")
                detail = f": {error}" if isinstance(error, str) and error else ""
                raise HostError(f"gateway startup failed{detail}; inspect './shuttle-gate logs'")
        if _host_state(paths) in {"failed", "inactive"}:
            raise HostError(
                "gateway service stopped before readiness; inspect './shuttle-gate logs'"
            )
        time.sleep(READY_POLL_SECONDS)
    _run([_command("systemctl"), "--user", "stop", "--", paths.unit_name])
    raise HostError("gateway did not become ready before the startup timeout")


def _check_host_bindings(config: ProjectConfig) -> None:
    result = _run([_command("ip"), "-json", "address", "show"], capture=True, check=True)
    try:
        links = json.loads(result.stdout)
        assigned = {
            item["local"]
            for link in links
            for item in link.get("addr_info", [])
            if isinstance(item, dict) and isinstance(item.get("local"), str)
        }
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise HostError("cannot parse host interface addresses") from exc
    missing = [
        str(address) for address in config.wireguard.bind_addresses if str(address) not in assigned
    ]
    if missing:
        raise HostError(
            "configured bind addresses are not assigned on the host: " + ", ".join(missing)
        )
    try:
        threshold = int(
            Path("/proc/sys/net/ipv4/ip_unprivileged_port_start")
            .read_text(encoding="ascii")
            .strip()
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise HostError("cannot determine the host unprivileged-port boundary") from exc
    if config.wireguard.listen_port < threshold:
        raise HostError(
            f"WireGuard port {config.wireguard.listen_port} is below the host unprivileged-port boundary {threshold}"
        )


@contextmanager
def lifecycle_lock(root: Path) -> Iterator[None]:
    """Serialize lifecycle transitions for one checkout."""

    state = root / "state"
    ensure_private_directory(state)
    lock_path = state / LIFECYCLE_LOCK
    try:
        descriptor = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except OSError as exc:
        raise HostError(f"cannot open lifecycle lock {lock_path}: {exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise HostError(f"lifecycle lock must be a regular file: {lock_path}")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise HostError("another up or down operation is already running") from exc
        yield
    finally:
        with suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        with suppress(OSError):
            os.close(descriptor)


def _up(root: Path, arguments: Sequence[str]) -> int:
    if arguments:
        raise HostError("usage: ./shuttle-gate up")
    paths = runtime_paths(root)
    instance = InstancePaths.from_root(root)
    config = load_config(instance.config)
    for name in REQUIRED_RUNTIME_COMMANDS:
        _command(name)
    _check_user_manager()
    _check_host_bindings(config)

    with lifecycle_lock(root):
        if _host_state(paths) in {"active", "activating"}:
            with locked_state_view(instance) as view:
                manifest = validate_launch_manifest(
                    config,
                    view.paths,
                    view.generation,
                    paths.launch,
                    paths.bundle,
                )
            launch_id = manifest.get("launch_id")
            if not isinstance(launch_id, str):
                raise StateError("launch manifest identifier is invalid")
            _wait_for_state(paths, launch_id, config.backend.startup_timeout_seconds + 15)
            print("shuttle-gate is ready")
            return 0

        _remove_known_runtime_files(paths)
        _prepare_runtime_directories(paths)
        _build_application_bundle(root, paths.bundle)
        manifest = prepare_launch(
            config,
            instance,
            paths.launch,
            paths.bundle,
            instance_id=paths.instance_id,
            unit_name=paths.unit_name,
        )
        inner = [sys.executable, "-m", "shuttle_gate", "runtime"]
        sandbox = bubblewrap_command(
            root,
            inner,
            network_namespace=True,
            project_read_only=True,
            runtime=paths,
        )
        service = systemd_run_command(paths.unit_name, pasta_command(sandbox, config))
        _run(service, check=True)
        launch_id = manifest["launch_id"]
        if not isinstance(launch_id, str):
            raise StateError("prepared launch identifier is invalid")
        _wait_for_state(paths, launch_id, config.backend.startup_timeout_seconds + 15)
        print("shuttle-gate is ready")
        return 0


def _remove_known_runtime_files(paths: RuntimePaths) -> None:
    allowed = {
        paths.inputs: {LAUNCH_FILE, APP_BUNDLE},
        paths.output: {STATUS_FILE, "wireguard.conf", "sshuttle-notify.sock"},
    }
    for directory, names in allowed.items():
        if not directory.exists():
            continue
        if directory.is_symlink() or not directory.is_dir():
            raise HostError(f"refusing to remove invalid runtime directory: {directory}")
        for child in directory.iterdir():
            temporary = any(
                child.name.startswith(f".{name}.")
                and TEMPORARY_SUFFIX_PATTERN.fullmatch(child.name.removeprefix(f".{name}."))
                is not None
                for name in names
            )
            if (child.name not in names and not temporary) or child.is_dir():
                raise HostError(f"refusing to remove unexpected runtime object: {child}")
            child.unlink(missing_ok=True)
        try:
            directory.rmdir()
        except OSError as exc:
            raise HostError(f"cannot remove runtime directory {directory}: {exc}") from exc
    if paths.root.exists():
        try:
            paths.root.rmdir()
        except OSError as exc:
            raise HostError(
                f"refusing to remove non-empty runtime directory: {paths.root}"
            ) from exc
    with suppress(OSError):
        paths.root.parent.rmdir()


def _down(root: Path, arguments: Sequence[str]) -> int:
    if arguments:
        raise HostError("usage: ./shuttle-gate down")
    paths = runtime_paths(root)
    with lifecycle_lock(root):
        result = _run(
            [_command("systemctl"), "--user", "stop", "--", paths.unit_name],
            capture=True,
        )
        if result.returncode not in {0, 5}:
            raise HostError("failed to stop the gateway service")
        deadline = time.monotonic() + STOP_TIMEOUT_SECONDS
        while _host_state(paths) not in {"inactive", "failed"}:
            if time.monotonic() >= deadline:
                raise HostError("gateway service did not stop within 30 seconds")
            time.sleep(READY_POLL_SECONDS)
        _remove_known_runtime_files(paths)
    print("shuttle-gate is stopped")
    return 0


def _status(root: Path, arguments: Sequence[str]) -> int:
    if list(arguments) not in ([], ["--json"]):
        raise HostError("usage: ./shuttle-gate status [--json]")
    paths = runtime_paths(root)
    service_state = _host_state(paths)
    status = _read_status(paths) or {"schema_version": 2, "state": "stopped"}
    value = {**status, "service_state": service_state}
    if arguments == ["--json"]:
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    else:
        print(f"state: {value['state']}")
        print(f"service: {service_state}")
        if value.get("state") == "ready":
            print(f"interface: {value.get('wireguard_interface', 'wg0')}")
            print("routes: " + ", ".join(value.get("routes", [])))
            for peer in value.get("peers", []):
                if isinstance(peer, dict):
                    print(
                        f"peer {peer.get('name', 'unknown')}: "
                        f"handshake={peer.get('latest_handshake', 0)} "
                        f"rx={peer.get('received_bytes', 0)} tx={peer.get('sent_bytes', 0)}"
                    )
        elif isinstance(value.get("error"), str):
            print(f"error: {value['error']}")
    return 0 if value.get("state") == "ready" and service_state == "active" else 1


def _validated_tail(value: str) -> str:
    if value == "all":
        return value
    if not value.isascii() or not value.isdecimal():
        raise HostError(LOGS_USAGE)
    if len(value) > len(str(MAX_LOG_TAIL_LINES)) or int(value) > MAX_LOG_TAIL_LINES:
        raise HostError(f"log tail exceeds {MAX_LOG_TAIL_LINES} lines")
    return value


def logs_command(unit_name: str, arguments: Sequence[str]) -> list[str]:
    """Map a small public log interface to fixed journalctl operands."""

    follow = False
    timestamps = False
    tail: str | None = None
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in {"-f", "--follow"}:
            follow = True
        elif argument == "--timestamps":
            timestamps = True
        elif argument in {"-n", "--tail"}:
            index += 1
            if index >= len(arguments):
                raise HostError(LOGS_USAGE)
            tail = _validated_tail(arguments[index])
        elif argument.startswith("--tail="):
            tail = _validated_tail(argument.removeprefix("--tail="))
        else:
            raise HostError(LOGS_USAGE)
        index += 1
    command = [
        _command("journalctl"),
        "--user",
        "--unit",
        unit_name,
        "--no-pager",
        "--output",
        "short-iso-precise" if timestamps else "cat",
    ]
    if tail == "all":
        if follow:
            command.append("--no-tail")
    elif tail is not None:
        command.extend(["--lines", tail])
    elif follow:
        command.extend(["--lines", "10"])
    if follow:
        command.append("--follow")
    return command


def _logs(root: Path, arguments: Sequence[str]) -> int:
    if list(arguments) in (["-h"], ["--help"]):
        print(LOGS_USAGE)
        return 0
    return _run(logs_command(runtime_paths(root).unit_name, arguments)).returncode


def _operator(root: Path, arguments: Sequence[str]) -> int:
    inner = [sys.executable, "-m", "shuttle_gate", *arguments]
    sandbox = bubblewrap_command(
        root,
        inner,
        network_namespace=False,
        project_read_only=False,
    )
    if arguments and arguments[0] == "doctor":
        config = load_config(root / "config.yaml")
        for name in REQUIRED_RUNTIME_COMMANDS:
            _command(name)
        _check_user_manager()
        _check_host_bindings(config)
        sandbox = bubblewrap_command(
            root,
            inner,
            network_namespace=True,
            project_read_only=True,
        )
        sandbox = pasta_command(sandbox, config)
    return _run(sandbox).returncode


def _print_help() -> None:
    print(
        """usage: ./shuttle-gate COMMAND [OPTIONS]

Commands:
  init                    Create local configuration and protected directories
  doctor                  Check host, namespaces, kernel, SSH, and remote Python
  config validate         Validate config.yaml
  keys ...                Generate, rotate, or prune WireGuard keys
  peers list              List configured peers and generated state
  ssh-key ...             Generate a dedicated key or print setup instructions
  phone-config NAME       Generate one mobile WireGuard configuration
  up                      Start the rootless gateway and wait until ready
  down                    Stop the gateway and destroy its namespaces
  status [--json]         Show gateway and peer status
  logs [OPTIONS]          Read gateway logs from the user journal
  version                 Print the project version
"""
    )


def main(root: Path, arguments: Sequence[str] | None = None) -> int:
    """Dispatch the public host command."""

    values = list(sys.argv[1:] if arguments is None else arguments)
    if not values or values[0] in {"-h", "--help"}:
        _print_help()
        return 0
    command, rest = values[0], values[1:]
    if command == "up":
        return _up(root, rest)
    if command == "down":
        return _down(root, rest)
    if command == "status":
        return _status(root, rest)
    if command == "logs":
        return _logs(root, rest)
    return _operator(root, values)


def entrypoint(root: Path) -> None:
    """Convert stable application failures to concise CLI diagnostics."""

    try:
        raise SystemExit(main(root))
    except ShuttleGateError as exc:
        _fail(str(exc))
