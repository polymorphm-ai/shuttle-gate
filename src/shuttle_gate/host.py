"""Rootless host launcher and namespace lifecycle."""

from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
import pwd
import re
import shutil
import socket
import stat
import subprocess
import sys
import time
import zipfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from ipaddress import IPv6Address
from pathlib import Path
from typing import Any, NoReturn

from . import __version__
from .config import IPAddress, ProjectConfig, load_config
from .errors import (
    INSTANCE_ENV,
    LAUNCHER_ENV,
    ShuttleGateError,
    StateError,
    command_context,
    with_command_hint,
)
from .files import InstancePaths, atomic_write_bytes, ensure_private_directory, fsync_directory
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
OPERATOR_COMMANDS = frozenset(
    {
        "config",
        "doctor",
        "init",
        "keys",
        "peers",
        "phone-config",
        "ssh-key",
    }
)
LOGS_USAGE = "usage: ./shuttle-gate logs [--follow] [--timestamps] [--tail LINES|all]"
MAX_LOG_TAIL_LINES = 1_000_000
READY_POLL_SECONDS = 0.2
STOP_TIMEOUT_SECONDS = 30.0
TEMPORARY_SUFFIX_PATTERN = re.compile(r"^[a-z0-9_]{8}$")
DEFAULT_INSTANCE_PARTS = ("shuttle-gate", "default")


class HostError(ShuttleGateError):
    """A stable host-lifecycle error safe to show to the operator."""


@dataclass(frozen=True)
class RuntimePaths:
    """Private volatile paths for one canonical instance."""

    instance_id: str
    unit_name: str
    root: Path
    inputs: Path
    output: Path
    launch: Path
    bundle: Path


def default_instance_root() -> Path:
    """Return the canonical per-user default without creating it."""

    configured = os.environ.get("XDG_CONFIG_HOME")
    if configured and not configured.isprintable():
        raise HostError("XDG_CONFIG_HOME must contain only printable characters")
    if configured and Path(configured).is_absolute():
        base = Path(configured)
    else:
        home_value = os.environ.get("HOME")
        if home_value and not home_value.isprintable():
            raise HostError("HOME must contain only printable characters")
        if home_value:
            home = Path(home_value)
            if not home.is_absolute():
                raise HostError("HOME must be an absolute path")
        else:
            home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        base = home / ".config"
    try:
        return base.joinpath(*DEFAULT_INSTANCE_PARTS).resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise HostError("default instance path cannot be resolved") from exc


def _validate_root_separation(application: Path, instance: Path) -> None:
    """Keep immutable application resources outside mutable instance data."""

    if (
        instance == application
        or instance.is_relative_to(application)
        or application.is_relative_to(instance)
    ):
        raise HostError("instance and application directories must be separate and non-overlapping")


def _create_directory_parents(path: Path) -> None:
    """Create missing XDG parents privately and durably without changing existing modes."""

    missing: list[Path] = []
    current = path
    while True:
        try:
            info = current.stat(follow_symlinks=False)
        except FileNotFoundError:
            missing.append(current)
            parent = current.parent
            if parent == current:
                raise HostError("default instance has no existing directory ancestor") from None
            current = parent
            continue
        except OSError as exc:
            raise HostError("default instance parent cannot be inspected") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise HostError("default instance parent must be a directory")
        break
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            try:
                info = directory.stat(follow_symlinks=False)
            except OSError as exc:
                raise HostError("default instance parent cannot be inspected") from exc
            if not stat.S_ISDIR(info.st_mode):
                raise HostError("default instance parent must be a directory") from None
        except OSError as exc:
            raise HostError("default instance parent cannot be created") from exc
        fsync_directory(directory.parent)


def _create_default_instance(root: Path) -> None:
    """Create the known private default in retry-safe directory steps."""

    namespace = root.parent
    _create_directory_parents(namespace.parent)
    ensure_private_directory(namespace)
    fsync_directory(namespace.parent)
    ensure_private_directory(root)
    fsync_directory(namespace)


def resolve_instance_root(
    application_root: Path,
    requested: str | None,
    *,
    cwd: Path | None = None,
    create_default: bool = False,
) -> Path:
    """Resolve one dedicated instance directory without unsafe broad mounts."""

    application = application_root.resolve(strict=True)
    if not str(application).isprintable():
        raise HostError("application paths must contain only printable characters")
    base = Path.cwd() if cwd is None else cwd
    if requested is not None and (not requested or not requested.isprintable()):
        raise HostError("instance paths must contain only printable characters")
    candidate = default_instance_root() if requested is None else Path(requested)
    if not candidate.is_absolute():
        candidate = base / candidate
    if requested is None and create_default:
        prospective = candidate.resolve(strict=False)
        _validate_root_separation(application, prospective)
        _create_default_instance(prospective)
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        if requested is None:
            raise HostError(
                with_command_hint("default instance is not initialized", "init")
            ) from exc
        raise HostError("instance directory does not exist or cannot be resolved") from exc
    if not str(resolved).isprintable():
        raise HostError("instance paths must contain only printable characters")
    try:
        info = resolved.stat(follow_symlinks=False)
    except OSError as exc:
        raise HostError("instance directory cannot be inspected") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise HostError("instance path must resolve to a directory")
    home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    if resolved in {Path("/"), home}:
        raise HostError("refusing to use a broad system or home directory as an instance")
    _validate_root_separation(application, resolved)
    return resolved


def select_instance(
    application_root: Path,
    arguments: Sequence[str],
    *,
    cwd: Path | None = None,
) -> tuple[Path, list[str]]:
    """Parse the bounded global instance option before command dispatch."""

    values = list(arguments)
    requested: str | None = None
    if values and values[0] == "--instance":
        if len(values) < 2:
            raise HostError("--instance requires a directory path")
        requested = values[1]
        values = values[2:]
    elif values and values[0].startswith("--instance="):
        requested = values[0].partition("=")[2]
        if not requested:
            raise HostError("--instance requires a directory path")
        values = values[1:]
    if values and (values[0] == "--instance" or values[0].startswith("--instance=")):
        raise HostError("--instance may be specified only once")
    create_default = requested is None and values == ["init"]
    return (
        resolve_instance_root(
            application_root,
            requested,
            cwd=cwd,
            create_default=create_default,
        ),
        values,
    )


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


def runtime_paths(instance_root: Path) -> RuntimePaths:
    """Derive private XDG runtime paths and a collision-resistant unit name."""

    resolved = instance_root.resolve()
    instance_id = hashlib.sha256(os.fsencode(resolved)).hexdigest()[:20]
    xdg_value = os.environ.get("XDG_RUNTIME_DIR")
    if not xdg_value:
        raise HostError("XDG_RUNTIME_DIR is unavailable; a systemd user session is required")
    xdg = Path(xdg_value)
    if not xdg.is_absolute():
        raise HostError("XDG_RUNTIME_DIR must be an absolute path")
    if not str(xdg).isprintable():
        raise HostError("XDG_RUNTIME_DIR must contain only printable characters")
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
    instance_root: Path,
    command: Sequence[str],
    *,
    network_namespace: bool,
    instance_read_only: bool,
    application_root: Path,
    runtime: RuntimePaths | None = None,
) -> list[str]:
    """Build the auditable filesystem/process sandbox command."""

    if not command:
        raise ValueError("sandbox command must not be empty")
    instance_root = instance_root.resolve(strict=True)
    application = application_root.resolve(strict=True)
    _validate_root_separation(application, instance_root)
    mounts = [*_system_mounts(), *_python_mounts()]
    instance_mode = "--ro-bind" if instance_read_only else "--bind"
    if runtime is None:
        # Keep both roots at their host pathnames. Operator commands print paths
        # for the user, so artificial mount points would leak unusable names.
        mounts.extend([(application, application), (instance_root, instance_root)])
    else:
        mounts.extend(
            [
                (runtime.bundle, Path("/opt/shuttle-gate/application.pyz")),
                (runtime.launch, Path("/run/shuttle-gate/launch.json")),
                (instance_root / "config.yaml", Path("/config/config.yaml")),
                (instance_root / "secrets", Path("/secrets")),
                (instance_root / "state", Path("/state")),
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
        if runtime is None and source == instance_root and destination == instance_root:
            mode = instance_mode
        elif runtime is not None and destination == Path("/run/shuttle-gate/output"):
            mode = "--bind"
        arguments.extend([mode, str(source), str(destination)])

    if runtime is not None:
        lock = instance_root / "state" / ".state.lock"
        arguments.extend(["--bind", str(lock), "/state/.state.lock"])

    python_path = (
        "/opt/shuttle-gate/application.pyz" if runtime is not None else str(application / "src")
    )
    execution_root = "/workspace" if runtime is not None else str(instance_root)
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
            execution_root,
            "--setenv",
            LAUNCHER_ENV,
            str(application / "shuttle-gate"),
            "--setenv",
            INSTANCE_ENV,
            str(instance_root),
        ]
    )
    if runtime is None:
        arguments.extend(["--setenv", "SHUTTLE_GATE_APPLICATION_ROOT", str(application)])
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
    working_directory = str(instance_root) if runtime is None else "/"
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


def socket_claim_paths(paths: RuntimePaths, config: ProjectConfig) -> tuple[Path, ...]:
    """Derive stable shared lock files for every exact host UDP socket."""

    directory = paths.root.parent / "claims"
    claims = {
        directory
        / (
            hashlib.sha256(
                f"udp\0{address.version}\0{address.compressed}\0{config.wireguard.listen_port}".encode(
                    "ascii"
                )
            ).hexdigest()
            + ".lock"
        )
        for address in config.wireguard.bind_addresses
    }
    return tuple(sorted(claims, key=str))


def prepare_socket_claims(claims: Sequence[Path]) -> None:
    """Create and validate durable session-local socket claim files."""

    if not claims or len({claim.parent for claim in claims}) != 1:
        raise HostError("socket claim set is invalid")
    directory = claims[0].parent
    ensure_private_directory(directory)
    for claim in claims:
        try:
            descriptor = os.open(
                claim,
                os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
        except OSError as exc:
            raise HostError("cannot create a host UDP socket claim") from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise HostError("host UDP socket claim ownership or type is invalid")
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    fsync_directory(directory)


def claim_command(claims: Sequence[Path], inner: Sequence[str]) -> list[str]:
    """Wrap one runtime command with ordered lifetime socket claims."""

    if not claims or not inner:
        raise ValueError("claims and runtime command must not be empty")
    arguments = [sys.executable, "-P", "-m", "shuttle_gate.claim"]
    for claim in claims:
        arguments.extend(["--claim", str(claim)])
    arguments.extend(["--", *inner])
    return arguments


def systemd_run_command(
    unit_name: str,
    inner: Sequence[str],
    *,
    python_path: Path | None = None,
) -> list[str]:
    """Build one bounded transient user-service request."""

    arguments = [
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
    ]
    if python_path is not None:
        arguments.append(f"--setenv=PYTHONPATH={python_path}")
    arguments.extend(["--", *inner])
    return arguments


def _application_bundle(application_root: Path) -> bytes:
    """Build deterministic immutable zip import bytes from application source."""

    source_root = application_root / "src" / "shuttle_gate"
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
    return output.getvalue()


def _build_application_bundle(application_root: Path, destination: Path) -> None:
    """Atomically publish one deterministic application bundle."""

    atomic_write_bytes(destination, _application_bundle(application_root), 0o600)


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
                raise HostError(with_command_hint(f"gateway startup failed{detail}", "logs"))
        if _host_state(paths) in {"failed", "inactive"}:
            raise HostError(with_command_hint("gateway service stopped before readiness", "logs"))
        time.sleep(READY_POLL_SECONDS)
    _run([_command("systemctl"), "--user", "stop", "--", paths.unit_name])
    raise HostError("gateway did not become ready before the startup timeout")


def _check_host_bindings(config: ProjectConfig) -> None:
    result = _run([_command("ip"), "-json", "address", "show"], capture=True, check=True)
    try:
        links = json.loads(result.stdout)
        if not isinstance(links, list):
            raise TypeError
        assigned: set[str] = set()
        assigned_scoped: set[tuple[str, str]] = set()
        for link in links:
            if not isinstance(link, dict):
                raise TypeError
            interface = link.get("ifname")
            addresses = link.get("addr_info", [])
            if not isinstance(addresses, list):
                raise TypeError
            for item in addresses:
                if not isinstance(item, dict):
                    raise TypeError
                local = item.get("local")
                if not isinstance(local, str):
                    continue
                assigned.add(local)
                if isinstance(interface, str):
                    assigned_scoped.add((local, interface))
    except (json.JSONDecodeError, TypeError) as exc:
        raise HostError("cannot parse host interface addresses") from exc
    missing = [
        str(address)
        for address in config.wireguard.bind_addresses
        if not _host_binding_is_assigned(address, assigned, assigned_scoped)
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


def _bind_address_parts(address: IPAddress) -> tuple[str, str | None]:
    """Return the kernel address and optional interface scope for one bind."""

    if isinstance(address, IPv6Address):
        return str(IPv6Address(int(address))), address.scope_id
    return str(address), None


def _host_binding_is_assigned(
    address: IPAddress,
    assigned: set[str],
    assigned_scoped: set[tuple[str, str]],
) -> bool:
    host, scope = _bind_address_parts(address)
    if scope is None:
        return host in assigned
    return (host, scope) in assigned_scoped


def _socket_bind_target(
    address: IPAddress,
    port: int,
) -> tuple[str, int] | tuple[str, int, int, int]:
    """Build a Python socket target with a numeric IPv6 scope ID."""

    host, scope = _bind_address_parts(address)
    if not isinstance(address, IPv6Address):
        return host, port
    try:
        scope_id = socket.if_nametoindex(scope) if scope is not None else 0
    except OSError as exc:
        raise HostError(f"configured bind interface is unavailable: {scope}") from exc
    return host, port, 0, scope_id


def _check_host_socket_availability(config: ProjectConfig) -> None:
    """Probe every exact UDP tuple without permitting address reuse."""

    listeners: list[socket.socket] = []
    try:
        for address in config.wireguard.bind_addresses:
            family = socket.AF_INET if address.version == 4 else socket.AF_INET6
            listener = socket.socket(family, socket.SOCK_DGRAM)
            listeners.append(listener)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                listener.bind(_socket_bind_target(address, config.wireguard.listen_port))
            except OSError as exc:
                raise HostError(
                    f"configured host UDP socket is unavailable: {address}/{config.wireguard.listen_port}"
                ) from exc
    finally:
        for listener in listeners:
            listener.close()


@contextmanager
def lifecycle_lock(instance_root: Path) -> Iterator[None]:
    """Serialize lifecycle transitions for one instance."""

    state = instance_root / "state"
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


def _up(application_root: Path, instance_root: Path, arguments: Sequence[str]) -> int:
    if arguments:
        raise HostError("usage: ./shuttle-gate up")
    paths = runtime_paths(instance_root)
    instance = InstancePaths.from_root(instance_root)
    config = load_config(instance.config)
    for name in REQUIRED_RUNTIME_COMMANDS:
        _command(name)
    _check_user_manager()
    _check_host_bindings(config)

    with lifecycle_lock(instance_root):
        if _host_state(paths) in {"active", "activating"}:
            with locked_state_view(instance) as view:
                manifest = validate_launch_manifest(
                    config,
                    view.paths,
                    view.generation,
                    paths.launch,
                    paths.bundle,
                )
            current_digest = hashlib.sha256(_application_bundle(application_root)).hexdigest()
            if manifest.get("application_digest") != current_digest:
                raise StateError(
                    with_command_hint(
                        "application source differs from the active gateway",
                        "down",
                    )
                )
            launch_id = manifest.get("launch_id")
            if not isinstance(launch_id, str):
                raise StateError("launch manifest identifier is invalid")
            _wait_for_state(paths, launch_id, config.backend.startup_timeout_seconds + 15)
            print("shuttle-gate is ready")
            return 0

        _check_host_socket_availability(config)
        _remove_known_runtime_files(paths)
        _prepare_runtime_directories(paths)
        _build_application_bundle(application_root, paths.bundle)
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
            instance_root,
            inner,
            network_namespace=True,
            instance_read_only=True,
            application_root=application_root,
            runtime=paths,
        )
        claims = socket_claim_paths(paths, config)
        prepare_socket_claims(claims)
        service = systemd_run_command(
            paths.unit_name,
            claim_command(claims, pasta_command(sandbox, config)),
            python_path=paths.bundle,
        )
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


def _down(instance_root: Path, arguments: Sequence[str]) -> int:
    if arguments:
        raise HostError("usage: ./shuttle-gate down")
    paths = runtime_paths(instance_root)
    with lifecycle_lock(instance_root):
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


def _status(instance_root: Path, arguments: Sequence[str]) -> int:
    if list(arguments) not in ([], ["--json"]):
        raise HostError("usage: ./shuttle-gate status [--json]")
    paths = runtime_paths(instance_root)
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


def _logs(instance_root: Path, arguments: Sequence[str]) -> int:
    if list(arguments) in (["-h"], ["--help"]):
        print(LOGS_USAGE)
        return 0
    return _run(logs_command(runtime_paths(instance_root).unit_name, arguments)).returncode


def _operator(
    application_root: Path,
    instance_root: Path,
    arguments: Sequence[str],
) -> int:
    inner = [sys.executable, "-m", "shuttle_gate", *arguments]
    sandbox = bubblewrap_command(
        instance_root,
        inner,
        network_namespace=False,
        instance_read_only=False,
        application_root=application_root,
    )
    if arguments and arguments[0] == "doctor":
        config = load_config(instance_root / "config.yaml")
        for name in REQUIRED_RUNTIME_COMMANDS:
            _command(name)
        _check_user_manager()
        _check_host_bindings(config)
        sandbox = bubblewrap_command(
            instance_root,
            inner,
            network_namespace=True,
            instance_read_only=True,
            application_root=application_root,
        )
        sandbox = pasta_command(sandbox)
    return _run(sandbox).returncode


def _print_help() -> None:
    print(
        """usage: ./shuttle-gate [--instance PATH] COMMAND [OPTIONS]

Global options:
  --instance PATH         Override the private XDG default instance

Commands:
  init                    Create local configuration and protected directories
  doctor                  Check host, namespaces, kernel, SSH, and remote Python
  config validate         Validate config.yaml
  keys ...                Generate, rotate, or prune WireGuard peer state
  peers list              List configured peers and generated state
  ssh-key ...             Generate a dedicated key or print setup instructions
  phone-config NAME       Regenerate one peer's WireGuard configuration
  up                      Start the rootless gateway and wait until ready
  down                    Stop the gateway and destroy its namespaces
  status [--json]         Show gateway and peer status
  logs [OPTIONS]          Read gateway logs from the user journal
  version                 Print the project version
"""
    )


def main(application_root: Path, arguments: Sequence[str] | None = None) -> int:
    """Dispatch the public host command."""

    launcher = application_root.resolve() / "shuttle-gate"
    with command_context(launcher, None):
        values = list(sys.argv[1:] if arguments is None else arguments)
        if not values or values[0] in {"-h", "--help"}:
            _print_help()
            return 0
        if values == ["version"]:
            print(__version__)
            return 0
        instance_root, values = select_instance(application_root, values)
        with command_context(launcher, instance_root):
            if not values or values[0] in {"-h", "--help"}:
                _print_help()
                return 0
            command, rest = values[0], values[1:]
            if command == "up":
                return _up(application_root, instance_root, rest)
            if command == "down":
                return _down(instance_root, rest)
            if command == "status":
                return _status(instance_root, rest)
            if command == "logs":
                return _logs(instance_root, rest)
            if command == "version" and not rest:
                print(__version__)
                return 0
            if command not in OPERATOR_COMMANDS:
                raise HostError(with_command_hint(f"unknown command: {command}", "--help"))
            return _operator(application_root, instance_root, values)


def entrypoint(application_root: Path) -> None:
    """Convert stable application failures to concise CLI diagnostics."""

    try:
        raise SystemExit(main(application_root))
    except ShuttleGateError as exc:
        _fail(str(exc))
