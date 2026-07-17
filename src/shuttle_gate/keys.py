"""WireGuard and dedicated SSH key lifecycle."""

from __future__ import annotations

import base64
import binascii
import json
import os
import shlex
import shutil
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .config import PeerConfig, ProjectConfig
from .errors import StateError
from .files import (
    InstancePaths,
    atomic_write,
    atomic_write_json,
    ensure_private_directory,
    read_text_secret,
    require_regular_file,
    resolve_config_path,
)
from .render import phone_fingerprint, render_phone_config
from .runner import Runner

PRIVATE_KEY = "private.key"
PUBLIC_KEY = "public.key"
PRESHARED_KEY = "preshared.key"
PHONE_CONFIG = "phone.conf"
FINGERPRINT = "fingerprint.json"
KEYSCAN_SCRIPT = 'exec ssh-keyscan -p "$1" -- "$2" > "$3"'


@dataclass(frozen=True)
class KeyPair:
    """WireGuard public/private key pair."""

    private: str
    public: str


def _validate_wireguard_key(value: str, label: str) -> str:
    """Require WireGuard's canonical base64 encoding of exactly 32 bytes."""

    if not value or "\n" in value or "\r" in value:
        raise StateError(f"{label} must contain exactly one key")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise StateError(f"{label} is not valid base64") from exc
    if len(decoded) != 32 or len(value) != 44:
        raise StateError(f"{label} must encode exactly 32 bytes")
    return value


def _read_public_key(path: Path, label: str) -> str:
    require_regular_file(path, label)
    try:
        if path.stat().st_size > 4096:
            raise StateError(f"{label} is unexpectedly large")
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise StateError(f"cannot read {label}: {exc}") from exc
    return _validate_wireguard_key(value, label)


def _generate_key_pair(runner: Runner) -> KeyPair:
    private = _validate_wireguard_key(
        runner.run(["wg", "genkey"]).stdout.strip(),
        "generated WireGuard private key",
    )
    public = _validate_wireguard_key(
        runner.run(["wg", "pubkey"], input_text=private + "\n").stdout.strip(),
        "generated WireGuard public key",
    )
    return KeyPair(private=private, public=public)


def _generate_preshared_key(runner: Runner) -> str:
    return _validate_wireguard_key(
        runner.run(["wg", "genpsk"]).stdout.strip(),
        "generated WireGuard preshared key",
    )


def _key_pair_status(directory: Path) -> str:
    present = [(directory / name).exists() for name in (PRIVATE_KEY, PUBLIC_KEY)]
    if all(present):
        return "complete"
    if any(present):
        return "partial"
    return "missing"


def generate_missing_keys(
    config: ProjectConfig,
    paths: InstancePaths,
    runner: Runner,
    peer_name: str | None = None,
) -> list[str]:
    """Create missing server and declared peer keys without overwriting state."""

    ensure_private_directory(paths.state)
    created: list[str] = []
    server_status = _key_pair_status(paths.server_dir())
    if server_status == "partial":
        raise StateError("server key state is partial; rotate or repair it explicitly")
    if server_status == "missing":
        pair = _generate_key_pair(runner)
        atomic_write(paths.server_dir() / PRIVATE_KEY, pair.private + "\n", 0o600)
        atomic_write(paths.server_dir() / PUBLIC_KEY, pair.public + "\n", 0o644)
        created.append("server")

    selected = _selected_peers(config, peer_name)
    for peer in selected:
        directory = paths.peer_dir(peer.name)
        status = _peer_key_status(directory)
        if status == "partial":
            raise StateError(f"peer {peer.name} key state is partial; rotate it explicitly")
        if status == "missing":
            pair = _generate_key_pair(runner)
            preshared = _generate_preshared_key(runner)
            atomic_write(directory / PRIVATE_KEY, pair.private + "\n", 0o600)
            atomic_write(directory / PUBLIC_KEY, pair.public + "\n", 0o644)
            atomic_write(directory / PRESHARED_KEY, preshared + "\n", 0o600)
            created.append(peer.name)

    render_all_phone_configs(config, paths)
    return created


def _selected_peers(config: ProjectConfig, peer_name: str | None) -> tuple[PeerConfig, ...]:
    if peer_name is None:
        return config.wireguard.peers
    for peer in config.wireguard.peers:
        if peer.name == peer_name:
            return (peer,)
    raise StateError(f"peer is not declared in config.yaml: {peer_name}")


def _peer_key_status(directory: Path) -> str:
    present = [(directory / name).exists() for name in (PRIVATE_KEY, PUBLIC_KEY, PRESHARED_KEY)]
    if all(present):
        return "complete"
    if any(present):
        return "partial"
    return "missing"


def load_server_keys(paths: InstancePaths) -> KeyPair:
    """Load complete server state."""

    if _key_pair_status(paths.server_dir()) != "complete":
        raise StateError("server keys are missing; run './shuttle-gate keys generate'")
    return KeyPair(
        private=_validate_wireguard_key(
            read_text_secret(paths.server_dir() / PRIVATE_KEY, "server private key"),
            "server private key",
        ),
        public=_read_public_key(paths.server_dir() / PUBLIC_KEY, "server public key"),
    )


def load_peer_keys(paths: InstancePaths, name: str) -> tuple[KeyPair, str]:
    """Load complete state for one peer."""

    directory = paths.peer_dir(name)
    if _peer_key_status(directory) != "complete":
        raise StateError(f"keys for peer {name} are missing")
    pair = KeyPair(
        private=_validate_wireguard_key(
            read_text_secret(directory / PRIVATE_KEY, f"{name} private key"),
            f"{name} private key",
        ),
        public=_read_public_key(directory / PUBLIC_KEY, f"{name} public key"),
    )
    preshared = _validate_wireguard_key(
        read_text_secret(directory / PRESHARED_KEY, f"{name} preshared key"),
        f"{name} preshared key",
    )
    return pair, preshared


def render_all_phone_configs(config: ProjectConfig, paths: InstancePaths) -> None:
    """Render every declared peer config and fingerprint."""

    server = load_server_keys(paths)
    for peer in config.wireguard.peers:
        pair, preshared = load_peer_keys(paths, peer.name)
        rendered = render_phone_config(config, peer, server.public, pair.private, preshared)
        fingerprint = phone_fingerprint(config, peer, server.public, pair.public, preshared)
        atomic_write(paths.peer_dir(peer.name) / PHONE_CONFIG, rendered, 0o600)
        atomic_write_json(
            paths.peer_dir(peer.name) / FINGERPRINT,
            {"schema_version": 1, "fingerprint": fingerprint},
            0o600,
        )


def require_current_phone_configs(config: ProjectConfig, paths: InstancePaths) -> None:
    """Reject missing or stale phone configurations before startup."""

    server = load_server_keys(paths)
    for peer in config.wireguard.peers:
        pair, preshared = load_peer_keys(paths, peer.name)
        expected = phone_fingerprint(config, peer, server.public, pair.public, preshared)
        path = paths.peer_dir(peer.name) / FINGERPRINT
        try:
            if path.stat().st_size > 64 * 1024:
                raise StateError(f"phone config fingerprint for {peer.name} is unexpectedly large")
            value = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
            raise StateError(
                f"phone config for {peer.name} is missing; run phone-config {peer.name}"
            ) from exc
        if not isinstance(value, dict) or value.get("fingerprint") != expected:
            raise StateError(f"phone config for {peer.name} is stale; run phone-config {peer.name}")


def rotate_peer(config: ProjectConfig, paths: InstancePaths, runner: Runner, name: str) -> None:
    """Atomically replace one declared peer's keys."""

    peer = _selected_peers(config, name)[0]
    pair = _generate_key_pair(runner)
    preshared = _generate_preshared_key(runner)
    directory = paths.peer_dir(peer.name)
    # Update public material first.  Until the final private-key write and
    # fingerprint regeneration, startup detects stale phone state and fails
    # closed instead of accepting a mismatched partial rotation.
    atomic_write(directory / PUBLIC_KEY, pair.public + "\n", 0o644)
    atomic_write(directory / PRESHARED_KEY, preshared + "\n", 0o600)
    atomic_write(directory / PRIVATE_KEY, pair.private + "\n", 0o600)
    render_all_phone_configs(config, paths)


def rotate_server(config: ProjectConfig, paths: InstancePaths, runner: Runner) -> None:
    """Replace the server key and regenerate every peer config."""

    pair = _generate_key_pair(runner)
    atomic_write(paths.server_dir() / PUBLIC_KEY, pair.public + "\n", 0o644)
    atomic_write(paths.server_dir() / PRIVATE_KEY, pair.private + "\n", 0o600)
    render_all_phone_configs(config, paths)


def prune_orphaned_peers(config: ProjectConfig, paths: InstancePaths) -> list[str]:
    """Delete peer state not declared in the current configuration."""

    peers_root = paths.state / "peers"
    if not peers_root.exists():
        return []
    declared = {peer.name for peer in config.wireguard.peers}
    removed: list[str] = []
    for child in peers_root.iterdir():
        if child.name in declared:
            continue
        if child.is_symlink() or not child.is_dir():
            raise StateError(f"refusing to prune unexpected peer state: {child}")
        shutil.rmtree(child)
        removed.append(child.name)
    return sorted(removed)


def generate_ssh_key(
    config: ProjectConfig, paths: InstancePaths, runner: Runner, force: bool
) -> Path:
    """Generate a dedicated Ed25519 key without contacting the remote server."""

    identity = resolve_config_path(paths.config, config.ssh.identity_file)
    public = Path(str(identity) + ".pub")
    if (identity.exists() or public.exists()) and not force:
        raise StateError(f"SSH key already exists: {identity}")
    ensure_private_directory(identity.parent)
    with tempfile.TemporaryDirectory(prefix=".ssh-key.", dir=identity.parent) as temp_dir:
        temporary = Path(temp_dir) / "id_ed25519"
        runner.run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"shuttle-gate:{config.project}",
                "-f",
                str(temporary),
            ]
        )
        os.replace(temporary, identity)
        os.replace(Path(str(temporary) + ".pub"), public)
    identity.chmod(0o600)
    public.chmod(0o644)
    return identity


def ssh_setup_instructions(config: ProjectConfig, paths: InstancePaths) -> str:
    """Return commands for the user to execute and verify manually."""

    identity = resolve_config_path(paths.config, config.ssh.identity_file)
    public = Path(str(identity) + ".pub")
    if not public.is_file():
        raise StateError("SSH public key is missing; run './shuttle-gate ssh-key generate'")
    destination = f"{config.ssh.user}@{config.ssh.host}"
    copy_command = shlex.join(
        ["ssh-copy-id", "-i", str(public), "-p", str(config.ssh.port), "--", destination]
    )
    known_hosts = resolve_config_path(paths.config, config.ssh.known_hosts_file)
    scan_command = shlex.join(
        [
            "sh",
            "-c",
            KEYSCAN_SCRIPT,
            "shuttle-gate-keyscan",
            str(config.ssh.port),
            config.ssh.host,
            str(known_hosts),
        ]
    )
    return (
        "Run this command yourself to authorize the dedicated key:\n"
        f"  {copy_command}\n\n"
        "Then collect the host key (this does not authenticate it):\n"
        f"  {scan_command}\n"
        "Verify the resulting fingerprint through a separate trusted channel before using it.\n"
        "The toolkit never runs either command and never edits the remote server."
    )


def peer_rows(config: ProjectConfig, paths: InstancePaths) -> Iterable[tuple[str, str, str]]:
    """Yield peer name, key state, and phone-config state."""

    for peer in config.wireguard.peers:
        key_state = _peer_key_status(paths.peer_dir(peer.name))
        phone_state = (
            "present" if (paths.peer_dir(peer.name) / PHONE_CONFIG).is_file() else "missing"
        )
        yield peer.name, key_state, phone_state
