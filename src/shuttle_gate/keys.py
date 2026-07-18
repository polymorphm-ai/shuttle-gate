"""WireGuard and dedicated SSH key lifecycle."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import shlex
import shutil
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from .config import PeerConfig, ProjectConfig
from .errors import StateError
from .files import (
    InstancePaths,
    atomic_write,
    atomic_write_json,
    ensure_private_directory,
    fsync_directory,
    read_text_secret,
    require_regular_file,
    resolve_config_path,
)
from .render import phone_fingerprint, render_phone_config
from .runner import Runner
from .state import mutate_state, read_state, state_lock, void_operation

PRIVATE_KEY = "private.key"
PUBLIC_KEY = "public.key"
PRESHARED_KEY = "preshared.key"
PHONE_CONFIG = "phone.conf"
FINGERPRINT = "fingerprint.json"
KEYSCAN_SCRIPT = 'exec ssh-keyscan -p "$1" -- "$2" > "$3"'
SSH_TRANSACTION_SCHEMA_VERSION = 1
SSH_TRANSACTION_PATTERN = re.compile(r"^[0-9a-f]{32}$")
MAX_SSH_KEY_BYTES = 64 * 1024
MAX_SSH_TRANSACTION_BYTES = 64 * 1024


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


def _generate_missing_keys(
    config: ProjectConfig,
    paths: InstancePaths,
    runner: Runner,
    selected: tuple[PeerConfig, ...],
) -> list[str]:
    """Create missing server and selected peer keys without overwriting state."""

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

    _validate_selected_keys(paths, selected)
    _render_phone_configs(config, paths, selected)
    return created


def generate_missing_keys(
    config: ProjectConfig,
    paths: InstancePaths,
    runner: Runner,
    peer_name: str | None = None,
) -> list[str]:
    """Generate selected missing keys and refresh only their phone configs."""

    selected = _selected_peers(config, peer_name)

    return mutate_state(
        paths,
        lambda snapshot: _generate_missing_keys(config, snapshot, runner, selected),
        lambda snapshot: _validate_phone_snapshot(config, snapshot, selected),
    )


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


def _load_server_keys(paths: InstancePaths) -> KeyPair:
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


def load_server_keys(paths: InstancePaths) -> KeyPair:
    """Load the server pair from one locked persistent-state generation."""

    return read_state(paths, _load_server_keys)


def _load_peer_keys(paths: InstancePaths, name: str) -> tuple[KeyPair, str]:
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


def load_peer_keys(paths: InstancePaths, name: str) -> tuple[KeyPair, str]:
    """Load one peer pair from one locked persistent-state generation."""

    return read_state(paths, lambda snapshot: _load_peer_keys(snapshot, name))


def _phone_artifacts(
    config: ProjectConfig,
    paths: InstancePaths,
    peer: PeerConfig,
    server: KeyPair,
) -> tuple[str, str]:
    """Render one peer config and its expected import fingerprint."""

    pair, preshared = _load_peer_keys(paths, peer.name)
    rendered = render_phone_config(config, peer, server.public, pair.private, preshared)
    fingerprint = phone_fingerprint(config, peer, server.public, pair.public, preshared)
    return rendered, fingerprint


def _render_phone_configs(
    config: ProjectConfig,
    paths: InstancePaths,
    peers: tuple[PeerConfig, ...],
) -> None:
    """Render exactly the selected peer configs inside a staged generation."""

    server = _load_server_keys(paths)
    for peer in peers:
        rendered, fingerprint = _phone_artifacts(config, paths, peer, server)
        atomic_write(paths.peer_dir(peer.name) / PHONE_CONFIG, rendered, 0o600)
        atomic_write_json(
            paths.peer_dir(peer.name) / FINGERPRINT,
            {"schema_version": 1, "fingerprint": fingerprint},
            0o600,
        )


def regenerate_phone_config(config: ProjectConfig, paths: InstancePaths, name: str) -> None:
    """Atomically regenerate only the requested peer configuration."""

    selected = _selected_peers(config, name)

    def render(snapshot: InstancePaths) -> None:
        _render_phone_configs(config, snapshot, selected)

    mutate_state(
        paths,
        render,
        lambda snapshot: _validate_phone_snapshot(config, snapshot, selected),
    )


def _require_current_phone_configs(config: ProjectConfig, paths: InstancePaths) -> None:
    """Reject missing or stale phone configurations in one generation."""

    _require_selected_phone_configs(config, paths, config.wireguard.peers)


def _require_selected_phone_configs(
    config: ProjectConfig,
    paths: InstancePaths,
    peers: tuple[PeerConfig, ...],
) -> None:
    """Require exact current artifacts for the selected peers."""

    server = _load_server_keys(paths)
    for peer in peers:
        expected_config, expected_fingerprint = _phone_artifacts(config, paths, peer, server)
        path = paths.peer_dir(peer.name) / FINGERPRINT
        try:
            info = path.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_size > 64 * 1024
            ):
                raise StateError(f"phone config fingerprint for {peer.name} is unexpectedly large")
            value = json.loads(path.read_text(encoding="utf-8"))
            actual_config = _read_phone_config(paths, peer.name)
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError, StateError) as exc:
            raise StateError(
                f"phone config for {peer.name} is missing or invalid; run phone-config {peer.name}"
            ) from exc
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != 1
            or value.get("fingerprint") != expected_fingerprint
            or actual_config != expected_config
        ):
            raise StateError(f"phone config for {peer.name} is stale; run phone-config {peer.name}")


def require_current_phone_configs(config: ProjectConfig, paths: InstancePaths) -> None:
    """Validate phone configurations in one locked generation."""

    read_state(paths, lambda snapshot: _require_current_phone_configs(config, snapshot))


def _validate_snapshot(config: ProjectConfig, paths: InstancePaths) -> None:
    _validate_selected_keys(paths, config.wireguard.peers)
    _require_current_phone_configs(config, paths)


def _validate_selected_keys(paths: InstancePaths, selected: tuple[PeerConfig, ...]) -> None:
    """Validate the server and exactly the selected peer keys."""

    _load_server_keys(paths)
    for peer in selected:
        _load_peer_keys(paths, peer.name)


def _validate_phone_snapshot(
    config: ProjectConfig,
    paths: InstancePaths,
    selected: tuple[PeerConfig, ...],
) -> None:
    """Validate exactly the keys and phone configs this operation selected."""

    _validate_selected_keys(paths, selected)
    _require_selected_phone_configs(config, paths, selected)


def rotate_peer(
    config: ProjectConfig,
    paths: InstancePaths,
    runner: Runner,
    name: str,
    operation_id: str,
) -> None:
    """Replace one peer in an atomically published generation."""

    selected = _selected_peers(config, name)

    def rotate(snapshot: InstancePaths) -> None:
        peer = selected[0]
        pair = _generate_key_pair(runner)
        preshared = _generate_preshared_key(runner)
        directory = snapshot.peer_dir(peer.name)
        atomic_write(directory / PUBLIC_KEY, pair.public + "\n", 0o644)
        atomic_write(directory / PRESHARED_KEY, preshared + "\n", 0o600)
        atomic_write(directory / PRIVATE_KEY, pair.private + "\n", 0o600)
        _render_phone_configs(config, snapshot, selected)

    mutate_state(
        paths,
        rotate,
        lambda snapshot: _validate_phone_snapshot(config, snapshot, selected),
        operation=void_operation(operation_id, f"keys.rotate-peer.{name}"),
    )


def rotate_server(
    config: ProjectConfig,
    paths: InstancePaths,
    runner: Runner,
    operation_id: str,
) -> None:
    """Replace the server key in a complete atomically published generation."""

    def rotate(snapshot: InstancePaths) -> None:
        pair = _generate_key_pair(runner)
        atomic_write(snapshot.server_dir() / PUBLIC_KEY, pair.public + "\n", 0o644)
        atomic_write(snapshot.server_dir() / PRIVATE_KEY, pair.private + "\n", 0o600)
        _render_phone_configs(config, snapshot, config.wireguard.peers)

    mutate_state(
        paths,
        rotate,
        lambda snapshot: _validate_snapshot(config, snapshot),
        operation=void_operation(operation_id, "keys.rotate-server"),
    )


def prune_orphaned_peers(config: ProjectConfig, paths: InstancePaths) -> list[str]:
    """Prune only inside a staged generation, then publish atomically."""

    def prune(snapshot: InstancePaths) -> list[str]:
        peers_root = snapshot.data_dir() / "peers"
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

    return mutate_state(
        paths,
        prune,
        lambda snapshot: _validate_available_keys(config, snapshot),
        publish_if=bool,
    )


def _validate_available_keys(config: ProjectConfig, paths: InstancePaths) -> None:
    """Validate the server and each provisioned declared peer without requiring all peers."""

    _load_server_keys(paths)
    for peer in config.wireguard.peers:
        status = _peer_key_status(paths.peer_dir(peer.name))
        if status == "missing":
            continue
        if status == "partial":
            raise StateError(f"peer {peer.name} key state is partial; rotate it explicitly")
        _load_peer_keys(paths, peer.name)


def generate_ssh_key(
    config: ProjectConfig,
    paths: InstancePaths,
    runner: Runner,
    force: bool,
    operation_id: str,
) -> Path:
    """Generate a recoverable dedicated key pair without remote access."""

    with state_lock(paths, exclusive=True, blocking=False):
        identity, public = _ssh_key_paths(config, paths)
        ensure_private_directory(identity.parent)
        recover_ssh_key_transaction(config, paths)
        operation_kind = "ssh-key.force" if force else "ssh-key.generate"
        void_operation(operation_id, operation_kind)
        if _ssh_operation_completed(paths, identity, public, operation_id, operation_kind):
            return identity
        if (_path_exists(identity) or _path_exists(public)) and not force:
            raise StateError(f"SSH key already exists: {identity}")

        transaction = os.urandom(16).hex()
        files = _ssh_transaction_files(identity, transaction)
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
                str(files.private_stage),
            ]
        )
        generated_public = Path(f"{files.private_stage}.pub")
        _require_bounded_regular(files.private_stage, "generated SSH private key")
        _require_bounded_regular(generated_public, "generated SSH public key")
        os.chmod(files.private_stage, 0o600, follow_symlinks=False)
        os.chmod(generated_public, 0o644, follow_symlinks=False)
        os.replace(generated_public, files.public_stage)
        _sync_regular_file(files.private_stage)
        _sync_regular_file(files.public_stage)
        fsync_directory(identity.parent)

        journal = _new_ssh_transaction(
            identity,
            public,
            files,
            operation_id,
            operation_kind,
        )
        atomic_write_json(_ssh_transaction_path(identity), journal, 0o600)
        _finish_ssh_key_transaction(identity, public, files, journal)
        _record_ssh_operation(paths, identity, public, journal)
        _remove_ssh_transaction(identity, files)
        return identity


@dataclass(frozen=True)
class _SshTransactionFiles:
    private_stage: Path
    public_stage: Path
    private_backup: Path
    public_backup: Path


def _ssh_key_paths(config: ProjectConfig, paths: InstancePaths) -> tuple[Path, Path]:
    identity = resolve_config_path(paths.config, config.ssh.identity_file)
    return identity, Path(f"{identity}.pub")


def _ssh_transaction_path(identity: Path) -> Path:
    return identity.parent / f".{identity.name}.transaction.json"


def _ssh_transaction_files(identity: Path, transaction: str) -> _SshTransactionFiles:
    prefix = identity.parent / f".{identity.name}.transaction-{transaction}"
    return _SshTransactionFiles(
        private_stage=Path(f"{prefix}.private.new"),
        public_stage=Path(f"{prefix}.public.new"),
        private_backup=Path(f"{prefix}.private.old"),
        public_backup=Path(f"{prefix}.public.old"),
    )


def _path_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _require_bounded_regular(path: Path, label: str) -> None:
    try:
        info = path.stat(follow_symlinks=False)
    except FileNotFoundError as exc:
        raise StateError(f"{label} is missing: {path}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise StateError(f"{label} must be a regular non-symlink file: {path}")
    if info.st_size == 0 or info.st_size > MAX_SSH_KEY_BYTES:
        raise StateError(f"{label} has an invalid size: {path}")


def _file_digest(path: Path, label: str) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise StateError(f"cannot read {label}: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_SSH_KEY_BYTES:
            raise StateError(f"{label} has an invalid size: {path}")
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            return sha256(source.read(MAX_SSH_KEY_BYTES + 1)).hexdigest()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _optional_digest(path: Path, label: str) -> str | None:
    return _file_digest(path, label) if _path_exists(path) else None


def _sync_regular_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _new_ssh_transaction(
    identity: Path,
    public: Path,
    files: _SshTransactionFiles,
    operation_id: str,
    operation_kind: str,
) -> dict[str, object]:
    transaction = files.private_stage.name.split(".transaction-", 1)[1].split(".", 1)[0]
    return {
        "schema_version": SSH_TRANSACTION_SCHEMA_VERSION,
        "transaction": transaction,
        "operation_id": operation_id,
        "operation_kind": operation_kind,
        "private_old_digest": _optional_digest(identity, "existing SSH private key"),
        "public_old_digest": _optional_digest(public, "existing SSH public key"),
        "private_new_digest": _file_digest(files.private_stage, "generated SSH private key"),
        "public_new_digest": _file_digest(files.public_stage, "generated SSH public key"),
    }


def _read_ssh_transaction(identity: Path) -> tuple[_SshTransactionFiles, dict[str, object]] | None:
    journal_path = _ssh_transaction_path(identity)
    try:
        info = journal_path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SSH_TRANSACTION_BYTES:
        raise StateError(f"invalid SSH key transaction journal: {journal_path}")
    try:
        value = json.loads(journal_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StateError(f"cannot read SSH key transaction journal: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != SSH_TRANSACTION_SCHEMA_VERSION:
        raise StateError(f"invalid SSH key transaction journal: {journal_path}")
    transaction = value.get("transaction")
    digest_keys = (
        "private_old_digest",
        "public_old_digest",
        "private_new_digest",
        "public_new_digest",
    )
    if not isinstance(transaction, str) or SSH_TRANSACTION_PATTERN.fullmatch(transaction) is None:
        raise StateError(f"invalid SSH key transaction identifier: {journal_path}")
    operation_id = value.get("operation_id")
    operation_kind = value.get("operation_kind")
    if not isinstance(operation_id, str) or not isinstance(operation_kind, str):
        raise StateError(f"invalid SSH key transaction operation: {journal_path}")
    void_operation(operation_id, operation_kind)
    for key in digest_keys:
        digest = value.get(key)
        if digest is not None and (
            not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise StateError(f"invalid SSH key transaction digest: {journal_path}")
    if value.get("private_new_digest") is None or value.get("public_new_digest") is None:
        raise StateError(f"incomplete SSH key transaction journal: {journal_path}")
    return _ssh_transaction_files(identity, transaction), value


def _matches_digest(path: Path, expected: object, label: str) -> bool:
    return (
        isinstance(expected, str) and _path_exists(path) and _file_digest(path, label) == expected
    )


def _replace_and_sync(source: Path, destination: Path) -> None:
    os.replace(source, destination)
    fsync_directory(destination.parent)


def _install_transaction_file(
    destination: Path,
    stage: Path,
    backup: Path,
    old_digest: object,
    new_digest: object,
    label: str,
) -> None:
    if _matches_digest(destination, new_digest, f"new {label}"):
        return
    if not _matches_digest(stage, new_digest, f"staged {label}"):
        raise StateError(f"cannot resume SSH key transaction: staged {label} is unavailable")
    if old_digest is None:
        if _path_exists(destination):
            raise StateError(f"cannot resume SSH key transaction: unexpected {label}")
    elif not _path_exists(backup):
        if not _matches_digest(destination, old_digest, f"old {label}"):
            raise StateError(f"cannot resume SSH key transaction: old {label} changed")
        _replace_and_sync(destination, backup)
    elif not _matches_digest(backup, old_digest, f"backed-up {label}"):
        raise StateError(f"cannot resume SSH key transaction: {label} backup changed")
    _replace_and_sync(stage, destination)


def _finish_ssh_key_transaction(
    identity: Path,
    public: Path,
    files: _SshTransactionFiles,
    journal: dict[str, object],
) -> None:
    _install_transaction_file(
        public,
        files.public_stage,
        files.public_backup,
        journal["public_old_digest"],
        journal["public_new_digest"],
        "SSH public key",
    )
    _install_transaction_file(
        identity,
        files.private_stage,
        files.private_backup,
        journal["private_old_digest"],
        journal["private_new_digest"],
        "SSH private key",
    )
    if not _matches_digest(identity, journal["private_new_digest"], "SSH private key") or not (
        _matches_digest(public, journal["public_new_digest"], "SSH public key")
    ):
        raise StateError("SSH key transaction could not be verified")
    os.chmod(identity, 0o600, follow_symlinks=False)
    os.chmod(public, 0o644, follow_symlinks=False)
    _sync_regular_file(identity)
    _sync_regular_file(public)


def _remove_ssh_transaction(identity: Path, files: _SshTransactionFiles) -> None:
    for obsolete in (
        files.private_stage,
        files.public_stage,
        files.private_backup,
        files.public_backup,
        _ssh_transaction_path(identity),
    ):
        obsolete.unlink(missing_ok=True)
    fsync_directory(identity.parent)


def _ssh_operation_path(paths: InstancePaths, operation_id: str) -> Path:
    digest = sha256(operation_id.encode("ascii")).hexdigest()
    return paths.state / "operations" / f"ssh-{digest}.json"


def _ssh_operation_completed(
    paths: InstancePaths,
    identity: Path,
    public: Path,
    operation_id: str,
    operation_kind: str,
) -> bool:
    path = _ssh_operation_path(paths, operation_id)
    try:
        info = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SSH_TRANSACTION_BYTES:
        raise StateError(f"invalid SSH operation receipt: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StateError(f"cannot read SSH operation receipt {path}: {exc}") from exc
    try:
        identity_value = identity.relative_to(paths.root).as_posix()
    except ValueError as exc:
        raise StateError(f"SSH identity is outside the instance: {identity}") from exc
    expected = {
        "schema_version": SSH_TRANSACTION_SCHEMA_VERSION,
        "operation_id": operation_id,
        "operation_kind": operation_kind,
        "identity": identity_value,
    }
    if not isinstance(value, dict) or any(value.get(key) != item for key, item in expected.items()):
        raise StateError(f"operation ID was already used for another request: {operation_id}")
    private_digest = value.get("private_digest")
    public_digest = value.get("public_digest")
    if not isinstance(private_digest, str) or not isinstance(public_digest, str):
        raise StateError(f"invalid SSH operation receipt: {path}")
    if not _matches_digest(identity, private_digest, "recorded SSH private key") or not (
        _matches_digest(public, public_digest, "recorded SSH public key")
    ):
        raise StateError(f"completed SSH operation was superseded or changed: {operation_id}")
    return True


def _record_ssh_operation(
    paths: InstancePaths,
    identity: Path,
    public: Path,
    journal: dict[str, object],
) -> None:
    operation_id = journal["operation_id"]
    operation_kind = journal["operation_kind"]
    if not isinstance(operation_id, str) or not isinstance(operation_kind, str):
        raise StateError("SSH key transaction operation is invalid")
    if _ssh_operation_completed(paths, identity, public, operation_id, operation_kind):
        return
    private_digest = journal["private_new_digest"]
    public_digest = journal["public_new_digest"]
    if not isinstance(private_digest, str) or not isinstance(public_digest, str):
        raise StateError("SSH key transaction digests are invalid")
    try:
        identity_value = identity.relative_to(paths.root).as_posix()
    except ValueError as exc:
        raise StateError(f"SSH identity is outside the instance: {identity}") from exc
    atomic_write_json(
        _ssh_operation_path(paths, operation_id),
        {
            "schema_version": SSH_TRANSACTION_SCHEMA_VERSION,
            "operation_id": operation_id,
            "operation_kind": operation_kind,
            "identity": identity_value,
            "private_digest": private_digest,
            "public_digest": public_digest,
        },
        0o600,
    )


def recover_ssh_key_transaction(config: ProjectConfig, paths: InstancePaths) -> None:
    """Finish an interrupted SSH-key replacement while holding the instance lock."""

    identity, public = _ssh_key_paths(config, paths)
    transaction = _read_ssh_transaction(identity)
    if transaction is not None:
        files, journal = transaction
        _finish_ssh_key_transaction(identity, public, files, journal)
        _record_ssh_operation(paths, identity, public, journal)
        _remove_ssh_transaction(identity, files)
    _clean_orphaned_ssh_transaction_files(identity)


def _clean_orphaned_ssh_transaction_files(identity: Path) -> None:
    """Remove pre-journal files left by an interrupted ssh-keygen call."""

    if not identity.parent.is_dir():
        return
    transaction_prefix = f".{identity.name}.transaction-"
    journal_temporary_prefix = f".{_ssh_transaction_path(identity).name}."
    for child in identity.parent.iterdir():
        if not (
            child.name.startswith(transaction_prefix)
            or child.name.startswith(journal_temporary_prefix)
        ):
            continue
        try:
            info = child.lstat()
            if stat.S_ISDIR(info.st_mode):
                raise StateError(f"unexpected SSH transaction directory: {child}")
            child.unlink()
        except FileNotFoundError:
            continue
    fsync_directory(identity.parent)


def require_no_ssh_key_transaction(config: ProjectConfig, paths: InstancePaths) -> None:
    """Reject an incomplete SSH-key update from a read-only operation."""

    identity, _public = _ssh_key_paths(config, paths)
    if _path_exists(_ssh_transaction_path(identity)):
        raise StateError(
            "SSH key update was interrupted; rerun ssh-key generate or config validate"
        )


def read_phone_config(paths: InstancePaths, name: str) -> str:
    """Read one bounded phone configuration from a stable generation."""

    return read_state(paths, lambda snapshot: _read_phone_config(snapshot, name))


def _read_phone_config(paths: InstancePaths, name: str) -> str:
    """Read one private phone configuration from an already locked snapshot."""

    path = paths.peer_dir(name) / PHONE_CONFIG
    try:
        info = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) & 0o077
            or info.st_size > 64 * 1024
        ):
            raise StateError(f"invalid phone configuration: {path}")
        return path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, UnicodeError) as exc:
        raise StateError(f"cannot read phone configuration for {name}: {exc}") from exc


def ssh_setup_instructions(config: ProjectConfig, paths: InstancePaths) -> str:
    """Return commands for the user to execute and verify manually."""

    with state_lock(paths, exclusive=True, blocking=False):
        recover_ssh_key_transaction(config, paths)
        _identity, public = _ssh_key_paths(config, paths)
        try:
            _require_bounded_regular(public, "SSH public key")
        except StateError as exc:
            raise StateError(
                "SSH public key is missing or invalid; run './shuttle-gate ssh-key generate'"
            ) from exc
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


def _peer_rows(config: ProjectConfig, paths: InstancePaths) -> tuple[tuple[str, str, str], ...]:
    rows: list[tuple[str, str, str]] = []
    for peer in config.wireguard.peers:
        key_state = _peer_key_status(paths.peer_dir(peer.name))
        phone = paths.peer_dir(peer.name) / PHONE_CONFIG
        fingerprint = paths.peer_dir(peer.name) / FINGERPRINT
        if not phone.is_file() or not fingerprint.is_file():
            phone_state = "missing"
        else:
            try:
                _require_selected_phone_configs(config, paths, (peer,))
            except StateError:
                phone_state = "stale"
            else:
                phone_state = "current"
        rows.append((peer.name, key_state, phone_state))
    return tuple(rows)


def peer_rows(config: ProjectConfig, paths: InstancePaths) -> Iterable[tuple[str, str, str]]:
    """Yield peer name, key state, and phone-config state."""

    return read_state(paths, lambda snapshot: _peer_rows(config, snapshot), required=False)
