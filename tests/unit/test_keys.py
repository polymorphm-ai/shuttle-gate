from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from shuttle_gate.config import ProjectConfig
from shuttle_gate.errors import StateError
from shuttle_gate.files import InstancePaths, atomic_write
from shuttle_gate.keys import (
    FINGERPRINT,
    PHONE_CONFIG,
    generate_missing_keys,
    generate_ssh_key,
    load_peer_keys,
    load_server_keys,
    peer_rows,
    prune_orphaned_peers,
    require_current_phone_configs,
    rotate_peer,
    rotate_server,
    ssh_setup_instructions,
)

from .fakes import FakeRunner


def test_generate_missing_keys_creates_server_peers_and_phone_configs(
    config: ProjectConfig, instance: InstancePaths
) -> None:
    runner = FakeRunner()

    created = generate_missing_keys(config, instance, runner)

    assert created == ["server", "phone", "tablet"]
    assert (instance.server_dir() / "private.key").stat().st_mode & 0o777 == 0o600
    assert (instance.peer_dir("phone") / PHONE_CONFIG).stat().st_mode & 0o777 == 0o600
    assert "PrivateKey = " in (instance.peer_dir("phone") / PHONE_CONFIG).read_text()
    require_current_phone_configs(config, instance)


def test_generation_is_idempotent_and_detects_partial_state(
    config: ProjectConfig, instance: InstancePaths
) -> None:
    runner = FakeRunner()
    generate_missing_keys(config, instance, runner)

    assert generate_missing_keys(config, instance, runner) == []

    (instance.peer_dir("phone") / "preshared.key").unlink()
    with pytest.raises(StateError, match="partial"):
        generate_missing_keys(config, instance, runner)


def test_selected_peer_must_exist(config: ProjectConfig, instance: InstancePaths) -> None:
    with pytest.raises(StateError, match="not declared"):
        generate_missing_keys(config, instance, FakeRunner(), "missing")


def test_stale_fingerprint_is_rejected(config: ProjectConfig, instance: InstancePaths) -> None:
    generate_missing_keys(config, instance, FakeRunner())
    atomic_write(instance.peer_dir("phone") / FINGERPRINT, '{"fingerprint":"bad"}\n', 0o600)

    with pytest.raises(StateError, match="stale"):
        require_current_phone_configs(config, instance)


def test_peer_and_server_rotation_replace_public_material(
    config: ProjectConfig, instance: InstancePaths
) -> None:
    runner = FakeRunner()
    generate_missing_keys(config, instance, runner)
    peer_before = (instance.peer_dir("phone") / "public.key").read_text()
    server_before = (instance.server_dir() / "public.key").read_text()

    rotate_peer(config, instance, runner, "phone")
    rotate_server(config, instance, runner)

    assert (instance.peer_dir("phone") / "public.key").read_text() != peer_before
    assert (instance.server_dir() / "public.key").read_text() != server_before


def test_prune_removes_only_undeclared_directories(
    config: ProjectConfig, instance: InstancePaths
) -> None:
    generate_missing_keys(config, instance, FakeRunner())
    orphan = instance.peer_dir("old-phone")
    orphan.mkdir(mode=0o700)
    (orphan / "private.key").write_text("old", encoding="ascii")

    assert prune_orphaned_peers(config, instance) == ["old-phone"]
    assert instance.peer_dir("phone").is_dir()
    assert not orphan.exists()


def test_generate_ssh_key_and_print_only_manual_instruction(
    config: ProjectConfig, instance: InstancePaths
) -> None:
    (instance.secrets / "id_ed25519").unlink()
    identity = generate_ssh_key(config, instance, FakeRunner(), force=False)
    text = ssh_setup_instructions(config, instance)

    assert identity.stat().st_mode & 0o777 == 0o600
    assert "ssh-copy-id" in text
    assert "ssh-keyscan" in text
    assert "never runs" in text
    commands = [line.strip() for line in text.splitlines() if line.startswith("  ")]
    copy_arguments = shlex.split(commands[0])
    scan_arguments = shlex.split(commands[1])
    assert copy_arguments[-2:] == ["--", "tester@ssh.example.test"]
    assert scan_arguments[:4] == [
        "sh",
        "-c",
        'exec ssh-keyscan -p "$1" -- "$2" > "$3"',
        "shuttle-gate-keyscan",
    ]
    assert scan_arguments[4:6] == ["2222", "ssh.example.test"]
    assert "ssh.example.test" not in scan_arguments[2]
    with pytest.raises(StateError, match="already exists"):
        generate_ssh_key(config, instance, FakeRunner(), force=False)


def test_peer_rows_report_state(config: ProjectConfig, instance: InstancePaths) -> None:
    assert list(peer_rows(config, instance)) == [
        ("phone", "missing", "missing"),
        ("tablet", "missing", "missing"),
    ]
    generate_missing_keys(config, instance, FakeRunner())
    assert next(iter(peer_rows(config, instance))) == ("phone", "complete", "present")


def test_generation_rejects_partial_server_and_empty_tool_output(
    config: ProjectConfig,
    instance: InstancePaths,
) -> None:
    atomic_write(instance.server_dir() / "private.key", "private\n", 0o600)
    with pytest.raises(StateError, match="server key state is partial"):
        generate_missing_keys(config, instance, FakeRunner())

    (instance.server_dir() / "private.key").unlink()
    runner = FakeRunner()
    runner.results[("wg", "genkey")] = runner.run(["true"])
    with pytest.raises(StateError, match="exactly one key"):
        generate_missing_keys(config, instance, runner)


def test_loaders_and_fingerprint_require_complete_private_state(
    config: ProjectConfig,
    instance: InstancePaths,
) -> None:
    with pytest.raises(StateError, match="server keys are missing"):
        load_server_keys(instance)
    with pytest.raises(StateError, match="keys for peer phone are missing"):
        load_peer_keys(instance, "phone")

    generate_missing_keys(config, instance, FakeRunner())
    (instance.peer_dir("phone") / FINGERPRINT).unlink()
    with pytest.raises(StateError, match="phone config for phone is missing"):
        require_current_phone_configs(config, instance)


def test_prune_refuses_unexpected_state_and_handles_absent_root(
    config: ProjectConfig,
    instance: InstancePaths,
) -> None:
    assert prune_orphaned_peers(config, instance) == []
    peers = instance.state / "peers"
    peers.mkdir()
    unexpected = peers / "unexpected"
    unexpected.write_text("not a directory", encoding="utf-8")
    with pytest.raises(StateError, match="unexpected peer state"):
        prune_orphaned_peers(config, instance)


def test_ssh_key_force_replaces_existing_files_and_requires_public_key(
    config: ProjectConfig,
    instance: InstancePaths,
) -> None:
    identity = instance.secrets / "id_ed25519"
    public = Path(f"{identity}.pub")
    public.write_text("old public", encoding="ascii")

    generated = generate_ssh_key(config, instance, FakeRunner(), force=True)

    assert generated.read_text(encoding="ascii") == "ssh-private\n"
    assert public.read_text(encoding="ascii") == "ssh-ed25519 public\n"
    public.unlink()
    with pytest.raises(StateError, match="public key is missing"):
        ssh_setup_instructions(config, instance)
