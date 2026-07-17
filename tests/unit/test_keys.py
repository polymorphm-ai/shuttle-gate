from __future__ import annotations

import shlex
import shutil
from pathlib import Path

import pytest

import shuttle_gate.keys as keys_module
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


def test_legacy_key_layout_is_migrated_without_regeneration(
    config: ProjectConfig, instance: InstancePaths
) -> None:
    initial_runner = FakeRunner()
    generate_missing_keys(config, instance, initial_runner)
    public_before = (instance.server_dir() / "public.key").read_text(encoding="ascii")
    shutil.copytree(instance.server_dir(), instance.state / "server")
    shutil.copytree(instance.data_dir() / "peers", instance.state / "peers")
    (instance.state / "current").unlink()
    shutil.rmtree(instance.state / "generations")

    with pytest.raises(StateError, match="requires migration"):
        load_server_keys(instance)
    migration_runner = FakeRunner()
    assert generate_missing_keys(config, instance, migration_runner) == []

    assert (instance.server_dir() / "public.key").read_text(encoding="ascii") == public_before
    assert not (instance.state / "server").exists()
    assert not (instance.state / "peers").exists()
    assert not migration_runner.calls


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

    rotate_peer(config, instance, runner, "phone", "rotate-phone-1")
    rotate_server(config, instance, runner, "rotate-server-1")

    assert (instance.peer_dir("phone") / "public.key").read_text() != peer_before
    assert (instance.server_dir() / "public.key").read_text() != server_before


def test_rotation_operation_id_prevents_duplicate_key_changes(
    config: ProjectConfig, instance: InstancePaths
) -> None:
    runner = FakeRunner()
    generate_missing_keys(config, instance, runner)

    rotate_peer(config, instance, runner, "phone", "stable-request")
    public_after_first = (instance.peer_dir("phone") / "public.key").read_text()
    calls_after_first = len(runner.calls)
    rotate_peer(config, instance, runner, "phone", "stable-request")

    assert (instance.peer_dir("phone") / "public.key").read_text() == public_after_first
    assert len(runner.calls) == calls_after_first
    with pytest.raises(StateError, match="already used"):
        rotate_server(config, instance, runner, "stable-request")


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
    identity = generate_ssh_key(
        config, instance, FakeRunner(), force=False, operation_id="ssh-generate-1"
    )
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
    assert copy_arguments[2] == str(instance.secrets / "id_ed25519.pub")
    assert scan_arguments[6] == str(instance.secrets / "known_hosts")
    assert "ssh.example.test" not in scan_arguments[2]
    with pytest.raises(StateError, match="already exists"):
        generate_ssh_key(config, instance, FakeRunner(), force=False, operation_id="ssh-generate-2")
    atomic_write(identity, "externally changed\n", 0o600)
    with pytest.raises(StateError, match="superseded or changed"):
        generate_ssh_key(config, instance, FakeRunner(), force=False, operation_id="ssh-generate-1")


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
    generate_missing_keys(config, instance, FakeRunner())
    (instance.server_dir() / "public.key").unlink()
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
    with pytest.raises(StateError, match="persistent keys are not initialized"):
        load_server_keys(instance)
    with pytest.raises(StateError, match="persistent keys are not initialized"):
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
    generate_missing_keys(config, instance, FakeRunner())
    peers = instance.data_dir() / "peers"
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

    generated = generate_ssh_key(
        config, instance, FakeRunner(), force=True, operation_id="ssh-force-1"
    )

    assert generated.read_text(encoding="ascii") == "ssh-private\n"
    assert public.read_text(encoding="ascii") == "ssh-ed25519 public\n"
    public.unlink()
    with pytest.raises(StateError, match="public key is missing"):
        ssh_setup_instructions(config, instance)


@pytest.mark.parametrize("failed_replace", [1, 2, 3, 4])
def test_ssh_key_replacement_recovers_every_rename_boundary(
    config: ProjectConfig,
    instance: InstancePaths,
    monkeypatch: pytest.MonkeyPatch,
    failed_replace: int,
) -> None:
    identity = instance.secrets / "id_ed25519"
    public = Path(f"{identity}.pub")
    public.write_text("old public\n", encoding="ascii")
    runner = FakeRunner()
    real_replace = keys_module._replace_and_sync
    calls = 0

    def interrupt(source: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == failed_replace:
            raise OSError("interrupted key replacement")
        real_replace(source, destination)

    monkeypatch.setattr(keys_module, "_replace_and_sync", interrupt)
    with pytest.raises(OSError, match="interrupted key replacement"):
        generate_ssh_key(
            config,
            instance,
            runner,
            force=True,
            operation_id=f"recover-rename-{failed_replace}",
        )

    monkeypatch.setattr(keys_module, "_replace_and_sync", real_replace)
    generate_ssh_key(
        config,
        instance,
        runner,
        force=True,
        operation_id=f"recover-rename-{failed_replace}",
    )

    assert identity.read_text(encoding="ascii") == "ssh-private\n"
    assert public.read_text(encoding="ascii") == "ssh-ed25519 public\n"
    assert sum(call[0][0] == "ssh-keygen" for call in runner.calls) == 1
    assert not list(instance.secrets.glob(".id_ed25519.transaction*"))


def test_ssh_key_retry_after_install_does_not_generate_again(
    config: ProjectConfig,
    instance: InstancePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = instance.secrets / "id_ed25519"
    Path(f"{identity}.pub").write_text("old public\n", encoding="ascii")
    runner = FakeRunner()
    real_record = keys_module._record_ssh_operation
    failed = False

    def interrupt(
        paths: InstancePaths,
        private_path: Path,
        public_path: Path,
        journal: dict[str, object],
    ) -> None:
        nonlocal failed
        if not failed:
            failed = True
            raise OSError("interrupted after key install")
        real_record(paths, private_path, public_path, journal)

    monkeypatch.setattr(keys_module, "_record_ssh_operation", interrupt)
    with pytest.raises(OSError, match="after key install"):
        generate_ssh_key(
            config,
            instance,
            runner,
            force=True,
            operation_id="recover-after-install",
        )

    generate_ssh_key(
        config,
        instance,
        runner,
        force=True,
        operation_id="recover-after-install",
    )
    assert sum(call[0][0] == "ssh-keygen" for call in runner.calls) == 1
