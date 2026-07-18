from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from shuttle_gate.config import ProjectConfig
from shuttle_gate.errors import ConfigurationError, StateError
from shuttle_gate.files import (
    InstancePaths,
    atomic_write,
    atomic_write_json,
    ensure_private_directory,
    mounted_secret_path,
    read_text_secret,
    require_private_file,
    require_regular_file,
    resolve_config_path,
    resolve_export_path,
    secret_relative_path,
    validate_ssh_files,
)

from .conftest import config_data


def test_atomic_write_sets_mode_and_replaces_content(tmp_path: Path) -> None:
    path = tmp_path / "private" / "value"
    atomic_write(path, "first\n", 0o600)
    atomic_write(path, "second\n", 0o600)

    assert path.read_text(encoding="utf-8") == "second\n"
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700


def test_atomic_json_is_deterministic(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    atomic_write_json(path, {"b": 2, "a": 1})

    assert json.loads(path.read_text(encoding="utf-8")) == {"a": 1, "b": 2}
    assert path.read_text(encoding="utf-8").index('"a"') < path.read_text().index('"b"')


def test_private_directory_rejects_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(StateError, match="symlink"):
        ensure_private_directory(link)


def test_private_file_rejects_group_access_and_multiline(tmp_path: Path) -> None:
    path = tmp_path / "key"
    path.write_text("secret\n", encoding="ascii")
    path.chmod(0o640)
    with pytest.raises(ConfigurationError, match="permissions"):
        require_private_file(path, "key")

    path.chmod(0o600)
    path.write_text("one\ntwo\n", encoding="ascii")
    with pytest.raises(StateError, match="one non-empty line"):
        read_text_secret(path, "key")


def test_secret_paths_are_instance_relative_and_context_mounted() -> None:
    assert secret_relative_path(Path("secrets/keys/id")) == Path("keys/id")
    paths = InstancePaths.from_root(Path("/instance"))
    assert mounted_secret_path(paths, Path("secrets/keys/id")) == Path("/instance/secrets/keys/id")
    with pytest.raises(ConfigurationError):
        secret_relative_path(Path("/tmp/id"))
    with pytest.raises(ConfigurationError):
        secret_relative_path(Path("other/id"))


def test_export_paths_are_explicitly_instance_local(tmp_path: Path) -> None:
    paths = InstancePaths.from_root(tmp_path)

    assert resolve_export_path(paths, Path("exports/phone.conf")) == tmp_path / "exports/phone.conf"
    invalid_paths = (
        Path("phone.conf"),
        Path("exports/line\nbreak.conf"),
        Path("exports/.."),
        Path("exports/nested/phone.conf"),
        tmp_path / "phone.conf",
    )
    for invalid in invalid_paths:
        with pytest.raises(ConfigurationError, match="exports/FILE"):
            resolve_export_path(paths, invalid)

    (tmp_path / "exports").symlink_to(tmp_path / "elsewhere", target_is_directory=True)
    with pytest.raises(ConfigurationError, match="symbolic"):
        resolve_export_path(paths, Path("exports/phone.conf"))


def test_resolve_config_path_uses_document_directory(tmp_path: Path) -> None:
    assert (
        resolve_config_path(tmp_path / "config.yaml", Path("secrets/id"))
        == (tmp_path / "secrets/id").resolve()
    )


def test_file_validators_reject_missing_directories_and_symlinks(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(ConfigurationError, match="does not exist"):
        require_private_file(missing, "private")
    with pytest.raises(ConfigurationError, match="does not exist"):
        require_regular_file(missing, "regular")

    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(ConfigurationError, match="regular"):
        require_private_file(directory, "private")
    with pytest.raises(ConfigurationError, match="regular"):
        require_regular_file(directory, "regular")

    target = tmp_path / "target"
    target.write_text("value", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ConfigurationError, match="non-symlink"):
        require_regular_file(link, "regular")


def test_validate_ssh_files_accepts_public_known_hosts_permissions(tmp_path: Path) -> None:
    data = config_data()
    config = ProjectConfig.model_validate(data)
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    identity = secrets / "id_ed25519"
    identity.write_text("private", encoding="ascii")
    identity.chmod(0o600)
    known_hosts = secrets / "known_hosts"
    known_hosts.write_text("host key", encoding="ascii")
    known_hosts.chmod(0o644)

    paths = InstancePaths.from_root(tmp_path)
    assert validate_ssh_files(config, paths) == (identity, known_hosts)


def test_validate_ssh_files_rejects_intermediate_symlink_escape(tmp_path: Path) -> None:
    config = ProjectConfig.model_validate(config_data())
    outside = tmp_path / "outside"
    outside.mkdir()
    identity = outside / "id_ed25519"
    identity.write_text("private", encoding="ascii")
    identity.chmod(0o600)
    (outside / "known_hosts").write_text("host key", encoding="ascii")
    (tmp_path / "secrets").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ConfigurationError, match="resolve below"):
        validate_ssh_files(config, InstancePaths.from_root(tmp_path))


def test_atomic_write_removes_temporary_file_after_replace_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "private" / "value"

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        atomic_write(destination, "value", 0o600)

    assert not destination.exists()
    assert list(destination.parent.iterdir()) == []


def test_atomic_write_syncs_the_parent_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    synced: list[Path] = []
    monkeypatch.setattr("shuttle_gate.files.fsync_directory", synced.append)

    atomic_write(tmp_path / "private/value", "value", 0o600)

    assert synced == [tmp_path / "private"]


def test_read_secret_reports_decode_failure(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.write_bytes(b"\xff")
    secret.chmod(0o600)
    with pytest.raises(StateError, match="cannot read"):
        read_text_secret(secret, "secret")
