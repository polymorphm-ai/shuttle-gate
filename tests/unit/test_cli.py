from __future__ import annotations

import json
import shlex
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

import shuttle_gate.cli as cli
from shuttle_gate.errors import INSTANCE_ENV, LAUNCHER_ENV, ShuttleGateError
from shuttle_gate.files import InstancePaths

from .conftest import config_data
from .fakes import FakeRunner

RUNNER = CliRunner()


def _select_roots(
    monkeypatch: pytest.MonkeyPatch,
    instance_root: Path,
    application_root: Path | None = None,
) -> None:
    application = application_root or instance_root.with_name(f".{instance_root.name}-application")
    monkeypatch.setenv("SHUTTLE_GATE_ROOT", str(instance_root))
    monkeypatch.setenv("SHUTTLE_GATE_APPLICATION_ROOT", str(application))
    monkeypatch.setenv(LAUNCHER_ENV, str(application / "shuttle-gate"))
    monkeypatch.setenv(INSTANCE_ENV, str(instance_root))


def _fake_commands(monkeypatch: pytest.MonkeyPatch, fake: FakeRunner) -> None:
    monkeypatch.setattr(cli, "SubprocessRunner", lambda: fake)


def test_instance_paths_require_launcher_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SHUTTLE_GATE_ROOT", raising=False)

    with pytest.raises(ShuttleGateError, match=r"use the \./shuttle-gate launcher"):
        cli.instance_paths()

    monkeypatch.setenv("SHUTTLE_GATE_ROOT", "/instance")
    monkeypatch.delenv("SHUTTLE_GATE_APPLICATION_ROOT", raising=False)
    with pytest.raises(ShuttleGateError, match=r"use the \./shuttle-gate launcher"):
        cli.application_root()


def test_init_creates_private_local_layout_and_refuses_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application = tmp_path / "application"
    instance = tmp_path / "instance"
    application.mkdir()
    instance.mkdir()
    _select_roots(monkeypatch, instance, application)
    (application / "config.example.yaml").write_text(
        yaml.safe_dump(config_data()),
        encoding="utf-8",
    )

    result = RUNNER.invoke(cli.app, ["init"])

    assert result.exit_code == 0
    assert (instance / "config.yaml").stat().st_mode & 0o777 == 0o600
    assert (instance / "secrets").stat().st_mode & 0o777 == 0o700
    repeated = RUNNER.invoke(cli.app, ["init"])
    assert repeated.exit_code == 2
    assert "refusing to overwrite" in repeated.output


def test_separate_unusual_instance_uses_application_template_and_prints_host_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application = tmp_path / "application source"
    instance = tmp_path / "  -instance $ ' \" ; 🚀"
    application.mkdir()
    instance.mkdir()
    monkeypatch.setenv("SHUTTLE_GATE_APPLICATION_ROOT", str(application))
    monkeypatch.setenv("SHUTTLE_GATE_ROOT", str(instance))
    (application / "config.example.yaml").write_text(
        yaml.safe_dump(config_data()),
        encoding="utf-8",
    )

    initialized = RUNNER.invoke(cli.app, ["init"])

    assert initialized.exit_code == 0
    assert f"created {instance / 'config.yaml'}" in initialized.output
    public = instance / "secrets/id_ed25519.pub"
    public.write_text("ssh-ed25519 public\n", encoding="ascii")
    instructions = RUNNER.invoke(cli.app, ["ssh-key", "instructions"])
    assert instructions.exit_code == 0
    commands = [line.strip() for line in instructions.output.splitlines() if line.startswith("  ")]
    assert shlex.split(commands[0])[2] == str(public)
    assert shlex.split(commands[1])[-1] == str(instance / "secrets/known_hosts")


def test_config_keys_peers_and_phone_workflow(
    instance: InstancePaths,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _select_roots(monkeypatch, instance.root)
    fake = FakeRunner()
    _fake_commands(monkeypatch, fake)

    assert RUNNER.invoke(cli.app, ["config", "validate"]).exit_code == 0
    generated = RUNNER.invoke(cli.app, ["keys", "generate"])
    assert generated.exit_code == 0
    assert "server, phone, tablet" in generated.output
    assert RUNNER.invoke(cli.app, ["keys", "generate"]).exit_code == 0

    peers = RUNNER.invoke(cli.app, ["peers", "list"])
    assert "phone\tkeys=complete\tphone-config=current" in peers.output
    phone = RUNNER.invoke(cli.app, ["phone-config", "phone", "--stdout"])
    assert phone.exit_code == 0
    assert "[Interface]" in phone.output

    destination = instance.root / "exports" / "phone.conf"
    exported = RUNNER.invoke(
        cli.app,
        ["phone-config", "phone", "--output", "exports/phone.conf"],
    )
    assert exported.exit_code == 0
    assert destination.stat().st_mode & 0o777 == 0o600
    assert destination.parent.stat().st_mode & 0o777 == 0o700
    assert RUNNER.invoke(cli.app, ["phone-config", "missing"]).exit_code == 2
    mutually_exclusive = RUNNER.invoke(
        cli.app,
        ["phone-config", "phone", "--output", "exports/phone.conf", "--stdout"],
    )
    assert mutually_exclusive.exit_code == 2


def test_rotation_and_pruning_commands(
    instance: InstancePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _select_roots(monkeypatch, instance.root)
    fake = FakeRunner()
    _fake_commands(monkeypatch, fake)
    assert RUNNER.invoke(cli.app, ["keys", "generate"]).exit_code == 0

    assert RUNNER.invoke(cli.app, ["keys", "rotate-peer", "phone", "--yes"]).exit_code == 0
    assert RUNNER.invoke(cli.app, ["keys", "rotate-server", "--yes"]).exit_code == 0
    orphan = instance.peer_dir("old")
    orphan.mkdir(mode=0o700)
    assert RUNNER.invoke(cli.app, ["keys", "prune", "--yes"]).exit_code == 0
    assert not orphan.exists()


def test_ssh_key_commands_only_generate_locally_and_print_manual_steps(
    instance: InstancePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _select_roots(monkeypatch, instance.root)
    fake = FakeRunner()
    _fake_commands(monkeypatch, fake)
    (instance.secrets / "id_ed25519").unlink()

    generated = RUNNER.invoke(cli.app, ["ssh-key", "generate"])
    assert generated.exit_code == 0
    hint = next(line for line in generated.output.splitlines() if "; run: " in line)
    assert hint.startswith("manual SSH authorization is required; run: ")
    assert shlex.split(hint.partition("; run: ")[2]) == [
        str(instance.root.with_name(f".{instance.root.name}-application") / "shuttle-gate"),
        "--instance",
        str(instance.root),
        "ssh-key",
        "instructions",
    ]
    instructions = RUNNER.invoke(cli.app, ["ssh-key", "instructions"])
    assert instructions.exit_code == 0
    assert "ssh-copy-id" in instructions.output
    assert not any(call[0][0] == "ssh-copy-id" for call in fake.calls)


def test_doctor_runtime_health_status_and_version_adapters(
    instance: InstancePaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _select_roots(monkeypatch, instance.root)
    monkeypatch.setattr(
        cli,
        "doctor_checks",
        lambda _config, _paths, _runner: ["all checks: ok"],
    )
    assert "all checks: ok" in RUNNER.invoke(cli.app, ["doctor"]).output

    monkeypatch.setattr(cli, "run_gateway", lambda: 7)
    assert RUNNER.invoke(cli.app, ["runtime"]).exit_code == 7
    monkeypatch.setattr(cli, "healthcheck", lambda: 1)
    assert RUNNER.invoke(cli.app, ["health"]).exit_code == 1

    status = {
        "schema_version": 2,
        "state": "ready",
        "health": "ok",
        "wireguard_interface": "wg0",
        "routes": ["10.0.0.0/8"],
        "peers": [
            {
                "name": "phone",
                "latest_handshake": 123,
                "received_bytes": 10,
                "sent_bytes": 20,
            }
        ],
    }
    monkeypatch.setattr(cli, "runtime_status", lambda: status)
    text_status = RUNNER.invoke(cli.app, ["runtime-status"])
    assert "peer phone: handshake=123" in text_status.output
    json_status = RUNNER.invoke(cli.app, ["runtime-status", "--json"])
    assert json.loads(json_status.output)["state"] == "ready"
    assert RUNNER.invoke(cli.app, ["version"]).output.strip() == "1.0.0"


def test_public_help_uses_launcher_name_and_describes_selected_effects() -> None:
    keys = RUNNER.invoke(
        cli.app,
        ["keys", "generate", "--help"],
        prog_name="./shuttle-gate",
    )
    phone = RUNNER.invoke(
        cli.app,
        ["phone-config", "--help"],
        prog_name="./shuttle-gate",
    )

    assert "Usage: ./shuttle-gate keys generate" in keys.output
    assert "Limit key generation and config refresh to one peer" in keys.output
    assert "Usage: ./shuttle-gate phone-config" in phone.output
    assert "instance-relative path exports/FILE" in phone.output


def test_main_turns_application_errors_into_stable_cli_errors(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(*, prog_name: str) -> None:
        assert prog_name == "./shuttle-gate"
        raise ShuttleGateError("bad")

    monkeypatch.setattr(cli, "app", fail)
    with pytest.raises(SystemExit) as raised:
        cli.main()
    assert raised.value.code == 2
    assert capsys.readouterr().err == "shuttle-gate error: bad\n"
