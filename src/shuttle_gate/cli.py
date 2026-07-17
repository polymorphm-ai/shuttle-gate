"""Container-side operator and runtime CLI."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from . import __version__
from .compose import prepare_launch
from .config import ProjectConfig, load_config
from .errors import ShuttleGateError
from .files import (
    InstancePaths,
    atomic_write,
    container_secret_path,
    ensure_private_directory,
    validate_ssh_files,
)
from .keys import (
    PHONE_CONFIG,
    generate_missing_keys,
    generate_ssh_key,
    peer_rows,
    prune_orphaned_peers,
    read_phone_config,
    recover_ssh_key_transaction,
    render_all_phone_configs,
    require_no_ssh_key_transaction,
    rotate_peer,
    rotate_server,
    ssh_setup_instructions,
)
from .runner import SubprocessRunner
from .runtime import doctor_checks, healthcheck, run_gateway, runtime_status
from .state import state_lock

app = typer.Typer(no_args_is_help=True, pretty_exceptions_enable=False)
config_app = typer.Typer(no_args_is_help=True)
keys_app = typer.Typer(no_args_is_help=True)
peers_app = typer.Typer(no_args_is_help=True)
ssh_key_app = typer.Typer(no_args_is_help=True)
app.add_typer(config_app, name="config")
app.add_typer(keys_app, name="keys")
app.add_typer(peers_app, name="peers")
app.add_typer(ssh_key_app, name="ssh-key")


def instance_paths() -> InstancePaths:
    root = Path(os.environ.get("SHUTTLE_GATE_ROOT", "/workspace"))
    return InstancePaths.from_root(root)


def configuration(paths: InstancePaths) -> ProjectConfig:
    return load_config(paths.config)


def abort(message: str, code: int = 2) -> NoReturn:
    typer.echo(f"shuttle-gate error: {message}", err=True)
    raise typer.Exit(code)


@app.command("init")
def initialize() -> None:
    """Create project-local configuration and private directories."""

    paths = instance_paths()
    with state_lock(paths, exclusive=True, blocking=False):
        if paths.config.exists() or paths.config.is_symlink():
            abort(f"refusing to overwrite existing configuration: {paths.config}")
        example = paths.root / "config.example.yaml"
        if not example.is_file():
            abort(f"example configuration is missing: {example}")
        ensure_private_directory(paths.secrets)
        atomic_write(paths.config, example.read_text(encoding="utf-8"), 0o600)
    typer.echo(f"created {paths.config}")
    typer.echo("edit bind addresses, peers, SSH destination, routes, and DNS before setup")


@config_app.command("validate")
def validate_config() -> None:
    """Validate schema, paths, and credential permissions."""

    paths = instance_paths()
    config = configuration(paths)
    container_secret_path(config.ssh.identity_file)
    container_secret_path(config.ssh.known_hosts_file)
    with state_lock(paths, exclusive=True, blocking=False):
        recover_ssh_key_transaction(config, paths)
        validate_ssh_files(config, paths.config)
    typer.echo("configuration: valid")


@keys_app.command("generate")
def keys_generate(peer: Annotated[str | None, typer.Option("--peer")] = None) -> None:
    """Generate missing server and declared peer keys."""

    paths = instance_paths()
    created = generate_missing_keys(configuration(paths), paths, SubprocessRunner(), peer)
    typer.echo("created: " + (", ".join(created) if created else "nothing; all keys exist"))


def require_confirmation(message: str, yes: bool) -> None:
    if not yes and not typer.confirm(message):
        raise typer.Abort()


@keys_app.command("rotate-peer")
def keys_rotate_peer(
    name: str,
    yes: Annotated[bool, typer.Option("--yes")] = False,
    operation_id: Annotated[str | None, typer.Option("--operation-id")] = None,
) -> None:
    """Replace one peer key and invalidate its old phone config."""

    require_confirmation(f"rotate keys for peer {name}?", yes)
    request_id = operation_id or uuid.uuid4().hex
    typer.echo(f"operation ID: {request_id}")
    paths = instance_paths()
    rotate_peer(configuration(paths), paths, SubprocessRunner(), name, request_id)
    typer.echo(f"rotated peer: {name}")


@keys_app.command("rotate-server")
def keys_rotate_server(
    yes: Annotated[bool, typer.Option("--yes")] = False,
    operation_id: Annotated[str | None, typer.Option("--operation-id")] = None,
) -> None:
    """Replace the server key and regenerate every phone config."""

    require_confirmation("rotate the server key and invalidate every imported phone config?", yes)
    request_id = operation_id or uuid.uuid4().hex
    typer.echo(f"operation ID: {request_id}")
    paths = instance_paths()
    rotate_server(configuration(paths), paths, SubprocessRunner(), request_id)
    typer.echo("rotated server key; re-import every phone config")


@keys_app.command("prune")
def keys_prune(yes: Annotated[bool, typer.Option("--yes")] = False) -> None:
    """Delete state for peers absent from config.yaml."""

    require_confirmation("delete orphaned peer state?", yes)
    paths = instance_paths()
    removed = prune_orphaned_peers(configuration(paths), paths)
    typer.echo("removed: " + (", ".join(removed) if removed else "nothing"))


@peers_app.command("list")
def peers_list() -> None:
    """List declared peers and generated state."""

    paths = instance_paths()
    for name, keys, phone in peer_rows(configuration(paths), paths):
        typer.echo(f"{name}\tkeys={keys}\tphone-config={phone}")


@ssh_key_app.command("generate")
def ssh_key_generate(
    force: Annotated[bool, typer.Option("--force")] = False,
    operation_id: Annotated[str | None, typer.Option("--operation-id")] = None,
) -> None:
    """Generate a dedicated local SSH identity without network access."""

    request_id = operation_id or uuid.uuid4().hex
    typer.echo(f"operation ID: {request_id}")
    paths = instance_paths()
    identity = generate_ssh_key(configuration(paths), paths, SubprocessRunner(), force, request_id)
    typer.echo(f"created {identity} and {identity}.pub")
    typer.echo("run './shuttle-gate ssh-key instructions' for manual authorization")


@ssh_key_app.command("instructions")
def ssh_key_instructions() -> None:
    """Print manual key authorization and fingerprint verification steps."""

    paths = instance_paths()
    typer.echo(ssh_setup_instructions(configuration(paths), paths))


@app.command("phone-config")
def phone_config(
    name: str,
    output: Annotated[Path | None, typer.Option("--output")] = None,
    stdout: Annotated[bool, typer.Option("--stdout")] = False,
) -> None:
    """Regenerate and optionally export one sensitive phone config."""

    if output is not None and stdout:
        abort("--output and --stdout are mutually exclusive")
    paths = instance_paths()
    config = configuration(paths)
    if name not in {peer.name for peer in config.wireguard.peers}:
        abort(f"peer is not declared in config.yaml: {name}")
    render_all_phone_configs(config, paths)
    rendered = read_phone_config(paths, name)
    source = paths.peer_dir(name) / PHONE_CONFIG
    if stdout:
        typer.echo(rendered, nl=False)
        return
    if output is not None:
        atomic_write(output.resolve(), rendered, 0o600)
        typer.echo(str(output.resolve()))
        return
    typer.echo(str(source))


@app.command("prepare", hidden=True)
def prepare() -> None:
    """Write non-secret launch metadata after complete validation."""

    paths = instance_paths()
    override, manifest = prepare_launch(configuration(paths), paths)
    typer.echo(f"prepared {override} and {manifest}")


@app.command("doctor")
def doctor() -> None:
    """Check disposable kernel, SSH, and remote-Python prerequisites."""

    paths = instance_paths()
    config = configuration(paths)
    with state_lock(paths, exclusive=False):
        require_no_ssh_key_transaction(config, paths)
        validate_ssh_files(config, paths.config)
        for message in doctor_checks(config, SubprocessRunner()):
            typer.echo(message)


@app.command("runtime", hidden=True)
def runtime_command() -> None:
    """Run the long-lived gateway."""

    raise typer.Exit(run_gateway())


@app.command("health", hidden=True)
def health_command() -> None:
    """Docker health-check entrypoint."""

    raise typer.Exit(healthcheck())


@app.command("runtime-status", hidden=True)
def runtime_status_command(
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Read live non-secret status from the gateway namespace."""

    value = runtime_status()
    if json_output:
        typer.echo(json.dumps(value, sort_keys=True))
        return
    typer.echo(f"state: {value['state']}")
    typer.echo(f"health: {value['health']}")
    typer.echo(f"interface: {value['wireguard_interface']}")
    typer.echo("routes: " + ", ".join(value["routes"]))
    for peer in value["peers"]:
        typer.echo(
            f"peer {peer['name']}: handshake={peer['latest_handshake']} "
            f"rx={peer['received_bytes']} tx={peer['sent_bytes']}"
        )


@app.command("version")
def version() -> None:
    """Print the internal application version."""

    typer.echo(__version__)


def main() -> None:
    try:
        app()
    except ShuttleGateError as exc:
        abort(str(exc))


if __name__ == "__main__":
    main()
