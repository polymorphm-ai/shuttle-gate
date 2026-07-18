"""Run locked sshuttle with the project native nftables method."""

from __future__ import annotations

import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import cast

from .errors import ShuttleGateError
from .files import atomic_write
from .nft_tproxy import Method

METHOD_MODULE = "sshuttle.methods.tproxy"
ADAPTER_FAILURE_EXIT = 70
FIREWALL_ENTRYPOINT_SOURCE = "from shuttle_gate.sshuttle_entry import main\nmain()\n"


def _skip_namespace_dns_cache_flush() -> None:
    """Do nothing: the private namespace has no local resolver daemon."""


def install_native_method() -> ModuleType:
    """Install the controlled method module in memory without changing packages."""

    import sshuttle.firewall as firewall  # type: ignore[import-untyped]

    module = ModuleType(METHOD_MODULE)
    module.Method = Method  # type: ignore[attr-defined]
    sys.modules[METHOD_MODULE] = module
    firewall.flush_systemd_dns_cache = _skip_namespace_dns_cache_flush
    return module


def prepare_firewall_entrypoint(directory: Path | None = None) -> Path:
    """Publish a real script for sshuttle's firewall-manager re-exec."""

    private_directory = directory or (
        Path(tempfile.gettempdir()) / f"shuttle-gate-sshuttle-{os.getpid()}"
    )
    entrypoint = private_directory / "firewall-entry.py"
    atomic_write(entrypoint, FIREWALL_ENTRYPOINT_SOURCE, 0o600)
    return entrypoint


def main() -> None:
    """Inject the method before sshuttle performs its dynamic method import."""

    install_native_method()
    try:
        entrypoint = prepare_firewall_entrypoint()
    except (OSError, ShuttleGateError) as exc:
        print(f"shuttle-gate sshuttle adapter error: {exc}", file=sys.stderr)
        raise SystemExit(ADAPTER_FAILURE_EXIT) from None

    from sshuttle.cmdline import main as untyped_main  # type: ignore[import-untyped]

    sshuttle_main = cast("Callable[[], int | None]", untyped_main)
    original_argv0 = sys.argv[0]
    sys.argv[0] = str(entrypoint)
    try:
        result = sshuttle_main()
    finally:
        sys.argv[0] = original_argv0
    raise SystemExit(0 if result is None else result)


if __name__ == "__main__":
    main()
