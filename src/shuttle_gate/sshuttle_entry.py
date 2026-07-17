"""Run locked sshuttle with the project native nftables method."""

from __future__ import annotations

import sys
from collections.abc import Callable
from types import ModuleType
from typing import cast

from .nft_tproxy import Method

METHOD_MODULE = "sshuttle.methods.tproxy"


def install_native_method() -> ModuleType:
    """Install the controlled method module in memory without changing packages."""

    module = ModuleType(METHOD_MODULE)
    module.Method = Method  # type: ignore[attr-defined]
    sys.modules[METHOD_MODULE] = module
    return module


def main() -> None:
    """Inject the method before sshuttle performs its dynamic method import."""

    install_native_method()
    from sshuttle.cmdline import main as untyped_main  # type: ignore[import-untyped]

    sshuttle_main = cast("Callable[[], int | None]", untyped_main)
    result = sshuttle_main()
    raise SystemExit(0 if result is None else result)


if __name__ == "__main__":
    main()
