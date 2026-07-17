from __future__ import annotations

import sys
from types import ModuleType

import pytest

from shuttle_gate.nft_tproxy import Method
from shuttle_gate.sshuttle_entry import METHOD_MODULE, install_native_method, main


def test_native_method_is_injected_without_changing_installed_files() -> None:
    module = install_native_method()

    assert module is sys.modules[METHOD_MODULE]
    assert module.Method is Method


@pytest.mark.parametrize(("result", "code"), [(None, 0), (7, 7)])
def test_entrypoint_propagates_sshuttle_status(
    result: int | None,
    code: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = ModuleType("sshuttle.cmdline")
    fake.main = lambda: result  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sshuttle.cmdline", fake)

    with pytest.raises(SystemExit) as raised:
        main()

    assert raised.value.code == code
