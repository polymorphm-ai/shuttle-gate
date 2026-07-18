from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

import shuttle_gate.sshuttle_entry as sshuttle_entry
from shuttle_gate.errors import StateError
from shuttle_gate.host import _build_application_bundle
from shuttle_gate.nft_tproxy import Method
from shuttle_gate.sshuttle_entry import (
    ADAPTER_FAILURE_EXIT,
    FIREWALL_ENTRYPOINT_SOURCE,
    METHOD_MODULE,
    install_native_method,
    main,
    prepare_firewall_entrypoint,
)


def test_native_method_is_injected_without_changing_installed_files() -> None:
    import sshuttle.firewall as firewall  # type: ignore[import-untyped]

    module = install_native_method()

    assert module is sys.modules[METHOD_MODULE]
    assert module.Method is Method
    assert firewall.flush_systemd_dns_cache() is None


@pytest.mark.parametrize(("result", "code"), [(None, 0), (7, 7)])
def test_entrypoint_propagates_sshuttle_status(
    result: int | None,
    code: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_argv0 = "/opt/shuttle-gate/application.pyz/shuttle_gate/sshuttle_entry.py"
    monkeypatch.setattr(sys, "argv", [original_argv0])
    real_prepare = prepare_firewall_entrypoint
    monkeypatch.setattr(
        sshuttle_entry,
        "prepare_firewall_entrypoint",
        lambda: real_prepare(tmp_path / "private"),
    )
    seen_argv0: list[str] = []

    def fake_main() -> int | None:
        seen_argv0.append(sys.argv[0])
        return result

    fake = ModuleType("sshuttle.cmdline")
    fake.main = fake_main  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sshuttle.cmdline", fake)

    with pytest.raises(SystemExit) as raised:
        main()

    assert raised.value.code == code
    assert sys.argv[0] == original_argv0
    assert len(seen_argv0) == 1
    entrypoint = Path(seen_argv0[0])
    assert entrypoint.is_file()
    assert entrypoint.read_text(encoding="utf-8") == FIREWALL_ENTRYPOINT_SOURCE
    assert entrypoint.stat().st_mode & 0o777 == 0o600


def test_entrypoint_setup_failure_has_a_permanent_exit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail() -> Path:
        raise StateError("private entrypoint is unavailable")

    monkeypatch.setattr(sshuttle_entry, "prepare_firewall_entrypoint", fail)

    with pytest.raises(SystemExit) as raised:
        main()

    assert raised.value.code == ADAPTER_FAILURE_EXIT
    assert capsys.readouterr().err == (
        "shuttle-gate sshuttle adapter error: private entrypoint is unavailable\n"
    )


def test_zip_bundle_firewall_reexec_uses_a_real_entrypoint(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    bundle = tmp_path / "application.pyz"
    _build_application_bundle(repository, bundle)

    fake_package = tmp_path / "fake-package/sshuttle"
    methods = fake_package / "methods"
    methods.mkdir(parents=True)
    (fake_package / "__init__.py").write_text("", encoding="utf-8")
    (fake_package / "helpers.py").write_text(
        "class Fatal(Exception):\n    pass\n",
        encoding="utf-8",
    )
    (fake_package / "firewall.py").write_text(
        "def flush_systemd_dns_cache():\n    pass\n",
        encoding="utf-8",
    )
    (methods / "__init__.py").write_text(
        "class BaseMethod:\n    pass\n",
        encoding="utf-8",
    )
    (fake_package / "cmdline.py").write_text(
        "import subprocess\n"
        "import sys\n"
        "\n"
        "def main():\n"
        "    if sys.argv[1:] == ['--firewall']:\n"
        "        return 0\n"
        "    return subprocess.run(\n"
        "        [sys.executable, sys.argv[0], '--firewall'],\n"
        "        check=False,\n"
        "    ).returncode\n",
        encoding="utf-8",
    )
    private_tmp = tmp_path / "private-tmp"
    private_tmp.mkdir()
    environment = {
        "PATH": os.environ["PATH"],
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join((str(bundle), str(fake_package.parent))),
        "TMPDIR": str(private_tmp),
    }

    completed = subprocess.run(
        [sys.executable, "-m", "shuttle_gate.sshuttle_entry"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env=environment,
    )

    assert completed.returncode == 0, shlex.join(completed.args) + "\n" + completed.stderr
