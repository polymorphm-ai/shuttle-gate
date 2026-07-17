from __future__ import annotations

import fcntl
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

import shuttle_gate.claim as claim


def _claim_path(tmp_path: Path, digit: str = "1") -> Path:
    path = tmp_path / f"{digit * 64}.lock"
    path.touch(mode=0o600)
    return path


def test_claim_arguments_require_sorted_paths_and_a_command_boundary(tmp_path: Path) -> None:
    first = _claim_path(tmp_path, "1")
    second = _claim_path(tmp_path, "2")

    claims, command = claim.parse_arguments(
        ["--claim", str(first), "--claim", str(second), "--", "/usr/bin/true"]
    )

    assert claims == (first, second)
    assert command == ("/usr/bin/true",)
    invalid: tuple[list[str], ...] = (
        [],
        ["--claim"],
        ["--claim", str(first)],
        ["--claim", str(second), "--claim", str(first), "--", "/usr/bin/true"],
        ["--claim", str(tmp_path / "bad"), "--", "/usr/bin/true"],
        ["--claim", str(first), "--", "relative-command"],
    )
    for arguments in invalid:
        with pytest.raises(claim.ClaimError):
            claim.parse_arguments(arguments)


def test_claim_wrapper_holds_locks_until_the_command_finishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _claim_path(tmp_path)
    observed: list[list[str]] = []

    def run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed.append(command)
        contender = os.open(path, os.O_RDWR | os.O_CLOEXEC)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(contender)
        return subprocess.CompletedProcess(command, 9)

    monkeypatch.setattr(subprocess, "run", run)

    assert claim.run_claimed([path], ["/usr/bin/false"]) == 9
    assert observed == [["/usr/bin/false"]]


def test_claim_conflict_and_invalid_file_fail_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _claim_path(tmp_path)
    holder = os.open(path, os.O_RDWR | os.O_CLOEXEC)
    fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        assert claim.run_claimed([path], ["/usr/bin/true"]) == claim.CLAIM_CONFLICT_EXIT
    finally:
        os.close(holder)
    assert "already in use" in capsys.readouterr().err

    path.chmod(0o644)
    with pytest.raises(claim.ClaimError, match="permissions"):
        claim.run_claimed([path], ["/usr/bin/true"])


def test_claim_wrapper_reports_execution_and_argument_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _claim_path(tmp_path)

    def unavailable(*_args: Any, **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise OSError("unavailable")

    monkeypatch.setattr(subprocess, "run", unavailable)
    with pytest.raises(claim.ClaimError, match="cannot execute"):
        claim.run_claimed([path], ["/usr/bin/missing"])

    monkeypatch.setattr(sys, "argv", ["claim-wrapper"])
    with pytest.raises(SystemExit) as raised:
        claim.main()
    assert raised.value.code == 2
    assert "claim error" in capsys.readouterr().err
