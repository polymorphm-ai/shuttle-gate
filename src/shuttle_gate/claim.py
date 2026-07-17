"""Hold deterministic host-socket claims while supervising one runtime command."""

from __future__ import annotations

import fcntl
import os
import re
import stat
import subprocess
import sys
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path
from typing import NoReturn

CLAIM_PATTERN = re.compile(r"^[0-9a-f]{64}\.lock$")
CLAIM_CONFLICT_EXIT = 73


class ClaimError(Exception):
    """A bounded internal wrapper failure safe to write to the journal."""


def parse_arguments(arguments: Sequence[str]) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    """Parse repeated claims followed by one structured command boundary."""

    values = list(arguments)
    claims: list[Path] = []
    while values[:1] == ["--claim"]:
        if len(values) < 2:
            raise ClaimError("--claim requires a path")
        claims.append(Path(values[1]))
        values = values[2:]
    if not claims or not values or values[0] != "--" or len(values) < 2:
        raise ClaimError("expected one or more claims followed by -- COMMAND")
    if claims != sorted(set(claims), key=str):
        raise ClaimError("claim paths must be unique and sorted")
    parent = claims[0].parent
    if any(
        not claim.is_absolute()
        or claim.parent != parent
        or CLAIM_PATTERN.fullmatch(claim.name) is None
        for claim in claims
    ):
        raise ClaimError("claim paths have an invalid structure")
    command = tuple(values[1:])
    if not Path(command[0]).is_absolute():
        raise ClaimError("runtime command must use an absolute executable path")
    return tuple(claims), command


def run_claimed(claims: Sequence[Path], command: Sequence[str]) -> int:
    """Hold every claim non-blockingly until the child command exits."""

    descriptors: list[int] = []
    try:
        for claim in claims:
            descriptor = os.open(claim, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
            descriptors.append(descriptor)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ClaimError("claim file ownership, type, or permissions are invalid")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print(
                    "shuttle-gate claim error: host UDP socket is already in use", file=sys.stderr
                )
                return CLAIM_CONFLICT_EXIT
        try:
            return subprocess.run(list(command), check=False).returncode
        except OSError as exc:
            raise ClaimError(f"cannot execute runtime command: {exc}") from exc
    finally:
        for descriptor in reversed(descriptors):
            with suppress(OSError):
                os.close(descriptor)


def main() -> NoReturn:
    """Run the internal claim wrapper with concise failure reporting."""

    try:
        claims, command = parse_arguments(sys.argv[1:])
        result = run_claimed(claims, command)
    except ClaimError as exc:
        print(f"shuttle-gate claim error: {exc}", file=sys.stderr)
        result = 2
    raise SystemExit(result)


if __name__ == "__main__":
    main()
