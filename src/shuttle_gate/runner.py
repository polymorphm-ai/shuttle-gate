"""Auditable subprocess execution without shell expansion."""

from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol

from .errors import CommandError

DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_DIAGNOSTIC_CHARS = 8_192


@dataclass(frozen=True)
class CommandResult:
    """Completed command output."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class Runner(Protocol):
    """Injectable fixed-command runner used by control-plane code."""

    def run(
        self,
        args: Sequence[str],
        *,
        input_text: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        check: bool = True,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        """Run one process without a shell."""


class SubprocessRunner:
    """Production implementation of :class:`Runner`."""

    def run(
        self,
        args: Sequence[str],
        *,
        input_text: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        check: bool = True,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        command = tuple(str(value) for value in args)
        if not command:
            raise ValueError("command must not be empty")
        try:
            completed = subprocess.run(
                command,
                input=input_text,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
                env=dict(env) if env is not None else None,
            )
        except FileNotFoundError as exc:
            raise CommandError(f"required command not found: {command[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise CommandError(f"command timed out after {timeout:g}s: {command[0]}") from exc

        result = CommandResult(
            args=command,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        if check and result.returncode != 0:
            diagnostic = (result.stderr or result.stdout).strip()[:MAX_DIAGNOSTIC_CHARS]
            suffix = f": {diagnostic}" if diagnostic else ""
            raise CommandError(f"{command[0]} exited with status {result.returncode}{suffix}")
        return result
