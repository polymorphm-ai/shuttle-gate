"""Stable application error types."""

from __future__ import annotations

import os
import shlex
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

LAUNCHER_ENV = "SHUTTLE_GATE_LAUNCHER"
INSTANCE_ENV = "SHUTTLE_GATE_INSTANCE"
_COMMAND_CONTEXT: ContextVar[tuple[str, str | None] | None] = ContextVar(
    "shuttle_gate_command_context",
    default=None,
)


@contextmanager
def command_context(launcher: Path, instance: Path | None) -> Iterator[None]:
    """Set host-side context for deterministic actionable diagnostics."""

    value = (str(launcher), str(instance) if instance is not None else None)
    token = _COMMAND_CONTEXT.set(value)
    try:
        yield
    finally:
        _COMMAND_CONTEXT.reset(token)


def command_hint(*arguments: str) -> str:
    """Render one complete, shell-safe command using the active instance."""

    context = _COMMAND_CONTEXT.get()
    if context is None:
        launcher = os.environ.get(LAUNCHER_ENV, "./shuttle-gate")
        instance = os.environ.get(INSTANCE_ENV)
    else:
        launcher, instance = context
    command = [launcher]
    if instance is not None:
        command.extend(["--instance", instance])
    command.extend(arguments)
    return f"run: {shlex.join(command)}"


def with_command_hint(message: str, *arguments: str) -> str:
    """Attach one consistently formatted recovery command to a diagnostic."""

    return f"{message}; {command_hint(*arguments)}"


class ShuttleGateError(Exception):
    """Base class for failures safe to show to an operator."""


class ConfigurationError(ShuttleGateError):
    """Configuration is missing, malformed, or unsafe."""


class StateError(ShuttleGateError):
    """Persistent local state is missing, inconsistent, or unsafe."""


class CommandError(ShuttleGateError):
    """A fixed external command failed."""


class RuntimeFailure(ShuttleGateError):
    """Gateway startup or supervision failed."""


class TransientRuntimeFailure(RuntimeFailure):
    """A classified runtime failure that may be retried safely."""
