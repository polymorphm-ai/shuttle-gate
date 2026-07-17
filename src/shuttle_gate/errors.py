"""Stable application error types."""

from __future__ import annotations


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
