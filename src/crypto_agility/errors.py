"""Domain exceptions surfaced consistently by the CLI and API."""

from __future__ import annotations


class CryptoAgilityError(RuntimeError):
    """Base error with a safe message suitable for an API response."""


class ScanSafetyError(CryptoAgilityError):
    """A scan target violates an explicit safety boundary."""


class BenchmarkUnavailable(CryptoAgilityError):
    """A real benchmark cannot run in the current environment."""


class ProtocolError(CryptoAgilityError):
    """The bounded demo protocol received an invalid message."""
