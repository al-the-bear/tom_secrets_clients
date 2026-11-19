# Copyright (c) 2026 Peter Nicolai Alexis Kyaw
# SPDX-License-Identifier: BSD-3-Clause
"""The error kinds and the library's one error type (protocol.md section 10)."""

from __future__ import annotations

import enum
from typing import Any, Mapping, Optional


class ErrorKind(str, enum.Enum):
    """What went wrong: the protocol's kinds plus ``NOT_RUNNING``, which the
    library reports when it finds no service or loses the connection."""

    LOCKED = "locked"
    DENIED = "denied"
    NOT_FOUND = "not_found"
    AMBIGUOUS = "ambiguous"
    NEEDS_UNLOCK = "needs_unlock"
    UNAVAILABLE = "unavailable"
    OFFLINE = "offline"
    TOKEN_EXPIRED = "token_expired"
    MALFORMED = "malformed"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    UNSUPPORTED = "unsupported"
    INTERNAL = "internal"
    NOT_RUNNING = "not_running"

    @classmethod
    def from_wire(cls, kind: Any) -> "ErrorKind":
        """The kind an ``error`` message names: an unknown kind (from a later
        service) is ``INTERNAL``; ``not_running`` is never the service's to
        send."""
        if isinstance(kind, str) and kind != cls.NOT_RUNNING.value:
            try:
                return cls(kind)
            except ValueError:
                pass
        return cls.INTERNAL


class SecretsError(Exception):
    """Every failure of the library: ``kind``, the message and ``details``
    (``reason``, ``candidates``, ``retryAfterMs``, ...)."""

    def __init__(
        self,
        kind: ErrorKind,
        message: str,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.details: Mapping[str, Any] = dict(details or {})

    @classmethod
    def from_error(cls, error: Mapping[str, Any]) -> "SecretsError":
        """The error an ``error`` message carries."""
        details = error.get("details")
        message = error.get("message")
        return cls(
            ErrorKind.from_wire(error.get("kind")),
            message if isinstance(message, str) else "",
            details if isinstance(details, dict) else {},
        )

    @property
    def reason(self) -> Optional[str]:
        """``details.reason``, when there is one."""
        reason = self.details.get("reason")
        return reason if isinstance(reason, str) else None

    def __str__(self) -> str:
        reason = "" if self.reason is None else f", {self.reason}"
        return f"SecretsError({self.kind.value}{reason}): {self.message}"

    def __repr__(self) -> str:
        return self.__str__()


def not_running(why: str) -> SecretsError:
    return SecretsError(
        ErrorKind.NOT_RUNNING, f"the secrets service is not running: {why}"
    )


def protocol_error(why: str) -> SecretsError:
    return SecretsError(
        ErrorKind.INTERNAL,
        f"the service broke the protocol: {why}",
        {"code": "protocol"},
    )
