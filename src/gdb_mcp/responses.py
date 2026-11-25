"""Shared response shapes and standardized error classification for GDB MCP tools."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .observability import redact_text
from .pagination import CursorError
from .session import (
    CommandResult,
    GdbMcpError,
    GdbNotFound,
    GdbSession,
    PolicyDeniedError,
    SessionLimitError,
    SessionNotFound,
)


def classify_error(exc: Exception) -> tuple[str, bool, str | None]:
    """Return ``(error_code, retryable, suggested_action)`` for a tool failure."""

    if isinstance(exc, CursorError):
        message = str(exc).lower()
        if "expired" in message:
            return (
                "expired_cursor",
                True,
                "Request the first page again without a cursor.",
            )
        if "stale" in message:
            return (
                "stale_cursor",
                True,
                "Request the first page again without a cursor.",
            )
        return ("invalid_cursor", False, None)

    if isinstance(exc, SessionNotFound):
        return (
            "session_not_found",
            False,
            "Call gdb_list_sessions to inspect active sessions or create one with "
            "gdb_create_session.",
        )

    if isinstance(exc, SessionLimitError):
        return (
            "session_limit_reached",
            True,
            "Close an unused session with gdb_close_session or gdb_close_idle_sessions.",
        )

    if isinstance(exc, (PolicyDeniedError, PermissionError)):
        return (
            "policy_denied",
            False,
            "Restart gdb-mcp with --unsafe or GDB_MCP_ALLOW_UNSAFE=1 if this operation is "
            "approved.",
        )

    if isinstance(exc, (GdbNotFound, FileNotFoundError)):
        return (
            "dependency_not_found",
            False,
            "Verify the executable or file path exists and is accessible on PATH.",
        )

    if isinstance(exc, TimeoutError):
        return (
            "timeout",
            True,
            "Retry with a larger timeout or interrupt the target with gdb_interrupt.",
        )

    if isinstance(exc, (ValueError, TypeError)):
        return ("invalid_input", False, None)

    if isinstance(exc, GdbMcpError):
        lowered = str(exc).lower()
        if "not found" in lowered:
            return (
                "dependency_not_found",
                False,
                "Install the missing dependency or pass an explicit executable path.",
            )
        if "closed" in lowered or "closing" in lowered:
            return (
                "session_closed",
                False,
                "Create a new session with gdb_create_session.",
            )
        if "timed out" in lowered:
            return (
                "timeout",
                True,
                "Retry with a larger timeout or interrupt the target with gdb_interrupt.",
            )
        return ("gdb_error", False, None)

    return ("internal_error", False, None)


@dataclass(frozen=True)
class ErrorResponse:
    """Common error payload returned by tool handlers."""

    error: str
    error_type: str
    error_code: str = "internal_error"
    retryable: bool = False
    suggested_action: str | None = None
    ok: bool = False

    @classmethod
    def from_exception(cls, exc: Exception) -> ErrorResponse:
        error_code, retryable, suggested_action = classify_error(exc)
        return cls(
            error=redact_text(str(exc)),
            error_type=type(exc).__name__,
            error_code=error_code,
            retryable=retryable,
            suggested_action=suggested_action,
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": self.ok,
            "error": self.error,
            "error_type": self.error_type,
            "error_code": self.error_code,
            "retryable": self.retryable,
        }
        if self.suggested_action is not None:
            payload["suggested_action"] = self.suggested_action
        return payload


@dataclass(frozen=True)
class OkResponse:
    """Common success payload for small non-command responses."""

    fields: dict[str, Any] = field(default_factory=dict)
    ok: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, **self.fields}


@dataclass(frozen=True)
class CommandResponse:
    """Response wrapper for bounded GDB command results."""

    session: GdbSession
    result: CommandResult

    def to_dict(self) -> dict[str, Any]:
        return self.result.to_dict(self.session.output_limit_chars)


def error_response(exc: Exception) -> dict[str, Any]:
    return ErrorResponse.from_exception(exc).to_dict()


def ok_response(**fields: Any) -> dict[str, Any]:
    return OkResponse(fields=fields).to_dict()


def session_response(session: GdbSession, **fields: Any) -> dict[str, Any]:
    return ok_response(session=session.describe(), **fields)


def command_response(session: GdbSession, result: CommandResult) -> dict[str, Any]:
    return CommandResponse(session=session, result=result).to_dict()


def diagnostic_response(**fields: Any) -> dict[str, Any]:
    return ok_response(**fields)
