"""Shared response shapes for GDB MCP tools."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .session import CommandResult, GdbSession


@dataclass(frozen=True)
class ErrorResponse:
    """Common error payload returned by tool handlers."""

    error: str
    error_type: str
    ok: bool = False

    @classmethod
    def from_exception(cls, exc: Exception) -> ErrorResponse:
        return cls(error=str(exc), error_type=type(exc).__name__)

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "error": self.error, "error_type": self.error_type}


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
