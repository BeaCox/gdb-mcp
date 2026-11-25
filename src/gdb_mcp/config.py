"""Runtime configuration loaded from CLI flags and environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass

from .observability import parse_log_level


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_optional_float(name: str, default: float | None = None) -> float | None:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        parsed = float(value)
    except ValueError:
        return default
    return parsed if parsed > 0 else None


def _env_log_level(name: str, default: str = "off") -> str:
    try:
        return parse_log_level(os.getenv(name, default))
    except ValueError:
        return default


@dataclass
class ServerConfig:
    allow_unsafe_execute: bool = False
    max_sessions: int = 8
    output_limit_chars: int = 100_000
    tool_profile: str = "full"
    idle_session_ttl_seconds: float | None = None
    max_recent_records: int = 500
    max_recent_commands: int = 200
    log_level: str = "off"

    @classmethod
    def from_env(cls) -> ServerConfig:
        return cls(
            allow_unsafe_execute=_env_bool("GDB_MCP_ALLOW_UNSAFE", False),
            max_sessions=max(0, _env_int("GDB_MCP_MAX_SESSIONS", 8)),
            output_limit_chars=max(
                10_000,
                _env_int("GDB_MCP_OUTPUT_LIMIT_CHARS", 100_000),
            ),
            tool_profile=os.getenv("GDB_MCP_TOOL_PROFILE", "full"),
            idle_session_ttl_seconds=_env_optional_float(
                "GDB_MCP_IDLE_SESSION_TTL_SECONDS",
                None,
            ),
            max_recent_records=max(
                10,
                min(5_000, _env_int("GDB_MCP_MAX_RECENT_RECORDS", 500)),
            ),
            max_recent_commands=max(
                10,
                min(2_000, _env_int("GDB_MCP_MAX_RECENT_COMMANDS", 200)),
            ),
            log_level=_env_log_level("GDB_MCP_LOG_LEVEL", "off"),
        )
