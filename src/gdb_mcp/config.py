"""Runtime configuration loaded from CLI flags and environment variables."""

from __future__ import annotations

import math
import os
from dataclasses import dataclass

from .observability import parse_log_level
from .tool_profiles import parse_tool_names, parse_tool_profile

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(
        f"{name} must be a boolean (1/0, true/false, yes/no, on/off), got {value!r}"
    )


def _env_int(
    name: str,
    default: int,
    *,
    min_value: int | None = None,
    max_value: int | None = None,
) -> int:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        parsed = int(value.strip())
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {value!r}") from exc
    if min_value is not None and parsed < min_value:
        raise ValueError(f"{name} must be >= {min_value}, got {parsed}")
    if max_value is not None and parsed > max_value:
        raise ValueError(f"{name} must be <= {max_value}, got {parsed}")
    return parsed


def _env_optional_float(name: str, default: float | None = None) -> float | None:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        parsed = float(value.strip())
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {value!r}") from exc
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f"{name} must be a finite number >= 0, got {value!r}")
    return parsed if parsed > 0 else None


def _env_positive_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        parsed = float(value.strip())
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {value!r}") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise ValueError(f"{name} must be a finite number > 0, got {value!r}")
    return parsed


def _env_log_level(name: str, default: str = "off") -> str:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return parse_log_level(value)
    except ValueError as exc:
        raise ValueError(f"{name}: {exc}") from exc


@dataclass
class ServerConfig:
    allow_unsafe_execute: bool = False
    max_sessions: int = 8
    output_limit_chars: int = 100_000
    tool_profile: str = "full"
    tool_profile_explicit: bool = False
    include_tools: tuple[str, ...] = ()
    exclude_tools: tuple[str, ...] = ()
    idle_session_ttl_seconds: float | None = None
    max_recent_records: int = 500
    max_recent_commands: int = 200
    log_level: str = "off"
    progress_notifications: bool = False

    @classmethod
    def from_env(cls) -> ServerConfig:
        raw_profile = os.getenv("GDB_MCP_TOOL_PROFILE")
        profile_explicit = bool(raw_profile and raw_profile.strip())
        profile = parse_tool_profile(raw_profile)
        return cls(
            allow_unsafe_execute=_env_bool("GDB_MCP_ALLOW_UNSAFE", False),
            max_sessions=_env_int("GDB_MCP_MAX_SESSIONS", 8, min_value=0),
            output_limit_chars=_env_int(
                "GDB_MCP_OUTPUT_LIMIT_CHARS",
                100_000,
                min_value=10_000,
            ),
            tool_profile=profile.canonical_name,
            tool_profile_explicit=profile_explicit,
            include_tools=parse_tool_names(os.getenv("GDB_MCP_TOOLS")),
            exclude_tools=parse_tool_names(os.getenv("GDB_MCP_EXCLUDE_TOOLS")),
            idle_session_ttl_seconds=_env_optional_float(
                "GDB_MCP_IDLE_SESSION_TTL_SECONDS",
                None,
            ),
            max_recent_records=_env_int(
                "GDB_MCP_MAX_RECENT_RECORDS",
                500,
                min_value=10,
                max_value=5_000,
            ),
            max_recent_commands=_env_int(
                "GDB_MCP_MAX_RECENT_COMMANDS",
                200,
                min_value=10,
                max_value=2_000,
            ),
            log_level=_env_log_level("GDB_MCP_LOG_LEVEL", "off"),
            progress_notifications=_env_bool("GDB_MCP_PROGRESS", False),
        )
