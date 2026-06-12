"""Runtime configuration loaded from CLI flags and environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass


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


@dataclass
class ServerConfig:
    allow_unsafe_execute: bool = False
    max_sessions: int = 8
    output_limit_chars: int = 100_000

    @classmethod
    def from_env(cls) -> ServerConfig:
        return cls(
            allow_unsafe_execute=_env_bool("GDB_MCP_ALLOW_UNSAFE", False),
            max_sessions=max(0, _env_int("GDB_MCP_MAX_SESSIONS", 8)),
            output_limit_chars=max(
                10_000,
                _env_int("GDB_MCP_OUTPUT_LIMIT_CHARS", 100_000),
            ),
        )
