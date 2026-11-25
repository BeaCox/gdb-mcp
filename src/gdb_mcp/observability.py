"""Opt-in structured operational observability with secret redaction."""

from __future__ import annotations

import json
import os
import re
import sys
import time
from typing import Any, TextIO

LOG_LEVELS: dict[str, int] = {
    "off": 0,
    "error": 10,
    "warning": 20,
    "info": 30,
    "debug": 40,
}

_SENSITIVE_KEYS = frozenset(
    {
        "token",
        "bearer_token",
        "authorization",
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "env",
        "args",
        "raw",
        "inferior_args",
    }
)

_BEARER_RE = re.compile(r"(?i)\b(Bearer)\s+[^\s,;\"']+")
_AUTH_HEADER_RE = re.compile(r"(?i)\b(Authorization)\s*:\s*[^\r\n,;]+")
_KV_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|api_key|apikey)\b(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_URL_USERINFO_RE = re.compile(r"(https?://)([^/\s@:]+(?::[^/\s@]*)?)@")


def parse_log_level(value: str | None) -> str:
    """Validate and normalize an operational log level."""

    if value is None:
        return "off"
    normalized = value.strip().lower()
    if not normalized:
        return "off"
    if normalized not in LOG_LEVELS:
        choices = ", ".join(LOG_LEVELS)
        raise ValueError(f"log_level must be one of: {choices}")
    return normalized


def _safe_parse_env_log_level(value: str | None) -> str:
    try:
        return parse_log_level(value)
    except ValueError:
        return "off"


def redact_text(text: str) -> str:
    """Redact common credential patterns from free-form text."""

    if not text:
        return text
    redacted = _BEARER_RE.sub(r"\1 [REDACTED]", text)
    redacted = _AUTH_HEADER_RE.sub(r"\1: [REDACTED]", redacted)
    redacted = _KV_SECRET_RE.sub(r"\1\2[REDACTED]", redacted)
    redacted = _URL_USERINFO_RE.sub(r"\1[REDACTED]@", redacted)
    return redacted


def redact_mapping(data: Any) -> Any:
    """Recursively redact sensitive keys and string credentials in structured data."""

    if isinstance(data, str):
        return redact_text(data)
    if isinstance(data, list):
        return [redact_mapping(item) for item in data]
    if isinstance(data, tuple):
        return [redact_mapping(item) for item in data]
    if isinstance(data, dict):
        output: dict[str, Any] = {}
        for key, value in data.items():
            key_text = str(key)
            if key_text.lower() in _SENSITIVE_KEYS:
                output[key_text] = "[REDACTED]"
            else:
                output[key_text] = redact_mapping(value)
        return output
    return data


class StructuredLogger:
    """JSON-lines operational logger writing strictly to stderr when enabled."""

    def __init__(self, level: str = "off", stream: TextIO | None = None) -> None:
        self.level = parse_log_level(level)
        self.stream = stream

    def set_level(self, level: str) -> None:
        self.level = parse_log_level(level)

    def is_enabled(self, level: str) -> bool:
        target = parse_log_level(level)
        current = LOG_LEVELS.get(self.level, 0)
        return current > 0 and LOG_LEVELS[target] <= current

    def emit(self, level: str, event: str, **fields: Any) -> None:
        try:
            if not self.is_enabled(level):
                return
            target_stream = self.stream if self.stream is not None else sys.stderr
            if target_stream is sys.stdout:
                target_stream = sys.stderr
            record: dict[str, Any] = {
                "ts": time.time(),
                "level": level.strip().lower(),
                "event": event,
                **redact_mapping(fields),
            }
            line = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
            target_stream.write(line + "\n")
            target_stream.flush()
        except Exception:
            return


logger = StructuredLogger(level=_safe_parse_env_log_level(os.getenv("GDB_MCP_LOG_LEVEL")))
