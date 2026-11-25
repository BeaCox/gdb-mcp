"""Pure formatting and pagination helpers for inspection MCP tools."""

from __future__ import annotations

import re
from typing import Any

from ..analysis import read_memory_contents
from ..pagination import paginate_text_lines
from .shared import _profile_command_payload


def disassembly_options(mixed: bool, raw_bytes: bool) -> str:
    """Build GDB ``disassemble`` option flags from booleans."""

    if not mixed and not raw_bytes:
        return ""
    return "/" + ("m" if mixed else "") + ("r" if raw_bytes else "")


def filter_source_matches(console: str, query: str, limit: int) -> list[str]:
    """Return up to ``limit`` unique source paths containing ``query``."""

    matches: list[str] = []
    for chunk in re.split(r"[\s,]+", console):
        source = chunk.strip()
        if source and query in source and source not in matches:
            matches.append(source)
            if len(matches) >= limit:
                break
    return matches


def decode_c_string(payload: dict[str, Any]) -> str:
    """Decode a NUL-terminated UTF-8 string from a ``gdb_read_memory`` payload."""

    if not payload.get("ok"):
        return ""
    data = read_memory_contents(payload)
    if not data:
        return ""
    return data.split(b"\0", 1)[0].decode(errors="replace")


def format_paged_console_payload(
    payload: dict[str, Any],
    *,
    output: str,
    cursor: str | None,
    page_size: int | None,
    default_page_size: int,
    max_page_size: int,
    cursor_scope: str,
) -> dict[str, Any]:
    """Paginate console lines and apply the requested output profile."""

    lines, pagination = paginate_text_lines(
        str(payload.get("console") or ""),
        cursor=cursor,
        page_size=page_size,
        default_page_size=default_page_size,
        max_page_size=max_page_size,
        cursor_scope=cursor_scope,
    )
    paged = {
        **payload,
        "lines": lines,
        "line_count": len(lines),
        "pagination": pagination,
    }
    if output != "raw":
        paged["console"] = "\n".join(lines)
    if output == "structured":
        paged.pop("console", None)
    return _profile_command_payload(paged, output)


def format_memory_read_payload(
    payload: dict[str, Any],
    *,
    address: str,
    read_address: str,
    count: int,
    read_count: int,
    pagination: dict[str, Any],
    output: str,
) -> dict[str, Any]:
    """Attach byte counts and pagination metadata to a memory read response."""

    byte_count = len(read_memory_contents(payload))
    enriched = {
        **payload,
        "address": address,
        "read_address": read_address,
        "requested_byte_count": count,
        "requested_page_bytes": read_count,
        "returned_byte_count": byte_count,
        "pagination": pagination,
    }
    return _profile_command_payload(
        enriched,
        output,
        summary_fields={
            "address": address,
            "read_address": read_address,
            "requested_byte_count": count,
            "requested_page_bytes": read_count,
            "returned_byte_count": byte_count,
            "pagination": pagination,
        },
    )
