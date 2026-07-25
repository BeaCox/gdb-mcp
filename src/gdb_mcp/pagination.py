"""Opaque cursor pagination helpers for bounded tool responses."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Sequence
from typing import Any, TypeVar

T = TypeVar("T")

CURSOR_TTL_SECONDS = 15 * 60
_CURSOR_VERSION = 1
_CURSOR_SECRET = secrets.token_bytes(32)


class CursorError(ValueError):
    """Raised when an opaque pagination cursor cannot be reused safely."""


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    decoded = base64.urlsafe_b64decode(value + padding)
    if _b64encode(decoded) != value:
        raise ValueError("non-canonical base64url encoding")
    return decoded


def _stable_digest(value: Any) -> str:
    serialized = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def snapshot_fingerprint(value: Any) -> str:
    """Return a deterministic identity for a collection snapshot."""

    return _stable_digest(value)


def _scope_fingerprint(scope: str) -> str:
    if not isinstance(scope, str) or not scope:
        raise ValueError("cursor_scope must be a non-empty string")
    return hashlib.sha256(scope.encode("utf-8")).hexdigest()


def _encode_cursor(*, offset: int, scope: str, snapshot: str, expires_at: int) -> str:
    payload = json.dumps(
        {
            "v": _CURSOR_VERSION,
            "o": offset,
            "s": _scope_fingerprint(scope),
            "f": snapshot,
            "e": expires_at,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signature = hmac.new(_CURSOR_SECRET, payload, hashlib.sha256).digest()[:16]
    return f"gdb1.{_b64encode(payload)}.{_b64encode(signature)}"


def _decode_cursor(cursor: str) -> dict[str, Any]:
    if not isinstance(cursor, str) or not cursor:
        raise CursorError("invalid cursor: expected an opaque gdb-mcp cursor")
    try:
        prefix, payload_text, signature_text = cursor.split(".", 2)
        if prefix != "gdb1":
            raise ValueError
        payload = _b64decode(payload_text)
        signature = _b64decode(signature_text)
        expected = hmac.new(_CURSOR_SECRET, payload, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(signature, expected):
            raise ValueError
        claims = json.loads(payload)
        if (
            not isinstance(claims, dict)
            or claims.get("v") != _CURSOR_VERSION
            or not isinstance(claims.get("o"), int)
            or claims["o"] < 0
            or not isinstance(claims.get("s"), str)
            or not isinstance(claims.get("f"), str)
            or not isinstance(claims.get("e"), int)
        ):
            raise ValueError
        return claims
    except (
        ValueError,
        TypeError,
        binascii.Error,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as exc:
        raise CursorError("invalid cursor: signature or payload is malformed") from exc


def _cursor_position(
    cursor: str | None,
    *,
    scope: str,
    snapshot: str,
    ttl_seconds: int,
    now: float | None,
) -> tuple[int, int]:
    current_time = int(time.time() if now is None else now)
    if ttl_seconds <= 0:
        raise ValueError("cursor_ttl_seconds must be positive")
    if cursor is None or cursor == "":
        return 0, current_time + ttl_seconds

    claims = _decode_cursor(cursor)
    if claims["e"] <= current_time:
        raise CursorError("expired cursor: request the first page again")
    if claims["s"] != _scope_fingerprint(scope):
        raise CursorError("cursor does not belong to this collection or session")
    if claims["f"] != snapshot:
        raise CursorError("stale cursor: collection snapshot changed")
    return claims["o"], claims["e"]


def page_size_or_default(
    page_size: int | None,
    *,
    default: int,
    maximum: int,
) -> int:
    """Validate a requested page size."""

    size = default if page_size is None else page_size
    if not 1 <= size <= maximum:
        raise ValueError(f"page_size must be between 1 and {maximum}")
    return size


def pagination_metadata(
    *,
    start: int,
    end: int,
    total_count: int,
    page_size: int,
    cursor_scope: str,
    snapshot: str,
    expires_at: int,
) -> dict[str, Any]:
    """Return common opaque cursor metadata for a page."""

    current_cursor = _encode_cursor(
        offset=start,
        scope=cursor_scope,
        snapshot=snapshot,
        expires_at=expires_at,
    )
    next_cursor = (
        _encode_cursor(
            offset=end,
            scope=cursor_scope,
            snapshot=snapshot,
            expires_at=expires_at,
        )
        if end < total_count
        else None
    )
    return {
        "cursor": current_cursor,
        "next_cursor": next_cursor,
        "page_size": page_size,
        "page_start": start,
        "page_end": end,
        "total_count": total_count,
        "has_more": next_cursor is not None,
        "expires_at": expires_at,
    }


def paginate_items(
    items: Sequence[T],
    *,
    cursor: str | None,
    page_size: int | None,
    default_page_size: int,
    max_page_size: int,
    cursor_scope: str,
    snapshot: str | None = None,
    cursor_ttl_seconds: int = CURSOR_TTL_SECONDS,
    initial_offset: int = 0,
    _now: float | None = None,
) -> tuple[list[T], dict[str, Any]]:
    """Return one page bound to the supplied collection and snapshot."""

    snapshot_id = snapshot or snapshot_fingerprint(items)
    start, expires_at = _cursor_position(
        cursor,
        scope=cursor_scope,
        snapshot=snapshot_id,
        ttl_seconds=cursor_ttl_seconds,
        now=_now,
    )
    if cursor is None or cursor == "":
        if initial_offset < 0:
            raise ValueError("initial_offset must be non-negative")
        start = initial_offset
    size = page_size_or_default(
        page_size,
        default=default_page_size,
        maximum=max_page_size,
    )
    total_count = len(items)
    end = min(total_count, start + size)
    page = list(items[start:end]) if start < total_count else []
    return page, pagination_metadata(
        start=start,
        end=end,
        total_count=total_count,
        page_size=size,
        cursor_scope=cursor_scope,
        snapshot=snapshot_id,
        expires_at=expires_at,
    )


def paginate_range(
    total_count: int,
    *,
    cursor: str | None,
    page_size: int | None,
    default_page_size: int,
    max_page_size: int,
    cursor_scope: str,
    snapshot: str,
    cursor_ttl_seconds: int = CURSOR_TTL_SECONDS,
    _now: float | None = None,
) -> tuple[int, int, dict[str, Any]]:
    """Return a range bound to an externally managed snapshot identity."""

    start, expires_at = _cursor_position(
        cursor,
        scope=cursor_scope,
        snapshot=snapshot,
        ttl_seconds=cursor_ttl_seconds,
        now=_now,
    )
    size = page_size_or_default(
        page_size,
        default=default_page_size,
        maximum=max_page_size,
    )
    end = min(total_count, start + size)
    return start, end, pagination_metadata(
        start=start,
        end=end,
        total_count=total_count,
        page_size=size,
        cursor_scope=cursor_scope,
        snapshot=snapshot,
        expires_at=expires_at,
    )


def paginate_text_lines(
    text: str,
    *,
    cursor: str | None,
    page_size: int | None,
    default_page_size: int,
    max_page_size: int,
    cursor_scope: str,
    snapshot: str | None = None,
    cursor_ttl_seconds: int = CURSOR_TTL_SECONDS,
    _now: float | None = None,
) -> tuple[list[str], dict[str, Any]]:
    """Page text by lines using an opaque snapshot-bound cursor."""

    return paginate_items(
        text.splitlines(),
        cursor=cursor,
        page_size=page_size,
        default_page_size=default_page_size,
        max_page_size=max_page_size,
        cursor_scope=cursor_scope,
        snapshot=snapshot,
        cursor_ttl_seconds=cursor_ttl_seconds,
        _now=_now,
    )
