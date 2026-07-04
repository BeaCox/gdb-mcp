"""Cursor pagination helpers for bounded tool responses."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, TypeVar

T = TypeVar("T")


def cursor_to_offset(cursor: str | None) -> int:
    """Parse a simple decimal offset cursor."""

    if cursor in {None, ""}:
        return 0
    if not isinstance(cursor, str) or not cursor.isdigit():
        raise ValueError("cursor must be a non-negative decimal offset")
    return int(cursor)


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
) -> dict[str, Any]:
    """Return common pagination metadata for a page."""

    next_cursor = str(end) if end < total_count else None
    return {
        "cursor": str(start),
        "next_cursor": next_cursor,
        "page_size": page_size,
        "page_start": start,
        "page_end": end,
        "total_count": total_count,
        "has_more": next_cursor is not None,
    }


def paginate_items(
    items: Sequence[T],
    *,
    cursor: str | None,
    page_size: int | None,
    default_page_size: int,
    max_page_size: int,
) -> tuple[list[T], dict[str, Any]]:
    """Return one page from a sequence plus cursor metadata."""

    start = cursor_to_offset(cursor)
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
    )


def paginate_range(
    total_count: int,
    *,
    cursor: str | None,
    page_size: int | None,
    default_page_size: int,
    max_page_size: int,
) -> tuple[int, int, dict[str, Any]]:
    """Return a byte/index range for a paged operation."""

    start = cursor_to_offset(cursor)
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
    )


def paginate_text_lines(
    text: str,
    *,
    cursor: str | None,
    page_size: int | None,
    default_page_size: int,
    max_page_size: int,
) -> tuple[list[str], dict[str, Any]]:
    """Page text by lines."""

    return paginate_items(
        text.splitlines(),
        cursor=cursor,
        page_size=page_size,
        default_page_size=default_page_size,
        max_page_size=max_page_size,
    )
