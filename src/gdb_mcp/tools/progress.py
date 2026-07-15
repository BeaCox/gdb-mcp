"""Bounded MCP progress reporting for long-running debugger operations."""

from __future__ import annotations

from mcp.server.fastmcp import Context


async def report_progress(
    context: Context | None,
    progress: float,
    message: str,
) -> None:
    """Emit one optional progress notification when the client requested it."""

    if context is not None:
        await context.report_progress(progress, total=100, message=message)
