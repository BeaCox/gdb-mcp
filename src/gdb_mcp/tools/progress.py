"""Bounded MCP progress reporting for long-running debugger operations."""

from __future__ import annotations

from mcp.server.mcpserver import Context


def _progress_enabled() -> bool:
    from .shared import require_runtime_config

    try:
        return bool(require_runtime_config().progress_notifications)
    except RuntimeError:
        return False


async def report_progress(
    context: Context | None,
    progress: float,
    message: str,
) -> None:
    """Emit one optional progress notification when requested and enabled."""

    if context is not None and _progress_enabled():
        await context.report_progress(progress, total=100, message=message)
