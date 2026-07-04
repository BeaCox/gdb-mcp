"""Remote-target MCP tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .execution import gdb_detach
from .shared import (
    _error,
    _gdb_set_string_command,
    _require_single_line,
    _result,
    manager,
)


def register_tools(
    mcp: FastMCP[Any],
    *,
    read_only: ToolAnnotations,
    session_mutation: ToolAnnotations,
    destructive: ToolAnnotations,
) -> None:
    """Register remote-target helper tools."""

    mcp.tool(annotations=session_mutation)(gdb_set_remote_paths)
    mcp.tool(annotations=destructive)(gdb_detach_gdbserver)
    mcp.tool(annotations=read_only)(gdb_gdbserver_status)


async def gdb_set_remote_paths(
    session_id: str,
    sysroot: str | None = None,
    solib_search_path: str | None = None,
) -> dict[str, Any]:
    """Set sysroot and/or solib-search-path for remote debugging."""

    try:
        if sysroot is None and solib_search_path is None:
            raise ValueError("Provide sysroot or solib_search_path")
        session = await manager.get(session_id)
        commands: list[dict[str, Any]] = []
        for name, value in (
            ("sysroot", sysroot),
            ("solib-search-path", solib_search_path),
        ):
            if value is None:
                continue
            _require_single_line(name, value)
            result = await session.execute(
                _gdb_set_string_command(name, value),
                timeout=10.0,
            )
            payload = _result(session, result)
            commands.append(payload)
            if not payload["ok"]:
                return {"ok": False, "session": session.describe(), "commands": commands}
        return {"ok": True, "session": session.describe(), "commands": commands}
    except Exception as exc:
        return _error(exc)


async def gdb_detach_gdbserver(session_id: str, timeout: float = 10.0) -> dict[str, Any]:
    """Detach from a remote target or managed gdbserver."""

    return await gdb_detach(session_id, timeout=timeout)


async def gdb_gdbserver_status(session_id: str) -> dict[str, Any]:
    """Return gdbserver lifecycle details for a session."""

    try:
        session = await manager.get(session_id)
        process = session.gdbserver_process
        return {
            "ok": True,
            "session_id": session_id,
            "gdbserver_endpoint": session.gdbserver_endpoint,
            "gdbserver_pid": process.pid if process else None,
            "gdbserver_returncode": process.returncode if process else None,
            "managed": process is not None,
            "session": session.describe(),
        }
    except Exception as exc:
        return _error(exc)
