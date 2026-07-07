"""Session lifecycle and gdbserver connection tools."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..responses import error_response
from ..session import (
    GdbSession,
    SessionManager,
    gdbserver_target_endpoint,
    launch_gdbserver,
)

ErrorHandler = Callable[[Exception], dict[str, Any]]
MiWordValidator = Callable[[str, str], None]

_manager: SessionManager | None = None
_error_handler: ErrorHandler | None = None
_require_mi_word: MiWordValidator | None = None


def configure(
    *,
    manager: SessionManager,
    error: ErrorHandler,
    require_mi_word: MiWordValidator,
) -> None:
    """Inject shared server dependencies used by this tool group."""

    global _manager, _error_handler, _require_mi_word
    _manager = manager
    _error_handler = error
    _require_mi_word = require_mi_word


def register_tools(
    mcp: FastMCP[Any],
    *,
    read_only: ToolAnnotations,
    session_mutation: ToolAnnotations,
    target_execution: ToolAnnotations,
    destructive: ToolAnnotations,
) -> None:
    """Register session lifecycle tools on the provided MCP server."""

    mcp.tool(annotations=session_mutation)(gdb_create_session)
    mcp.tool(annotations=session_mutation)(gdb_connect_gdbserver)
    mcp.tool(annotations=target_execution)(gdb_launch_gdbserver)
    mcp.tool(annotations=read_only)(gdb_list_sessions)
    mcp.tool(annotations=read_only)(gdb_status)
    mcp.tool(annotations=destructive)(gdb_close_session)


def _require_manager() -> SessionManager:
    if _manager is None:
        raise RuntimeError("session lifecycle tools are not configured")
    return _manager


def _error(exc: Exception) -> dict[str, Any]:
    if _error_handler is None:
        return error_response(exc)
    return _error_handler(exc)


def _validate_mi_word(name: str, value: str) -> None:
    if _require_mi_word is None:
        raise RuntimeError("session lifecycle tools are not configured")
    _require_mi_word(name, value)


async def _terminate_process(process: asyncio.subprocess.Process | None) -> None:
    if process is None or process.returncode is not None:
        return
    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()


async def gdb_create_session(
    program: str | None = None,
    args: list[str] | None = None,
    cwd: str | None = None,
    gdb_path: str = "gdb",
    startup_timeout: float = 10.0,
) -> dict[str, Any]:
    """Create an isolated GDB session and optionally load a program."""

    try:
        session = await _require_manager().create(
            gdb_path=gdb_path,
            program=program,
            args=args,
            cwd=cwd,
            startup_timeout=startup_timeout,
        )
        return {"ok": True, "session": session.describe()}
    except Exception as exc:
        return _error(exc)


async def gdb_connect_gdbserver(
    endpoint: str,
    session_id: str | None = None,
    program: str | None = None,
    cwd: str | None = None,
    gdb_path: str = "gdb",
    extended: bool = True,
    sysroot: str | None = None,
    solib_search_path: str | None = None,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Connect a session to an existing gdbserver endpoint."""

    manager = _require_manager()
    created_session = False
    session: GdbSession | None = None

    async def close_created_session() -> None:
        if created_session and session is not None:
            try:
                await manager.close(session.session_id)
            except Exception:
                await session.close()

    try:
        _validate_mi_word("endpoint", endpoint)
        if session_id:
            session = await manager.get(session_id)
        else:
            session = await manager.create(
                gdb_path=gdb_path,
                program=program,
                cwd=cwd,
                startup_timeout=timeout,
            )
            created_session = True
        result = await session.connect_gdbserver(
            endpoint,
            extended=extended,
            timeout=timeout,
            sysroot=sysroot,
            solib_search_path=solib_search_path,
        )
        if not result["ok"] and created_session:
            await manager.close(session.session_id)
            return {
                "ok": False,
                "error": "Failed to connect to gdbserver; the new session was closed",
                "command": result,
            }
        return {"ok": result["ok"], "session": session.describe(), "command": result}
    except asyncio.CancelledError:
        await close_created_session()
        raise
    except Exception as exc:
        await close_created_session()
        return _error(exc)


async def gdb_launch_gdbserver(
    program: str,
    listen: str = "localhost:2345",
    target_endpoint: str | None = None,
    args: list[str] | None = None,
    cwd: str | None = None,
    gdb_path: str = "gdb",
    gdbserver_path: str = "gdbserver",
    extended: bool = False,
    sysroot: str | None = None,
    solib_search_path: str | None = None,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Launch a local gdbserver and connect a new GDB session to it."""

    manager = _require_manager()
    gdbserver_process: asyncio.subprocess.Process | None = None
    session: GdbSession | None = None
    try:
        gdbserver_process, banner, drain_task = await launch_gdbserver(
            program=program,
            listen=listen,
            args=args,
            cwd=cwd,
            gdbserver_path=gdbserver_path,
            startup_timeout=min(timeout, 5.0),
        )
        session = await manager.create(
            gdb_path=gdb_path,
            program=program,
            cwd=cwd,
            startup_timeout=timeout,
        )
        session.gdbserver_process = gdbserver_process
        session.gdbserver_drain_task = drain_task
        target = target_endpoint or gdbserver_target_endpoint(listen, banner)
        result = await session.connect_gdbserver(
            target,
            extended=extended,
            timeout=timeout,
            sysroot=sysroot,
            solib_search_path=solib_search_path,
        )
        if not result["ok"]:
            await manager.close(session.session_id)
            return {
                "ok": False,
                "error": "Launched gdbserver but GDB could not connect; both were closed",
                "gdbserver_output": banner.strip(),
                "command": result,
            }
        return {
            "ok": result["ok"],
            "session": session.describe(),
            "gdbserver_output": banner.strip(),
            "command": result,
        }
    except Exception as exc:
        if session is not None:
            try:
                await manager.close(session.session_id)
            except Exception:
                await session.close()
        else:
            await _terminate_process(gdbserver_process)
        return _error(exc)


async def gdb_list_sessions() -> dict[str, Any]:
    """List active GDB sessions."""

    return {"ok": True, "sessions": await _require_manager().list()}


async def gdb_status(session_id: str) -> dict[str, Any]:
    """Return one session's status."""

    try:
        session = await _require_manager().get(session_id)
        return {"ok": True, "session": session.describe()}
    except Exception as exc:
        return _error(exc)


async def gdb_close_session(session_id: str) -> dict[str, Any]:
    """Close a GDB session and any child gdbserver process."""

    try:
        return {"ok": True, **await _require_manager().close(session_id)}
    except Exception as exc:
        return _error(exc)
