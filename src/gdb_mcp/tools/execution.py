"""Execution and target-control MCP tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..mi import c_escape
from ..session import GdbMcpError
from .shared import (
    _error,
    _require_cli_target,
    _require_single_line,
    _result,
    manager,
    runtime_config,
)


def register_tools(
    mcp: FastMCP[Any],
    *,
    read_only: ToolAnnotations,
    session_mutation: ToolAnnotations,
    target_execution: ToolAnnotations,
    destructive: ToolAnnotations,
) -> None:
    """Register execution and target-control tools."""

    mcp.tool(annotations=target_execution)(gdb_attach)
    mcp.tool(annotations=session_mutation)(gdb_load_core)
    mcp.tool(annotations=target_execution)(gdb_execute)
    mcp.tool(annotations=target_execution)(gdb_run)
    mcp.tool(annotations=target_execution)(gdb_continue)
    mcp.tool(annotations=target_execution)(gdb_restart)
    mcp.tool(annotations=target_execution)(gdb_interrupt)
    mcp.tool(annotations=target_execution)(gdb_signal)
    mcp.tool(annotations=destructive)(gdb_detach)
    mcp.tool(annotations=destructive)(gdb_kill)
    mcp.tool(annotations=target_execution)(gdb_step)
    mcp.tool(annotations=target_execution)(gdb_next)
    mcp.tool(annotations=session_mutation)(gdb_start_recording)
    mcp.tool(annotations=session_mutation)(gdb_stop_recording)
    mcp.tool(annotations=read_only)(gdb_record_status)
    mcp.tool(annotations=target_execution)(gdb_reverse_continue)
    mcp.tool(annotations=target_execution)(gdb_reverse_step)
    mcp.tool(annotations=target_execution)(gdb_reverse_next)
    mcp.tool(annotations=target_execution)(gdb_reverse_finish)


async def gdb_attach(
    pid: int,
    session_id: str | None = None,
    program: str | None = None,
    cwd: str | None = None,
    gdb_path: str = "gdb",
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Attach GDB to an existing local process."""

    created_session = False
    try:
        if pid <= 0:
            raise ValueError("pid must be a positive integer")
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
        result = await session.execute(
            f"-target-attach {pid}",
            timeout=timeout,
            wait_for_stop=True,
        )
        payload = _result(session, result)
        if not payload["ok"] and created_session:
            await manager.close(session.session_id)
            return {
                "ok": False,
                "error": "Failed to attach; the new session was closed",
                "command": payload,
            }
        return {"ok": payload["ok"], "session": session.describe(), "command": payload}
    except Exception as exc:
        return _error(exc)


async def gdb_load_core(
    core_path: str,
    session_id: str | None = None,
    program: str | None = None,
    cwd: str | None = None,
    gdb_path: str = "gdb",
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Load a core dump into a GDB session."""

    created_session = False
    try:
        _require_cli_target("core_path", core_path)
        if program is not None:
            _require_single_line("program", program)
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
        result = await session.execute(
            f"target core {core_path}",
            timeout=timeout,
        )
        payload = _result(session, result)
        if not payload["ok"] and created_session:
            await manager.close(session.session_id)
            return {
                "ok": False,
                "error": "Failed to load core; the new session was closed",
                "command": payload,
            }
        if payload["ok"]:
            session.state = "stopped"
        return {"ok": payload["ok"], "session": session.describe(), "command": payload}
    except Exception as exc:
        return _error(exc)


async def gdb_execute(
    session_id: str,
    command: str,
    timeout: float = 15.0,
    wait_for_stop: bool = False,
    auto_interrupt: bool = False,
) -> dict[str, Any]:
    """Execute an unrestricted CLI or raw MI command when unsafe mode is enabled."""

    try:
        if not runtime_config.allow_unsafe_execute:
            raise GdbMcpError(
                "gdb_execute is disabled by default because arbitrary GDB commands "
                "can call functions, write memory, or execute shell commands. "
                "Restart gdb-mcp with --unsafe or GDB_MCP_ALLOW_UNSAFE=1."
            )
        session = await manager.get(session_id)
        result = await session.execute(
            command,
            timeout=timeout,
            wait_for_stop=wait_for_stop,
            auto_interrupt=auto_interrupt,
        )
        return _result(session, result)
    except Exception as exc:
        return _error(exc)


async def gdb_run(
    session_id: str,
    args: list[str] | None = None,
    timeout: float = 30.0,
    auto_interrupt: bool = True,
) -> dict[str, Any]:
    """Run or restart the inferior and wait until it stops."""

    try:
        session = await manager.get(session_id)
        if args:
            encoded_args = " ".join(c_escape(arg) for arg in args)
            args_result = await session.execute(
                f"-exec-arguments {encoded_args}",
                timeout=3.0,
            )
            if not _result(session, args_result)["ok"]:
                return _result(session, args_result)
        result = await session.execute(
            "-exec-run",
            timeout=timeout,
            wait_for_stop=True,
            auto_interrupt=auto_interrupt,
        )
        return _result(session, result)
    except Exception as exc:
        return _error(exc)


async def gdb_continue(
    session_id: str,
    timeout: float = 30.0,
    auto_interrupt: bool = True,
) -> dict[str, Any]:
    """Continue execution and wait until the target stops."""

    try:
        session = await manager.get(session_id)
        result = await session.execute(
            "-exec-continue",
            timeout=timeout,
            wait_for_stop=True,
            auto_interrupt=auto_interrupt,
        )
        return _result(session, result)
    except Exception as exc:
        return _error(exc)


async def gdb_restart(
    session_id: str,
    args: list[str] | None = None,
    timeout: float = 30.0,
    auto_interrupt: bool = True,
) -> dict[str, Any]:
    """Restart the inferior and wait until it stops."""

    return await gdb_run(
        session_id,
        args=args,
        timeout=timeout,
        auto_interrupt=auto_interrupt,
    )


async def gdb_interrupt(session_id: str, timeout: float = 5.0) -> dict[str, Any]:
    """Interrupt a running target."""

    try:
        session = await manager.get(session_id)
        return _result(session, await session.interrupt(timeout=timeout))
    except Exception as exc:
        return _error(exc)


async def gdb_signal(
    session_id: str,
    signal_name: str,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Resume the inferior with a signal such as SIGTERM or 0."""

    try:
        _require_cli_target("signal_name", signal_name)
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(
                f"signal {signal_name}",
                timeout=timeout,
                wait_for_stop=True,
            ),
        )
    except Exception as exc:
        return _error(exc)


async def gdb_detach(session_id: str, timeout: float = 10.0) -> dict[str, Any]:
    """Detach GDB from the current target while keeping the session alive."""

    try:
        session = await manager.get(session_id)
        result = await session.execute("-target-detach", timeout=timeout)
        payload = _result(session, result)
        if payload["ok"]:
            session.state = "ready"
            session.gdbserver_endpoint = None
        return payload
    except Exception as exc:
        return _error(exc)


async def gdb_kill(session_id: str, timeout: float = 10.0) -> dict[str, Any]:
    """Kill the current inferior while keeping the GDB session alive."""

    try:
        session = await manager.get(session_id)
        result = await session.execute("kill", timeout=timeout)
        payload = _result(session, result)
        if payload["ok"]:
            session.state = "ready"
        return payload
    except Exception as exc:
        return _error(exc)


async def gdb_step(
    session_id: str,
    instruction: bool = False,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Step into one source line or machine instruction."""

    try:
        command = "-exec-step-instruction" if instruction else "-exec-step"
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(command, timeout=timeout, wait_for_stop=True),
        )
    except Exception as exc:
        return _error(exc)


async def gdb_next(
    session_id: str,
    instruction: bool = False,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Step over one source line or machine instruction."""

    try:
        command = "-exec-next-instruction" if instruction else "-exec-next"
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(command, timeout=timeout, wait_for_stop=True),
        )
    except Exception as exc:
        return _error(exc)


async def gdb_start_recording(
    session_id: str,
    method: str = "full",
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Enable GDB process recording for reverse debugging."""

    try:
        commands = {
            "full": "target record-full",
            "btrace": "target record-btrace",
        }
        command = commands.get(method)
        if command is None:
            raise ValueError("method must be one of: full, btrace")
        session = await manager.get(session_id)
        return _result(session, await session.execute(command, timeout=timeout))
    except Exception as exc:
        return _error(exc)


async def gdb_stop_recording(session_id: str, timeout: float = 10.0) -> dict[str, Any]:
    """Stop GDB process recording when a recording target is active."""

    try:
        session = await manager.get(session_id)
        return _result(session, await session.execute("record stop", timeout=timeout))
    except Exception as exc:
        return _error(exc)


async def gdb_record_status(session_id: str) -> dict[str, Any]:
    """Return GDB recording status."""

    try:
        session = await manager.get(session_id)
        return _result(session, await session.execute("info record", timeout=10.0))
    except Exception as exc:
        return _error(exc)


async def gdb_reverse_continue(
    session_id: str,
    timeout: float = 30.0,
    auto_interrupt: bool = True,
) -> dict[str, Any]:
    """Run backward until the target stops."""

    try:
        session = await manager.get(session_id)
        result = await session.execute(
            "reverse-continue",
            timeout=timeout,
            wait_for_stop=True,
            auto_interrupt=auto_interrupt,
        )
        return _result(session, result)
    except Exception as exc:
        return _error(exc)


async def gdb_reverse_step(
    session_id: str,
    instruction: bool = False,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Step backward into one source line or machine instruction."""

    try:
        command = "reverse-stepi" if instruction else "reverse-step"
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(command, timeout=timeout, wait_for_stop=True),
        )
    except Exception as exc:
        return _error(exc)


async def gdb_reverse_next(
    session_id: str,
    instruction: bool = False,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Step backward over one source line or machine instruction."""

    try:
        command = "reverse-nexti" if instruction else "reverse-next"
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(command, timeout=timeout, wait_for_stop=True),
        )
    except Exception as exc:
        return _error(exc)


async def gdb_reverse_finish(
    session_id: str,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Run backward to the call site of the selected frame."""

    try:
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute("reverse-finish", timeout=timeout, wait_for_stop=True),
        )
    except Exception as exc:
        return _error(exc)
