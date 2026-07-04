"""Breakpoint and watchpoint MCP tools."""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .shared import (
    _error,
    _require_breakpoint_number,
    _require_cli_target,
    _require_read_expression,
    _require_single_line,
    _require_unsafe_tool,
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
    """Register breakpoint and watchpoint tools."""

    mcp.tool(annotations=session_mutation)(gdb_set_breakpoint)
    mcp.tool(annotations=session_mutation)(gdb_enable_breakpoint)
    mcp.tool(annotations=session_mutation)(gdb_disable_breakpoint)
    mcp.tool(annotations=session_mutation)(gdb_breakpoint_condition)
    mcp.tool(annotations=destructive)(gdb_breakpoint_commands)
    mcp.tool(annotations=destructive)(gdb_delete_breakpoint)
    mcp.tool(annotations=read_only)(gdb_list_breakpoints)
    mcp.tool(annotations=session_mutation)(gdb_set_watchpoint)


async def gdb_set_breakpoint(
    session_id: str,
    location: str,
    condition: str | None = None,
    temporary: bool = False,
    hardware: bool = False,
) -> dict[str, Any]:
    """Set a breakpoint using GDB CLI syntax."""

    try:
        _require_cli_target("location", location)
        if condition is not None:
            _require_read_expression("condition", condition)
        if hardware and temporary:
            prefix = "thbreak"
        elif hardware:
            prefix = "hbreak"
        elif temporary:
            prefix = "tbreak"
        else:
            prefix = "break"
        command = f"{prefix} {location}"
        if condition:
            command += f" if {condition}"
        session = await manager.get(session_id)
        return _result(session, await session.execute(command, timeout=10.0))
    except Exception as exc:
        return _error(exc)


async def gdb_enable_breakpoint(session_id: str, number: str) -> dict[str, Any]:
    """Enable a breakpoint by number."""

    try:
        _require_breakpoint_number(number)
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(f"-break-enable {number}", timeout=10.0),
        )
    except Exception as exc:
        return _error(exc)


async def gdb_disable_breakpoint(session_id: str, number: str) -> dict[str, Any]:
    """Disable a breakpoint by number."""

    try:
        _require_breakpoint_number(number)
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(f"-break-disable {number}", timeout=10.0),
        )
    except Exception as exc:
        return _error(exc)


async def gdb_breakpoint_condition(
    session_id: str,
    number: str,
    condition: str | None = None,
) -> dict[str, Any]:
    """Set or clear a breakpoint condition."""

    try:
        _require_breakpoint_number(number)
        if condition is not None:
            _require_read_expression("condition", condition)
        suffix = f" {condition}" if condition else ""
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(f"condition {number}{suffix}", timeout=10.0),
        )
    except Exception as exc:
        return _error(exc)


async def gdb_breakpoint_commands(
    session_id: str,
    number: str,
    commands: list[str],
) -> dict[str, Any]:
    """Set breakpoint command-list actions. Requires unsafe mode."""

    try:
        _require_unsafe_tool("gdb_breakpoint_commands")
        _require_breakpoint_number(number)
        if not commands:
            raise ValueError("commands must not be empty")
        for command in commands:
            _require_single_line("command", command)
            if not command.strip():
                raise ValueError("commands must not contain empty commands")
        session = await manager.get(session_id)
        script = "\n".join(["commands " + number, *commands, "end"])
        return _result(session, await session.execute(script, timeout=10.0))
    except Exception as exc:
        return _error(exc)


async def gdb_delete_breakpoint(session_id: str, number: str) -> dict[str, Any]:
    """Delete a breakpoint by number."""

    try:
        _require_breakpoint_number(number)
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(f"-break-delete {number}", timeout=10.0),
        )
    except Exception as exc:
        return _error(exc)


async def gdb_list_breakpoints(session_id: str) -> dict[str, Any]:
    """List breakpoints as structured MI data."""

    try:
        session = await manager.get(session_id)
        return _result(session, await session.execute("-break-list", timeout=10.0))
    except Exception as exc:
        return _error(exc)


async def gdb_set_watchpoint(
    session_id: str,
    expression: str,
    access: str = "write",
) -> dict[str, Any]:
    """Set a watchpoint for a read-safe expression."""

    try:
        _require_read_expression("expression", expression)
        commands = {
            "write": "watch",
            "read": "rwatch",
            "access": "awatch",
        }
        command = commands.get(access)
        if command is None:
            raise ValueError("access must be one of: write, read, access")
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(f"{command} {expression}", timeout=10.0),
        )
    except Exception as exc:
        return _error(exc)
