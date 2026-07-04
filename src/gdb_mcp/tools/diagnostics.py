"""Diagnostic and capability MCP tools."""

from __future__ import annotations

import asyncio
import shutil
import time
from collections.abc import Awaitable, Callable
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..config import ServerConfig
from ..resources import command_reference_index, resource_index, tool_profile
from ..responses import error_response
from ..session import SessionManager

ErrorHandler = Callable[[Exception], dict[str, Any]]
ExecutableVersion = Callable[..., Awaitable[str | None]]

_manager: SessionManager | None = None
_runtime_config: ServerConfig | None = None
_error_handler: ErrorHandler | None = None
_executable_version: ExecutableVersion | None = None


def configure(
    *,
    manager: SessionManager,
    runtime_config: ServerConfig,
    error: ErrorHandler,
    executable_version: ExecutableVersion,
) -> None:
    """Inject shared server dependencies used by this tool group."""

    global _manager, _runtime_config, _error_handler, _executable_version
    _manager = manager
    _runtime_config = runtime_config
    _error_handler = error
    _executable_version = executable_version


def register_tools(
    mcp: FastMCP[Any],
    *,
    read_only: ToolAnnotations,
    session_mutation: ToolAnnotations,
) -> None:
    """Register diagnostic tools on the provided MCP server."""

    mcp.tool(annotations=read_only)(gdb_recent_events)
    mcp.tool(annotations=read_only)(gdb_recent_commands)
    mcp.tool(annotations=read_only)(gdb_session_diagnostics)
    mcp.tool(annotations=session_mutation)(gdb_close_idle_sessions)
    mcp.tool(annotations=read_only)(gdb_command_reference)
    mcp.tool(annotations=read_only)(gdb_capabilities)
    mcp.tool(annotations=read_only)(gdb_server_health)


def _require_manager() -> SessionManager:
    if _manager is None:
        raise RuntimeError("diagnostic tools are not configured")
    return _manager


def _require_config() -> ServerConfig:
    if _runtime_config is None:
        raise RuntimeError("diagnostic tools are not configured")
    return _runtime_config


def _error(exc: Exception) -> dict[str, Any]:
    if _error_handler is None:
        return error_response(exc)
    return _error_handler(exc)


async def _version_for(path: str | None, *args: str) -> str | None:
    if _executable_version is None:
        raise RuntimeError("diagnostic tools are not configured")
    return await _executable_version(path, *args)


async def gdb_recent_events(
    session_id: str,
    limit: int = 100,
) -> dict[str, Any]:
    """Return recent MI records, including asynchronous stop and thread events."""

    try:
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        session = await _require_manager().get(session_id)
        return {
            "ok": True,
            "session_id": session_id,
            "events": session.recent_records(limit),
        }
    except Exception as exc:
        return _error(exc)


async def gdb_recent_commands(
    session_id: str,
    limit: int = 100,
) -> dict[str, Any]:
    """Return recent commands sent to GDB for one session."""

    try:
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        session = await _require_manager().get(session_id)
        return {
            "ok": True,
            "session_id": session_id,
            "commands": session.recent_commands(limit),
        }
    except Exception as exc:
        return _error(exc)


async def gdb_session_diagnostics(session_id: str) -> dict[str, Any]:
    """Return diagnostic state for one session."""

    try:
        session = await _require_manager().get(session_id)
        return {
            "ok": True,
            "session": session.describe(),
            "recent_commands": session.recent_commands(20),
            "recent_events": session.recent_records(20),
        }
    except Exception as exc:
        return _error(exc)


async def gdb_close_idle_sessions(max_idle_seconds: float = 3600.0) -> dict[str, Any]:
    """Close live sessions idle for at least max_idle_seconds."""

    try:
        if max_idle_seconds < 0:
            raise ValueError("max_idle_seconds must be non-negative")
        now = time.time()
        session_manager = _require_manager()
        sessions = await session_manager.list()
        closed: list[dict[str, Any]] = []
        for session in sessions:
            idle = now - float(session["last_activity_at"])
            if idle < max_idle_seconds:
                continue
            try:
                result = await session_manager.close(str(session["session_id"]))
                closed.append({"session": session, "result": result, "idle_seconds": idle})
            except Exception as exc:
                closed.append({"session": session, "error": str(exc), "idle_seconds": idle})
        return {"ok": True, "closed": closed, "closed_count": len(closed)}
    except Exception as exc:
        return _error(exc)


async def gdb_command_reference() -> dict[str, Any]:
    """Return a compact index of safe flows and reference resources."""

    return {
        "ok": True,
        **command_reference_index(),
    }


async def gdb_capabilities() -> dict[str, Any]:
    """Return a workflow-oriented capability index for agent tool selection."""

    runtime_config = _require_config()
    return {
        "ok": True,
        "design_notes": [
            {
                "source": "Ipiano/gdb-mcp",
                "url": "https://github.com/Ipiano/gdb-mcp",
                "borrowed": (
                    "Expose a workflow-oriented reference for sessions, threads, "
                    "breakpoints, execution, and data inspection."
                ),
            },
            {
                "source": "signal-slot/mcp-gdb",
                "url": "https://github.com/signal-slot/mcp-gdb",
                "borrowed": (
                    "Keep simple GDB command equivalents visible so agents can map "
                    "natural debugging requests to dedicated tools."
                ),
            },
            {
                "source": "maxholman/mcp-gdbmi",
                "url": "https://github.com/maxholman/mcp-gdbmi",
                "borrowed": (
                    "Treat GDB/MI verbosity as an explicit capability concern and "
                    "steer agents toward compact context tools before raw payloads."
                ),
            },
            {
                "source": "pansila/mcp_server_gdb",
                "url": "https://github.com/pansila/mcp_server_gdb",
                "borrowed": (
                    "Describe concurrent multi-session debugging as a first-class "
                    "server capability."
                ),
            },
        ],
        "session_model": {
            "multi_session": True,
            "explicit_session_id_required": True,
            "max_sessions": runtime_config.max_sessions,
            "recommended_start": ["gdb_create_session", "gdb_list_sessions"],
            "recommended_finish": ["gdb_close_session", "gdb_close_idle_sessions"],
        },
        "resources": resource_index(),
        "tool_profiles": tool_profile(),
        "workflows": {
            "local_program": [
                "gdb_create_session",
                "gdb_set_breakpoint",
                "gdb_run_and_context",
                "gdb_context",
            ],
            "running_process": ["gdb_attach", "gdb_context", "gdb_detach"],
            "core_dump": ["gdb_load_core", "gdb_threads", "gdb_backtrace", "gdb_context"],
            "remote_gdbserver": [
                "gdb_connect_gdbserver",
                "gdb_set_remote_paths",
                "gdb_gdbserver_status",
                "gdb_detach_gdbserver",
            ],
            "managed_gdbserver": [
                "gdb_launch_gdbserver",
                "gdb_gdbserver_status",
                "gdb_detach_gdbserver",
            ],
            "source_debugging": [
                "gdb_source",
                "gdb_find_source",
                "gdb_backtrace",
                "gdb_frame_variables",
            ],
            "binary_analysis": [
                "gdb_pwn_context",
                "gdb_vmmap_structured",
                "gdb_address_info",
                "gdb_rva_info",
                "gdb_nearpc",
                "gdb_telescope",
                "gdb_piebase",
                "gdb_break_rva",
                "gdb_register_context",
                "gdb_symbols",
                "gdb_got",
                "gdb_binary_summary",
                "gdb_checksec",
                "gdb_elf_info",
            ],
            "reverse_debugging": [
                "gdb_start_recording",
                "gdb_reverse_continue_and_context",
                "gdb_reverse_step_and_context",
                "gdb_reverse_next_and_context",
                "gdb_stop_recording",
            ],
            "diagnostics": [
                "gdb_server_health",
                "gdb_session_diagnostics",
                "gdb_recent_commands",
                "gdb_recent_events",
                "gdb_command_reference",
            ],
        },
        "output_strategy": {
            "default_limit_chars": runtime_config.output_limit_chars,
            "prefer_compact_tools": [
                "gdb_run_and_context",
                "gdb_continue_and_context",
                "gdb_step_and_context",
                "gdb_next_and_context",
                "gdb_context",
                "gdb_pwn_context",
            ],
            "raw_payload_escape_hatch": (
                "Set include_raw=true only when compact fields are insufficient."
            ),
            "hex_compaction": "Full hexadecimal strings are normalized to shorter canonical hex.",
        },
        "safety": {
            "unsafe_enabled": runtime_config.allow_unsafe_execute,
            "unsafe_tools": [
                "gdb_execute",
                "gdb_call_function",
                "gdb_set_variable",
                "gdb_write_memory",
                "gdb_breakpoint_commands",
            ],
            "safe_expression_tools_reject_calls_and_mutations": True,
        },
    }


async def gdb_server_health() -> dict[str, Any]:
    """Report server capabilities, safety mode, dependencies, and session count."""

    runtime_config = _require_config()
    try:
        package_version = version("gdb-mcp")
    except PackageNotFoundError:
        package_version = "0+unknown"
    gdb_path = shutil.which("gdb")
    gdbserver_path = shutil.which("gdbserver")
    gdb_version, gdbserver_version = await asyncio.gather(
        _version_for(gdb_path, "--version"),
        _version_for(gdbserver_path, "--version"),
    )
    sessions = await _require_manager().list()
    return {
        "ok": True,
        "name": "gdb-mcp",
        "version": package_version,
        "gdb_available": gdb_path is not None,
        "gdb_path": gdb_path,
        "gdb_version": gdb_version,
        "gdbserver_available": gdbserver_path is not None,
        "gdbserver_path": gdbserver_path,
        "gdbserver_version": gdbserver_version,
        "unsafe_execute_enabled": runtime_config.allow_unsafe_execute,
        "max_sessions": runtime_config.max_sessions,
        "output_limit_chars": runtime_config.output_limit_chars,
        "capability_tool": "gdb_capabilities",
        "session_count": len(sessions),
        "sessions": sessions,
    }
