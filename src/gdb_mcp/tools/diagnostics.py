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
from ..pagination import paginate_items, pagination_metadata
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
    mcp.tool(annotations=read_only)(gdb_export_session_bundle)
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
    cursor: str | None = None,
    page_size: int | None = None,
) -> dict[str, Any]:
    """Return recent MI records, including asynchronous stop and thread events."""

    try:
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        session = await _require_manager().get(session_id)
        all_events = session.recent_records(500)
        if cursor is None and page_size is None:
            events = all_events[-limit:]
            page_start = max(0, len(all_events) - len(events))
            pagination = pagination_metadata(
                start=page_start,
                end=len(all_events),
                total_count=len(all_events),
                page_size=limit,
            )
        else:
            events, pagination = paginate_items(
                all_events,
                cursor=cursor,
                page_size=page_size,
                default_page_size=limit,
                max_page_size=500,
            )
        return {
            "ok": True,
            "session_id": session_id,
            "events": events,
            "event_count": len(events),
            "pagination": pagination,
        }
    except Exception as exc:
        return _error(exc)


async def gdb_recent_commands(
    session_id: str,
    limit: int = 100,
    cursor: str | None = None,
    page_size: int | None = None,
) -> dict[str, Any]:
    """Return recent commands sent to GDB for one session."""

    try:
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        session = await _require_manager().get(session_id)
        all_commands = session.recent_commands(200)
        if cursor is None and page_size is None:
            commands = all_commands[-limit:]
            page_start = max(0, len(all_commands) - len(commands))
            pagination = pagination_metadata(
                start=page_start,
                end=len(all_commands),
                total_count=len(all_commands),
                page_size=limit,
            )
        else:
            commands, pagination = paginate_items(
                all_commands,
                cursor=cursor,
                page_size=page_size,
                default_page_size=limit,
                max_page_size=200,
            )
        return {
            "ok": True,
            "session_id": session_id,
            "commands": commands,
            "command_count": len(commands),
            "pagination": pagination,
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


def _command_family(command: object) -> str | None:
    if not isinstance(command, str):
        return None
    parts = command.split(maxsplit=1)
    return parts[0] if parts else None


def _command_summary(commands: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep chronology useful while excluding commands and their sensitive arguments."""

    return [
        {
            "token": command.get("token"),
            "command_family": _command_family(command.get("mi_command") or command.get("command")),
            "wait_for_stop": command.get("wait_for_stop"),
            "status": command.get("status"),
            "result_class": command.get("result_class"),
            "timed_out": command.get("timed_out", False),
            "interrupted": command.get("interrupted", False),
            "started_at": command.get("started_at"),
            "finished_at": command.get("finished_at"),
            "duration_seconds": command.get("duration_seconds"),
            "record_count": command.get("record_count", 0),
            "error_present": bool(command.get("error")),
        }
        for command in commands
    ]


def _event_summary(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return MI chronology metadata without raw records, values, or stream text."""

    summaries: list[dict[str, Any]] = []
    for record in records:
        results = record.get("results")
        summaries.append(
            {
                "kind": record.get("kind"),
                "token": record.get("token"),
                "record_class": record.get("class"),
                "stream": record.get("stream"),
                "result_keys": sorted(results) if isinstance(results, dict) else [],
            }
        )
    return summaries


def _last_stop_summary(last_stop: object) -> dict[str, Any] | None:
    if not isinstance(last_stop, dict):
        return None
    frame = last_stop.get("frame")
    frame_summary = None
    if isinstance(frame, dict):
        frame_summary = {
            key: frame.get(key)
            for key in ("level", "func", "line", "addr")
            if key in frame
        }
    return {
        "reason": last_stop.get("reason"),
        "thread_id": last_stop.get("thread-id"),
        "frame": frame_summary,
    }


async def _breakpoint_summary(session: Any) -> dict[str, Any]:
    """Read a minimal active-breakpoint inventory without exposing locations."""

    result = await session.execute("-break-list", timeout=2.0)
    if result.error is not None or result.result_record is None:
        return {"available": False, "count": 0, "breakpoints": []}

    table = result.result_record.results.get("BreakpointTable")
    body = table.get("body") if isinstance(table, dict) else []
    if isinstance(body, dict):
        body = [body]
    if not isinstance(body, list):
        body = []
    breakpoints = [
        {
            "number": item.get("number"),
            "type": item.get("type"),
            "enabled": item.get("enabled"),
            "disposition": item.get("disp"),
            "hit_count": item.get("times"),
        }
        for item in body
        if isinstance(item, dict)
    ]
    return {
        "available": True,
        "count": len(breakpoints),
        "breakpoints": breakpoints,
    }


async def gdb_export_session_bundle(
    session_id: str,
    command_limit: int = 100,
    event_limit: int = 100,
    include_raw: bool = False,
) -> dict[str, Any]:
    """Export a redacted, reproducible diagnostic bundle for one live session.

    ``include_raw`` can expose evaluated values and command arguments, so it is
    available only when the server was explicitly started in unsafe mode.
    """

    try:
        if not 1 <= command_limit <= 200:
            raise ValueError("command_limit must be between 1 and 200")
        if not 1 <= event_limit <= 500:
            raise ValueError("event_limit must be between 1 and 500")
        if include_raw and not _require_config().allow_unsafe_execute:
            raise PermissionError("include_raw requires --unsafe or GDB_MCP_ALLOW_UNSAFE=1")

        session = await _require_manager().get(session_id)
        commands = session.recent_commands(command_limit)
        events = session.recent_records(event_limit)
        description = session.describe()
        gdb_version = await _version_for(session.gdb_path, "--version")
        bundle: dict[str, Any] = {
            "schema_version": 1,
            "exported_at": time.time(),
            "session": {
                "session_id": session.session_id,
                "gdb_path": session.gdb_path,
                "program": session.program,
                "cwd": session.cwd,
                "rr_trace_present": session.rr_trace_dir is not None,
                "state": description["state"],
                "alive": description["alive"],
                "created_at": description["created_at"],
                "last_activity_at": description["last_activity_at"],
                "last_stop": _last_stop_summary(description["last_stop"]),
            },
            "gdb_version": gdb_version,
            "breakpoints": await _breakpoint_summary(session),
            "command_summary": _command_summary(commands),
            "event_chronology": _event_summary(events),
            "redaction": {
                "raw_included": include_raw,
                "excluded_by_default": [
                    "inferior arguments",
                    "environment variables",
                    "raw commands",
                    "MI record text and values",
                    "stream output",
                    "error messages",
                ],
            },
        }
        if include_raw:
            bundle["raw"] = {
                "session": description,
                "recent_commands": commands,
                "recent_events": events,
            }
        return {"ok": True, "session_id": session_id, "bundle": bundle}
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
        "dependencies": {
            "required": {
                "gdb": {
                    "tools": [
                        "gdb_create_session",
                        "gdb_attach",
                        "gdb_load_core",
                        "gdb_run_and_context",
                        "gdb_context",
                    ],
                },
            },
            "optional": {
                "gdbserver": {
                    "tools": [
                        "gdb_connect_gdbserver",
                        "gdb_launch_gdbserver",
                        "gdb_gdbserver_status",
                    ],
                },
                "rr": {
                    "tools": ["gdb_rr_record", "gdb_start_rr_replay_session"],
                },
            },
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
                "gdb_rr_record",
                "gdb_start_rr_replay_session",
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
            "profiles": {
                "summary": "Short bounded summary and counts.",
                "structured": "Default parsed data without duplicate raw command text.",
                "raw": "Include raw MI/readelf payloads where available.",
            },
            "prefer_compact_tools": [
                "gdb_run_and_context",
                "gdb_continue_and_context",
                "gdb_step_and_context",
                "gdb_next_and_context",
                "gdb_context",
                "gdb_pwn_context",
            ],
            "raw_payload_escape_hatch": (
                "Set output='raw' or legacy include_raw=true only when compact fields "
                "are insufficient."
            ),
            "profiled_tools": [
                "gdb_context",
                "gdb_backtrace",
                "gdb_locals",
                "gdb_stack_arguments",
                "gdb_frame_variables",
                "gdb_read_memory",
                "gdb_search_memory",
                "gdb_read_c_string",
                "gdb_memory_mappings",
                "gdb_vmmap_structured",
                "gdb_telescope",
                "gdb_pwn_context",
                "gdb_checksec",
                "gdb_elf_info",
                "gdb_symbols",
                "gdb_got",
                "gdb_binary_summary",
            ],
            "pagination": {
                "cursor_format": "non-negative decimal offset",
                "fields": ["cursor", "page_size", "pagination.next_cursor"],
                "tools": [
                    "gdb_symbols",
                    "gdb_got",
                    "gdb_read_memory",
                    "gdb_thread_apply_all_backtrace",
                    "gdb_memory_mappings",
                    "gdb_vmmap_structured",
                    "gdb_recent_commands",
                    "gdb_recent_events",
                ],
            },
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
    rr_path = shutil.which("rr")
    gdb_version, gdbserver_version, rr_version = await asyncio.gather(
        _version_for(gdb_path, "--version"),
        _version_for(gdbserver_path, "--version"),
        _version_for(rr_path, "--version"),
    )
    sessions = await _require_manager().list()
    return {
        "ok": True,
        "name": "gdb-mcp",
        "version": package_version,
        "gdb_available": gdb_path is not None,
        "gdb_path": gdb_path,
        "gdb_version": gdb_version,
        "required_dependencies": {
            "gdb": {
                "available": gdb_path is not None,
                "path": gdb_path,
                "version": gdb_version,
            },
        },
        "optional_dependencies": {
            "gdbserver": {
                "available": gdbserver_path is not None,
                "path": gdbserver_path,
                "version": gdbserver_version,
                "tools": [
                    "gdb_connect_gdbserver",
                    "gdb_launch_gdbserver",
                    "gdb_gdbserver_status",
                ],
            },
            "rr": {
                "available": rr_path is not None,
                "path": rr_path,
                "version": rr_version,
                "tools": ["gdb_rr_record", "gdb_start_rr_replay_session"],
            },
        },
        "gdbserver_available": gdbserver_path is not None,
        "gdbserver_path": gdbserver_path,
        "gdbserver_version": gdbserver_version,
        "rr_available": rr_path is not None,
        "rr_path": rr_path,
        "rr_version": rr_version,
        "unsafe_execute_enabled": runtime_config.allow_unsafe_execute,
        "max_sessions": runtime_config.max_sessions,
        "output_limit_chars": runtime_config.output_limit_chars,
        "capability_tool": "gdb_capabilities",
        "session_count": len(sessions),
        "sessions": sessions,
    }
