"""Session lifecycle and gdbserver connection tools."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse, urlunparse

from mcp.server.mcpserver import Context, MCPServer
from mcp.types import ToolAnnotations

from ..mi import c_escape
from ..process import terminate_process_group
from ..responses import error_response
from ..session import (
    GdbMcpError,
    GdbSession,
    SessionManager,
    gdbserver_target_endpoint,
    launch_gdbserver,
)
from .progress import report_progress

ErrorHandler = Callable[[Exception], dict[str, Any]]
MiWordValidator = Callable[[str, str], None]
UnsafeToolChecker = Callable[[str], None]

_manager: SessionManager | None = None
_error_handler: ErrorHandler | None = None
_require_mi_word: MiWordValidator | None = None
_require_unsafe_tool: UnsafeToolChecker | None = None


def configure(
    *,
    manager: SessionManager,
    error: ErrorHandler,
    require_mi_word: MiWordValidator,
    require_unsafe_tool: UnsafeToolChecker,
) -> None:
    """Inject shared server dependencies used by this tool group."""

    global _manager, _error_handler, _require_mi_word, _require_unsafe_tool
    _manager = manager
    _error_handler = error
    _require_mi_word = require_mi_word
    _require_unsafe_tool = require_unsafe_tool


def register_tools(
    mcp: MCPServer[Any],
    *,
    read_only: ToolAnnotations,
    session_mutation: ToolAnnotations,
    target_execution: ToolAnnotations,
    destructive: ToolAnnotations,
) -> None:
    """Register session lifecycle tools on the provided MCP server."""

    mcp.tool(annotations=session_mutation)(gdb_create_session)
    mcp.tool(annotations=session_mutation)(gdb_connect_gdbserver)
    mcp.tool(annotations=session_mutation)(gdb_apply_init_profile)
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


def _require_unsafe(name: str) -> None:
    if _require_unsafe_tool is None:
        raise RuntimeError("session lifecycle tools are not configured")
    _require_unsafe_tool(name)


def _require_single_line(name: str, value: str) -> None:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\n" in value
        or "\r" in value
        or "\0" in value
    ):
        raise ValueError(f"{name} must be a non-empty single-line string")


def _validate_debuginfod_url(url: str) -> str:
    _require_single_line("debuginfod_urls entry", url)
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("debuginfod_urls entries must be http:// or https:// URLs")
    return url.strip()


def _sanitize_url_for_record(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    return urlunparse((parsed.scheme, netloc, parsed.path, "", "", ""))


async def _apply_profile_command(
    session: GdbSession,
    command: str,
    timeout: float,
) -> dict[str, Any]:
    result = await session.execute(command, timeout=timeout)
    payload = result.to_dict(session.output_limit_chars)
    if not payload["ok"]:
        raise GdbMcpError(payload["error"] or f"GDB initialization command failed: {command}")
    return payload


async def _terminate_process(process: asyncio.subprocess.Process | None) -> None:
    if process is None or process.returncode is not None:
        return
    await terminate_process_group(process, process.pid, timeout=2.0)


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


async def gdb_apply_init_profile(
    session_id: str,
    profile: str,
    source_directories: list[str] | None = None,
    sysroot: str | None = None,
    solib_search_path: str | None = None,
    substitute_paths: dict[str, str] | None = None,
    debug_file_directories: list[str] | None = None,
    debuginfod_enabled: bool | None = None,
    debuginfod_urls: list[str] | None = None,
    init_file: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Apply and record a named initialization profile for an existing session.

    ``source_paths``, ``remote_paths``, and ``debug_info`` only alter GDB lookup
    configuration. ``init_file`` runs GDB's ``source`` command and is therefore
    available only when unsafe mode is explicitly enabled.
    """

    try:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        session = await _require_manager().get(session_id)
        commands: list[dict[str, Any]] = []
        configuration: dict[str, Any]

        if profile == "source_paths":
            if not source_directories:
                raise ValueError("source_paths requires at least one source_directories entry")
            directories = list(source_directories)
            for directory in directories:
                _require_single_line("source_directories entry", directory)
                commands.append(
                    await _apply_profile_command(
                        session,
                        f"-environment-directory {c_escape(directory)}",
                        timeout,
                    )
                )
            configuration = {"source_directories": directories}
        elif profile == "remote_paths":
            if sysroot is None and solib_search_path is None:
                raise ValueError("remote_paths requires sysroot or solib_search_path")
            for setting, value in (
                ("sysroot", sysroot),
                ("solib-search-path", solib_search_path),
            ):
                if value is None:
                    continue
                _require_single_line(setting, value)
                commands.append(
                    await _apply_profile_command(
                        session,
                        f"-gdb-set {setting} {c_escape(value)}",
                        timeout,
                    )
                )
            configuration = {
                "sysroot": sysroot,
                "solib_search_path": solib_search_path,
            }
        elif profile == "debug_info":
            if (
                not substitute_paths
                and not debug_file_directories
                and debuginfod_enabled is None
                and not debuginfod_urls
            ):
                raise ValueError(
                    "debug_info requires at least one of substitute_paths, "
                    "debug_file_directories, debuginfod_enabled, or debuginfod_urls"
                )
            if debuginfod_urls and debuginfod_enabled is not True:
                raise ValueError(
                    "debuginfod_urls requires debuginfod_enabled=true so remote "
                    "debuginfod lookups remain explicitly opt-in"
                )

            applied_substitutions: dict[str, str] = {}
            for src_prefix, dst_prefix in (substitute_paths or {}).items():
                _require_single_line("substitute_paths source", src_prefix)
                _require_single_line("substitute_paths target", dst_prefix)
                commands.append(
                    await _apply_profile_command(
                        session,
                        f"-gdb-set substitute-path {c_escape(src_prefix)} {c_escape(dst_prefix)}",
                        timeout,
                    )
                )
                applied_substitutions[src_prefix] = dst_prefix

            applied_debug_dirs = list(debug_file_directories or [])
            if applied_debug_dirs:
                for directory in applied_debug_dirs:
                    _require_single_line("debug_file_directories entry", directory)
                joined_dirs = ":".join(applied_debug_dirs)
                commands.append(
                    await _apply_profile_command(
                        session,
                        f"-gdb-set debug-file-directory {c_escape(joined_dirs)}",
                        timeout,
                    )
                )

            sanitized_urls: list[str] = []
            if debuginfod_enabled is not None:
                mode = "on" if debuginfod_enabled else "off"
                try:
                    commands.append(
                        await _apply_profile_command(
                            session,
                            f"-gdb-set debuginfod enabled {mode}",
                            timeout,
                        )
                    )
                except GdbMcpError as exc:
                    raise GdbMcpError(
                        f"{exc}; debuginfod may be unavailable in this GDB build—use "
                        "debug_file_directories or substitute_paths as a local fallback"
                    ) from exc

            if debuginfod_urls:
                validated_urls = [_validate_debuginfod_url(url) for url in debuginfod_urls]
                sanitized_urls = [_sanitize_url_for_record(url) for url in validated_urls]
                try:
                    commands.append(
                        await _apply_profile_command(
                            session,
                            f"-gdb-set debuginfod urls {c_escape(' '.join(validated_urls))}",
                            timeout,
                        )
                    )
                except GdbMcpError as exc:
                    raise GdbMcpError(
                        f"{exc}; symbol server configuration failed—use "
                        "debug_file_directories or substitute_paths as a local fallback"
                    ) from exc

            configuration = {
                "substitute_paths": applied_substitutions,
                "debug_file_directories": applied_debug_dirs,
                "debuginfod_enabled": debuginfod_enabled,
                "debuginfod_urls": sanitized_urls,
            }
        elif profile == "init_file":
            _require_unsafe("gdb_apply_init_profile(profile='init_file')")
            if init_file is None:
                raise ValueError("init_file profile requires init_file")
            _require_single_line("init_file", init_file)
            commands.append(
                await _apply_profile_command(
                    session,
                    f"-interpreter-exec console {c_escape(f'source {init_file}')}",
                    timeout,
                )
            )
            configuration = {"init_file": init_file}
        else:
            raise ValueError(
                "profile must be one of: source_paths, remote_paths, debug_info, init_file"
            )

        session.record_profile(profile, configuration)
        return {
            "ok": True,
            "session": session.describe(),
            "profile": session.applied_profiles[-1],
            "commands": commands,
        }
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
    context: Context | None = None,
) -> dict[str, Any]:
    """Launch a local gdbserver and connect a new GDB session to it."""

    manager = _require_manager()
    gdbserver_process: asyncio.subprocess.Process | None = None
    drain_task: asyncio.Task[None] | None = None
    session: GdbSession | None = None

    async def cleanup_launch() -> None:
        if session is not None:
            try:
                await manager.close(session.session_id)
            except Exception:
                await session.close()
            return
        if drain_task is not None and not drain_task.done():
            drain_task.cancel()
        await _terminate_process(gdbserver_process)
        if drain_task is not None:
            try:
                await drain_task
            except asyncio.CancelledError:
                pass

    try:
        await report_progress(context, 0, "Launching gdbserver")
        gdbserver_process, banner, drain_task = await launch_gdbserver(
            program=program,
            listen=listen,
            args=args,
            cwd=cwd,
            gdbserver_path=gdbserver_path,
            startup_timeout=min(timeout, 5.0),
        )
        await report_progress(context, 40, "gdbserver launched; starting GDB")
        session = await manager.create(
            gdb_path=gdb_path,
            program=program,
            cwd=cwd,
            startup_timeout=timeout,
        )
        session.gdbserver_process = gdbserver_process
        session.gdbserver_pgid = gdbserver_process.pid
        session.gdbserver_drain_task = drain_task
        target = target_endpoint or gdbserver_target_endpoint(listen, banner)
        await report_progress(context, 70, "Connecting GDB to gdbserver")
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
        await report_progress(context, 100, "gdbserver session connected")
        return {
            "ok": result["ok"],
            "session": session.describe(),
            "gdbserver_output": banner.strip(),
            "command": result,
        }
    except asyncio.CancelledError:
        await cleanup_launch()
        raise
    except Exception as exc:
        await cleanup_launch()
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
