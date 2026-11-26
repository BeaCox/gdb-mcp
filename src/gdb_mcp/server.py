"""MCP tool surface and command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import atexit
import os
import shutil  # noqa: F401 - kept for compatibility with callers patching this module
import signal
import sys
from collections.abc import Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import __version__
from .config import ServerConfig, _env_bool
from .http_security import HTTP_TRANSPORTS, configure_http_security
from .observability import logger, parse_log_level
from .process import set_pdeathsig
from .prompts import register_prompts
from .resources import register_resources
from .session import CommandResult, GdbMcpError, GdbSession, SessionManager, _truncate_text
from .tool_profiles import parse_tool_names, parse_tool_selection
from .tools import binary as _binary_tools
from .tools import breakpoints as _breakpoint_tools
from .tools import diagnostics as _diagnostics_tools
from .tools import execution as _execution_tools
from .tools import inspection as _inspection_tools
from .tools import remote as _remote_tools
from .tools import session as _session_tools
from .tools import shared as _shared_tools

_COMPAT_EXPORTS = (CommandResult, GdbMcpError, GdbSession, _truncate_text)

_env_config_error: ValueError | None = None
try:
    runtime_config = ServerConfig.from_env()
except ValueError as exc:
    _env_config_error = exc
    runtime_config = ServerConfig()
logger.set_level(runtime_config.log_level)
manager = SessionManager(
    max_sessions=runtime_config.max_sessions,
    output_limit_chars=runtime_config.output_limit_chars,
    idle_session_ttl_seconds=runtime_config.idle_session_ttl_seconds,
    max_recent_records=runtime_config.max_recent_records,
    max_recent_commands=runtime_config.max_recent_commands,
)
_shared_tools.configure(manager=manager, runtime_config=runtime_config)


@asynccontextmanager
async def _lifespan(_: MCPServer[Any]):
    manager.start_reaper()
    try:
        yield
    finally:
        await manager.close_all()


mcp = MCPServer(
    "gdb-mcp",
    instructions=(
        "Create an explicit GDB session before debugging. Prefer the dedicated "
        "inspection and execution tools. Raw gdb_execute is disabled unless the "
        "server is launched with --unsafe."
    ),
    lifespan=_lifespan,
)

READ_ONLY = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)
SESSION_MUTATION = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=False,
    openWorldHint=True,
)
TARGET_EXECUTION = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)
DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=True,
    openWorldHint=False,
)

_error = _shared_tools._error
_result = _shared_tools._result
_run_readelf = _binary_tools._run_readelf
gdb_close_session = _session_tools.gdb_close_session
gdb_connect_gdbserver = _session_tools.gdb_connect_gdbserver
gdb_create_session = _session_tools.gdb_create_session
gdb_apply_init_profile = _session_tools.gdb_apply_init_profile
gdb_launch_gdbserver = _session_tools.gdb_launch_gdbserver
gdb_list_sessions = _session_tools.gdb_list_sessions
gdb_status = _session_tools.gdb_status
gdb_attach = _execution_tools.gdb_attach
gdb_load_core = _execution_tools.gdb_load_core
gdb_execute = _execution_tools.gdb_execute
gdb_run = _execution_tools.gdb_run
gdb_continue = _execution_tools.gdb_continue
gdb_restart = _execution_tools.gdb_restart
gdb_interrupt = _execution_tools.gdb_interrupt
gdb_signal = _execution_tools.gdb_signal
gdb_detach = _execution_tools.gdb_detach
gdb_kill = _execution_tools.gdb_kill
gdb_step = _execution_tools.gdb_step
gdb_next = _execution_tools.gdb_next
gdb_rr_record = _execution_tools.gdb_rr_record
gdb_start_rr_replay_session = _execution_tools.gdb_start_rr_replay_session
gdb_start_recording = _execution_tools.gdb_start_recording
gdb_stop_recording = _execution_tools.gdb_stop_recording
gdb_record_status = _execution_tools.gdb_record_status
gdb_reverse_continue = _execution_tools.gdb_reverse_continue
gdb_reverse_step = _execution_tools.gdb_reverse_step
gdb_reverse_next = _execution_tools.gdb_reverse_next
gdb_reverse_finish = _execution_tools.gdb_reverse_finish
gdb_set_breakpoint = _breakpoint_tools.gdb_set_breakpoint
gdb_enable_breakpoint = _breakpoint_tools.gdb_enable_breakpoint
gdb_disable_breakpoint = _breakpoint_tools.gdb_disable_breakpoint
gdb_breakpoint_condition = _breakpoint_tools.gdb_breakpoint_condition
gdb_breakpoint_commands = _breakpoint_tools.gdb_breakpoint_commands
gdb_delete_breakpoint = _breakpoint_tools.gdb_delete_breakpoint
gdb_list_breakpoints = _breakpoint_tools.gdb_list_breakpoints
gdb_set_watchpoint = _breakpoint_tools.gdb_set_watchpoint
gdb_threads = _inspection_tools.gdb_threads
gdb_select_thread = _inspection_tools.gdb_select_thread
gdb_backtrace = _inspection_tools.gdb_backtrace
gdb_select_frame = _inspection_tools.gdb_select_frame
gdb_locals = _inspection_tools.gdb_locals
gdb_eval_expression = _inspection_tools.gdb_eval_expression
gdb_print = _inspection_tools.gdb_print
gdb_call_function = _inspection_tools.gdb_call_function
gdb_set_variable = _inspection_tools.gdb_set_variable
gdb_disassemble = _inspection_tools.gdb_disassemble
gdb_current_location = _inspection_tools.gdb_current_location
gdb_context = _inspection_tools.gdb_context
gdb_run_and_context = _inspection_tools.gdb_run_and_context
gdb_continue_and_context = _inspection_tools.gdb_continue_and_context
gdb_step_and_context = _inspection_tools.gdb_step_and_context
gdb_next_and_context = _inspection_tools.gdb_next_and_context
gdb_reverse_continue_and_context = _inspection_tools.gdb_reverse_continue_and_context
gdb_reverse_step_and_context = _inspection_tools.gdb_reverse_step_and_context
gdb_reverse_next_and_context = _inspection_tools.gdb_reverse_next_and_context
gdb_reverse_finish_and_context = _inspection_tools.gdb_reverse_finish_and_context
gdb_disassemble_current_frame = _inspection_tools.gdb_disassemble_current_frame
gdb_disassemble_around_pc = _inspection_tools.gdb_disassemble_around_pc
gdb_find_source = _inspection_tools.gdb_find_source
gdb_source = _inspection_tools.gdb_source
gdb_thread_apply_all_backtrace = _inspection_tools.gdb_thread_apply_all_backtrace
gdb_stack_arguments = _inspection_tools.gdb_stack_arguments
gdb_frame_variables = _inspection_tools.gdb_frame_variables
gdb_registers = _inspection_tools.gdb_registers
gdb_register_names = _inspection_tools.gdb_register_names
gdb_read_register = _inspection_tools.gdb_read_register
gdb_read_memory = _inspection_tools.gdb_read_memory
gdb_write_memory = _inspection_tools.gdb_write_memory
gdb_search_memory = _inspection_tools.gdb_search_memory
gdb_read_c_string = _inspection_tools.gdb_read_c_string
gdb_shared_libraries = _inspection_tools.gdb_shared_libraries
gdb_info_files = _inspection_tools.gdb_info_files
gdb_memory_mappings = _inspection_tools.gdb_memory_mappings
gdb_vmmap_structured = _binary_tools.gdb_vmmap_structured
gdb_address_info = _binary_tools.gdb_address_info
gdb_telescope = _binary_tools.gdb_telescope
gdb_nearpc = _binary_tools.gdb_nearpc
gdb_piebase = _binary_tools.gdb_piebase
gdb_break_rva = _binary_tools.gdb_break_rva
gdb_pwn_context = _binary_tools.gdb_pwn_context
gdb_checksec = _binary_tools.gdb_checksec
gdb_elf_info = _binary_tools.gdb_elf_info
gdb_register_context = _binary_tools.gdb_register_context
gdb_symbols = _binary_tools.gdb_symbols
gdb_got = _binary_tools.gdb_got
gdb_rva_info = _binary_tools.gdb_rva_info
gdb_binary_summary = _binary_tools.gdb_binary_summary
gdb_set_remote_paths = _remote_tools.gdb_set_remote_paths
gdb_detach_gdbserver = _remote_tools.gdb_detach_gdbserver
gdb_gdbserver_status = _remote_tools.gdb_gdbserver_status
gdb_capabilities = _diagnostics_tools.gdb_capabilities
gdb_close_idle_sessions = _diagnostics_tools.gdb_close_idle_sessions
gdb_command_reference = _diagnostics_tools.gdb_command_reference
gdb_recent_commands = _diagnostics_tools.gdb_recent_commands
gdb_recent_events = _diagnostics_tools.gdb_recent_events
gdb_server_health = _diagnostics_tools.gdb_server_health
gdb_session_diagnostics = _diagnostics_tools.gdb_session_diagnostics
gdb_export_session_bundle = _diagnostics_tools.gdb_export_session_bundle


async def _executable_version(path: str | None, *args: str) -> str | None:
    if path is None:
        return None
    try:
        process = await asyncio.create_subprocess_exec(
            path,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=2.0)
    except Exception:
        return None
    text = stdout.decode(errors="replace").strip()
    return text.splitlines()[0] if text else None


_session_tools.configure(
    manager=manager,
    error=_shared_tools._error,
    require_mi_word=_shared_tools._require_mi_word,
    require_unsafe_tool=_shared_tools._require_unsafe_tool,
)
_session_tools.register_tools(
    mcp,
    read_only=READ_ONLY,
    session_mutation=SESSION_MUTATION,
    target_execution=TARGET_EXECUTION,
    destructive=DESTRUCTIVE,
)
_execution_tools.register_tools(
    mcp,
    read_only=READ_ONLY,
    session_mutation=SESSION_MUTATION,
    target_execution=TARGET_EXECUTION,
    destructive=DESTRUCTIVE,
)
_breakpoint_tools.register_tools(
    mcp,
    read_only=READ_ONLY,
    session_mutation=SESSION_MUTATION,
    destructive=DESTRUCTIVE,
)
_inspection_tools.register_tools(
    mcp,
    read_only=READ_ONLY,
    session_mutation=SESSION_MUTATION,
    target_execution=TARGET_EXECUTION,
    destructive=DESTRUCTIVE,
)
_binary_tools.register_tools(
    mcp,
    read_only=READ_ONLY,
    session_mutation=SESSION_MUTATION,
)
_remote_tools.register_tools(
    mcp,
    read_only=READ_ONLY,
    session_mutation=SESSION_MUTATION,
    destructive=DESTRUCTIVE,
)
_diagnostics_tools.configure(
    manager=manager,
    runtime_config=runtime_config,
    error=_shared_tools._error,
    executable_version=_executable_version,
)
_diagnostics_tools.register_tools(
    mcp,
    read_only=READ_ONLY,
    session_mutation=SESSION_MUTATION,
)
register_resources(mcp)
register_prompts(mcp)


async def apply_tool_profile(
    profile_value: str,
    *,
    include_tools: str | Sequence[str] | None = None,
    exclude_tools: str | Sequence[str] | None = None,
    profile_explicit: bool | None = None,
) -> str:
    """Restrict the registered tool surface and return the canonical selection name."""

    selection = parse_tool_selection(
        profile_value,
        include_tools=include_tools,
        exclude_tools=exclude_tools,
        profile_explicit=profile_explicit,
    )
    tools = await mcp.list_tools()
    allowed = selection.allowed_names({tool.name for tool in tools})
    for tool in tools:
        if tool.name not in allowed:
            mcp.remove_tool(tool.name)
    runtime_config.tool_profile = selection.canonical_name
    runtime_config.tool_profile_explicit = selection.profile_explicit
    runtime_config.include_tools = selection.include_tools
    runtime_config.exclude_tools = selection.exclude_tools
    return selection.canonical_name


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Full gdb-mcp backend server")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http", "sse"],
        default="stdio",
        help="MCP transport (default: stdio)",
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind host")
    parser.add_argument("--port", type=int, default=8000, help="HTTP bind port")
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        default=False,
        help="Acknowledge a protected non-loopback HTTP deployment",
    )
    parser.add_argument(
        "--allow-unsafe-over-http",
        action="store_true",
        default=False,
        help="Allow unsafe tools on an authenticated non-loopback HTTP deployment",
    )
    parser.add_argument(
        "--http-auth-token",
        default=os.getenv("GDB_MCP_HTTP_AUTH_TOKEN"),
        help="Bearer token for HTTP clients; prefer GDB_MCP_HTTP_AUTH_TOKEN over this flag",
    )
    parser.add_argument(
        "--http-auth-issuer-url",
        default=os.getenv("GDB_MCP_HTTP_AUTH_ISSUER_URL"),
        help="OAuth issuer URL for the bearer token's authorization server",
    )
    parser.add_argument(
        "--http-auth-resource-url",
        default=os.getenv("GDB_MCP_HTTP_AUTH_RESOURCE_URL"),
        help="Public MCP resource URL, usually https://host.example/mcp",
    )
    parser.add_argument(
        "--http-allowed-host",
        action="append",
        default=None,
        help="Allowed HTTP Host header; may be repeated, supports :* ports",
    )
    parser.add_argument(
        "--http-allowed-origin",
        action="append",
        default=None,
        help="Allowed HTTP Origin header; may be repeated, supports :* ports",
    )
    parser.add_argument(
        "--unsafe",
        action="store_true",
        help="Enable unrestricted gdb_execute commands",
    )
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=None,
        help="Maximum live GDB sessions; 0 means unlimited",
    )
    parser.add_argument(
        "--output-limit-chars",
        type=int,
        default=None,
        help="Approximate output limit per tool result",
    )
    parser.add_argument(
        "--tool-profile",
        default=None,
        help=(
            "Discovered tools: full (default), core, or "
            "advanced:<group>[,<group>]"
        ),
    )
    parser.add_argument(
        "--tools",
        action="append",
        default=None,
        help="Explicitly expose only (or add to profile) comma-separated tool names",
    )
    parser.add_argument(
        "--exclude-tools",
        action="append",
        default=None,
        help="Comma-separated tool names to exclude after profile and --tools",
    )
    parser.add_argument(
        "--idle-session-ttl",
        type=float,
        default=None,
        help="Optional idle session TTL in seconds (disabled by default)",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        help="Operational stderr log level: off (default), error, warning, info, debug",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        default=None,
        help="Enable MCP notifications/progress (disabled by default)",
    )
    parser.add_argument(
        "--no-progress",
        dest="progress",
        action="store_false",
        help="Disable MCP notifications/progress",
    )
    return parser


_ATEXIT_REGISTERED = False


def _install_process_cleanup(*, stdio_transport: bool) -> None:
    global _ATEXIT_REGISTERED
    if not _ATEXIT_REGISTERED:
        atexit.register(manager.terminate_all_sync)
        _ATEXIT_REGISTERED = True

    if stdio_transport and (parent_pid_raw := os.getenv("GDB_MCP_PARENT_PID")):
        try:
            parent_pid = int(parent_pid_raw)
        except ValueError:
            parent_pid = None
        if parent_pid is not None and parent_pid > 0:
            set_pdeathsig(signal.SIGTERM, expected_ppid=parent_pid)

    if hasattr(signal, "SIGTERM"):
        def _handle_sigterm(_signum: int, _frame: Any) -> None:
            manager.terminate_all_sync()
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            os.kill(os.getpid(), signal.SIGTERM)

        try:
            signal.signal(signal.SIGTERM, _handle_sigterm)
        except ValueError:
            pass


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if argv is None and Path(sys.argv[0]).name == "gdb-mcp-backend":
        print(
            "Warning: gdb-mcp-backend is deprecated; use 'gdb-mcp serve-http' "
            "or 'gdb-mcp backend'.",
            file=sys.stderr,
        )

    try:
        if _env_config_error is not None:
            raise _env_config_error
        env_config = ServerConfig.from_env()
        allow_remote = args.allow_remote or _env_bool("GDB_MCP_ALLOW_REMOTE", False)
        allow_unsafe_over_http = args.allow_unsafe_over_http or _env_bool(
            "GDB_MCP_ALLOW_UNSAFE_OVER_HTTP", False
        )
        unsafe_enabled = env_config.allow_unsafe_execute or args.unsafe
        max_sessions = (
            args.max_sessions if args.max_sessions is not None else env_config.max_sessions
        )
        if max_sessions < 0:
            raise ValueError("--max-sessions must be >= 0")
        output_limit_chars = (
            args.output_limit_chars
            if args.output_limit_chars is not None
            else env_config.output_limit_chars
        )
        if output_limit_chars < 10_000:
            raise ValueError("--output-limit-chars must be >= 10000")
        idle_ttl = (
            args.idle_session_ttl
            if args.idle_session_ttl is not None
            else env_config.idle_session_ttl_seconds
        )
        if idle_ttl is not None and idle_ttl <= 0:
            idle_ttl = None
        tool_profile = (
            args.tool_profile if args.tool_profile is not None else env_config.tool_profile
        )
        profile_explicit = (args.tool_profile is not None) or env_config.tool_profile_explicit
        include_tools = (
            parse_tool_names(args.tools)
            if args.tools is not None
            else env_config.include_tools
        )
        exclude_tools = (
            parse_tool_names(args.exclude_tools)
            if args.exclude_tools is not None
            else env_config.exclude_tools
        )
        progress_enabled = (
            args.progress
            if args.progress is not None
            else env_config.progress_notifications
        )
        log_level = parse_log_level(
            args.log_level if args.log_level is not None else env_config.log_level
        )
        asyncio.run(
            apply_tool_profile(
                tool_profile,
                include_tools=include_tools,
                exclude_tools=exclude_tools,
                profile_explicit=profile_explicit,
            )
        )
        transport_security = configure_http_security(
            mcp,
            transport=args.transport,
            host=args.host,
            allow_remote=allow_remote,
            allow_unsafe_over_http=allow_unsafe_over_http,
            unsafe_enabled=unsafe_enabled,
            bearer_token=args.http_auth_token,
            issuer_url=args.http_auth_issuer_url,
            resource_url=args.http_auth_resource_url,
            allowed_hosts=args.http_allowed_host or [],
            allowed_origins=args.http_allowed_origin or [],
        )
    except ValueError as exc:
        parser.error(str(exc))

    runtime_config.allow_unsafe_execute = unsafe_enabled
    runtime_config.max_sessions = max_sessions
    runtime_config.output_limit_chars = output_limit_chars
    runtime_config.idle_session_ttl_seconds = idle_ttl
    runtime_config.log_level = log_level
    runtime_config.progress_notifications = progress_enabled
    logger.set_level(log_level)
    manager.max_sessions = runtime_config.max_sessions
    manager.output_limit_chars = runtime_config.output_limit_chars
    manager.idle_session_ttl_seconds = runtime_config.idle_session_ttl_seconds

    _install_process_cleanup(stdio_transport=args.transport == "stdio")
    if args.transport in HTTP_TRANSPORTS:
        mcp.run(
            transport=args.transport,
            host=args.host,
            port=args.port,
            transport_security=transport_security,
        )
    else:
        mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
