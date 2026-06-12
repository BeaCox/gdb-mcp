"""MCP tool surface and command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import shutil
from contextlib import asynccontextmanager
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .config import ServerConfig
from .mi import c_escape
from .session import CommandResult, GdbMcpError, GdbSession, SessionManager, launch_gdbserver

runtime_config = ServerConfig.from_env()
manager = SessionManager(
    max_sessions=runtime_config.max_sessions,
    output_limit_chars=runtime_config.output_limit_chars,
)


@asynccontextmanager
async def _lifespan(_: FastMCP[Any]):
    try:
        yield
    finally:
        await manager.close_all()


mcp = FastMCP(
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


def _error(exc: Exception) -> dict[str, Any]:
    return {"ok": False, "error": str(exc), "error_type": type(exc).__name__}


def _result(session: GdbSession, result: CommandResult) -> dict[str, Any]:
    return result.to_dict(session.output_limit_chars)


def _require_single_line(name: str, value: str) -> None:
    if "\n" in value or "\r" in value:
        raise ValueError(f"{name} must not contain line breaks")


async def _terminate_process(process: asyncio.subprocess.Process | None) -> None:
    if process is None or process.returncode is not None:
        return
    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()


@mcp.tool(annotations=SESSION_MUTATION)
async def gdb_create_session(
    program: str | None = None,
    args: list[str] | None = None,
    cwd: str | None = None,
    gdb_path: str = "gdb",
    startup_timeout: float = 10.0,
) -> dict[str, Any]:
    """Create an isolated GDB session and optionally load a program."""

    try:
        session = await manager.create(
            gdb_path=gdb_path,
            program=program,
            args=args,
            cwd=cwd,
            startup_timeout=startup_timeout,
        )
        return {"ok": True, "session": session.describe()}
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=SESSION_MUTATION)
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

    created_session = False
    try:
        _require_single_line("endpoint", endpoint)
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
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=TARGET_EXECUTION)
async def gdb_launch_gdbserver(
    program: str,
    listen: str = "localhost:2345",
    target_endpoint: str | None = None,
    args: list[str] | None = None,
    cwd: str | None = None,
    gdb_path: str = "gdb",
    gdbserver_path: str = "gdbserver",
    extended: bool = False,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Launch a local gdbserver and connect a new GDB session to it."""

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
        endpoint = target_endpoint or listen.lstrip(":")
        if endpoint.startswith("localhost:") or endpoint.startswith("127.0.0.1:"):
            target = endpoint
        elif ":" in endpoint and endpoint.split(":", 1)[0]:
            target = endpoint
        else:
            target = f"localhost:{endpoint.split(':')[-1]}"
        result = await session.connect_gdbserver(
            target,
            extended=extended,
            timeout=timeout,
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


@mcp.tool(annotations=READ_ONLY)
async def gdb_list_sessions() -> dict[str, Any]:
    """List active GDB sessions."""

    return {"ok": True, "sessions": await manager.list()}


@mcp.tool(annotations=READ_ONLY)
async def gdb_status(session_id: str) -> dict[str, Any]:
    """Return one session's status."""

    try:
        session = await manager.get(session_id)
        return {"ok": True, "session": session.describe()}
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=DESTRUCTIVE)
async def gdb_close_session(session_id: str) -> dict[str, Any]:
    """Close a GDB session and any child gdbserver process."""

    try:
        return {"ok": True, **await manager.close(session_id)}
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=TARGET_EXECUTION)
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


@mcp.tool(annotations=TARGET_EXECUTION)
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


@mcp.tool(annotations=TARGET_EXECUTION)
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


@mcp.tool(annotations=TARGET_EXECUTION)
async def gdb_interrupt(session_id: str, timeout: float = 5.0) -> dict[str, Any]:
    """Interrupt a running target."""

    try:
        session = await manager.get(session_id)
        return _result(session, await session.interrupt(timeout=timeout))
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=TARGET_EXECUTION)
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


@mcp.tool(annotations=TARGET_EXECUTION)
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


@mcp.tool(annotations=SESSION_MUTATION)
async def gdb_set_breakpoint(
    session_id: str,
    location: str,
    condition: str | None = None,
    temporary: bool = False,
) -> dict[str, Any]:
    """Set a breakpoint using GDB CLI syntax."""

    try:
        _require_single_line("location", location)
        if condition is not None:
            _require_single_line("condition", condition)
        prefix = "tbreak" if temporary else "break"
        command = f"{prefix} {location}"
        if condition:
            command += f" if {condition}"
        session = await manager.get(session_id)
        return _result(session, await session.execute(command, timeout=10.0))
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=DESTRUCTIVE)
async def gdb_delete_breakpoint(session_id: str, number: str) -> dict[str, Any]:
    """Delete a breakpoint by number."""

    try:
        if not number or any(char not in "0123456789." for char in number):
            raise ValueError("Breakpoint number must contain only digits and dots")
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(f"-break-delete {number}", timeout=10.0),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_list_breakpoints(session_id: str) -> dict[str, Any]:
    """List breakpoints as structured MI data."""

    try:
        session = await manager.get(session_id)
        return _result(session, await session.execute("-break-list", timeout=10.0))
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_threads(session_id: str) -> dict[str, Any]:
    """List threads."""

    try:
        session = await manager.get(session_id)
        return _result(session, await session.execute("-thread-info", timeout=10.0))
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=SESSION_MUTATION)
async def gdb_select_thread(session_id: str, thread_id: str) -> dict[str, Any]:
    """Select the current thread."""

    try:
        if not thread_id.isdigit():
            raise ValueError("Thread ID must be a positive integer")
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(f"-thread-select {thread_id}", timeout=10.0),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_backtrace(session_id: str, max_frames: int = 50) -> dict[str, Any]:
    """Get stack frames."""

    try:
        if not 1 <= max_frames <= 1_000:
            raise ValueError("max_frames must be between 1 and 1000")
        high = max_frames - 1
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(f"-stack-list-frames 0 {high}", timeout=10.0),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=SESSION_MUTATION)
async def gdb_select_frame(session_id: str, frame: int) -> dict[str, Any]:
    """Select a stack frame."""

    try:
        if frame < 0:
            raise ValueError("Frame index must be non-negative")
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(f"-stack-select-frame {frame}", timeout=10.0),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_locals(session_id: str) -> dict[str, Any]:
    """List local variables in the selected frame."""

    try:
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(
                "-stack-list-variables --simple-values",
                timeout=10.0,
            ),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_registers(
    session_id: str,
    register_numbers: list[int] | None = None,
    fmt: str = "x",
) -> dict[str, Any]:
    """Read register values."""

    try:
        if fmt not in {"x", "o", "t", "d", "r", "N"}:
            raise ValueError("fmt must be one of: x, o, t, d, r, N")
        if register_numbers and any(item < 0 for item in register_numbers):
            raise ValueError("Register numbers must be non-negative")
        suffix = ""
        if register_numbers:
            suffix = " " + " ".join(str(item) for item in register_numbers)
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(
                f"-data-list-register-values {fmt}{suffix}",
                timeout=10.0,
            ),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_read_memory(
    session_id: str,
    address: str,
    count: int,
) -> dict[str, Any]:
    """Read raw memory bytes."""

    try:
        if not 1 <= count <= 1_048_576:
            raise ValueError("count must be between 1 and 1048576 bytes")
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(
                f"-data-read-memory-bytes {c_escape(address)} {count}",
                timeout=10.0,
            ),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_recent_events(
    session_id: str,
    limit: int = 100,
) -> dict[str, Any]:
    """Return recent MI records, including asynchronous stop and thread events."""

    try:
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        session = await manager.get(session_id)
        return {
            "ok": True,
            "session_id": session_id,
            "events": session.recent_records(limit),
        }
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_server_health() -> dict[str, Any]:
    """Report server capabilities, safety mode, dependencies, and session count."""

    try:
        package_version = version("gdb-mcp")
    except PackageNotFoundError:
        package_version = "0+unknown"
    sessions = await manager.list()
    return {
        "ok": True,
        "name": "gdb-mcp",
        "version": package_version,
        "gdb_available": shutil.which("gdb") is not None,
        "gdbserver_available": shutil.which("gdbserver") is not None,
        "unsafe_execute_enabled": runtime_config.allow_unsafe_execute,
        "max_sessions": runtime_config.max_sessions,
        "output_limit_chars": runtime_config.output_limit_chars,
        "session_count": len(sessions),
        "sessions": sessions,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Multi-session GDB MCP server")
    lifecycle = parser.add_mutually_exclusive_group()
    lifecycle.add_argument(
        "--install",
        nargs="?",
        const="auto",
        metavar="CLIENTS",
        help="Install for detected clients or a comma-separated list",
    )
    lifecycle.add_argument(
        "--uninstall",
        nargs="?",
        const="auto",
        metavar="CLIENTS",
        help="Uninstall from detected clients or a comma-separated list",
    )
    parser.add_argument(
        "--direct",
        action="store_true",
        help="Configure MCP directly instead of installing marketplace plugins",
    )
    parser.add_argument(
        "--scope",
        choices=["user", "project", "local"],
        default="user",
        help="Client configuration scope where supported",
    )
    parser.add_argument(
        "--source",
        default=None,
        help="Override the Python package source used by direct installs",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print installation commands without running them",
    )
    parser.add_argument(
        "--list-clients",
        action="store_true",
        help="List supported clients and whether they are installed",
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
        "--unsafe",
        action="store_true",
        help="Enable unrestricted gdb_execute commands",
    )
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=runtime_config.max_sessions,
        help="Maximum live GDB sessions; 0 means unlimited",
    )
    parser.add_argument(
        "--output-limit-chars",
        type=int,
        default=runtime_config.output_limit_chars,
        help="Approximate output limit per tool result",
    )
    parser.add_argument(
        "--config",
        "--print-config",
        dest="print_config",
        action="store_true",
        help="Print portable MCP client configuration and exit",
    )
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    from .installer import (
        PACKAGE_SOURCE,
        install,
        list_clients,
        parse_targets,
        print_configuration,
        uninstall,
    )

    package_source = args.source or PACKAGE_SOURCE
    if args.list_clients:
        list_clients()
        return
    if args.print_config:
        print_configuration(package_source)
        return
    if args.install is not None:
        install(
            parse_targets(args.install),
            scope=args.scope,
            direct=args.direct,
            dry_run=args.dry_run,
            package_source=package_source,
        )
        return
    if args.uninstall is not None:
        uninstall(
            parse_targets(args.uninstall),
            scope=args.scope,
            direct=args.direct,
            dry_run=args.dry_run,
        )
        return

    runtime_config.allow_unsafe_execute = (
        runtime_config.allow_unsafe_execute or args.unsafe
    )
    runtime_config.max_sessions = max(0, args.max_sessions)
    runtime_config.output_limit_chars = max(10_000, args.output_limit_chars)
    manager.max_sessions = runtime_config.max_sessions
    manager.output_limit_chars = runtime_config.output_limit_chars
    mcp.settings.host = args.host
    mcp.settings.port = args.port
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
