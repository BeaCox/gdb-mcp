"""MCP tool surface and command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import re
import shutil
import time
from contextlib import asynccontextmanager
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .config import ServerConfig
from .mi import c_escape
from .session import (
    CommandResult,
    GdbMcpError,
    GdbSession,
    SessionManager,
    gdbserver_target_endpoint,
    launch_gdbserver,
)

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


def _require_cli_target(name: str, value: str) -> None:
    _require_single_line(name, value)
    if not value.strip():
        raise ValueError(f"{name} must not be empty")
    if any(char in value for char in "\0"):
        raise ValueError(f"{name} contains unsupported characters")


def _require_mi_word(name: str, value: str) -> None:
    _require_cli_target(name, value)
    if any(char.isspace() for char in value) or '"' in value:
        raise ValueError(f"{name} must be a single unquoted GDB/MI argument")


def _require_unsafe_tool(name: str) -> None:
    if not runtime_config.allow_unsafe_execute:
        raise GdbMcpError(
            f"{name} requires --unsafe or GDB_MCP_ALLOW_UNSAFE=1 because it can "
            "modify the inferior or run arbitrary target code."
        )


def _require_breakpoint_number(number: str) -> None:
    if not number or any(char not in "0123456789." for char in number):
        raise ValueError("Breakpoint number must contain only digits and dots")


def _require_hex_bytes(name: str, value: str) -> str:
    compact = "".join(value.split())
    if not compact or len(compact) % 2 != 0:
        raise ValueError(f"{name} must contain an even number of hexadecimal digits")
    if any(char not in "0123456789abcdefABCDEF" for char in compact):
        raise ValueError(f"{name} must contain only hexadecimal digits")
    return compact.lower()


_EXPRESSION_ASSIGNMENT_RE = re.compile(r"(?<![<>=!])=(?!=)")
_EXPRESSION_CALL_RE = re.compile(r"(?:[A-Za-z_$][\w$:]*|\]|\))\s*\(")


def _require_read_expression(name: str, expression: str) -> None:
    _require_single_line(name, expression)
    if not expression.strip():
        raise ValueError(f"{name} must not be empty")
    if any(char in expression for char in ";{}"):
        raise ValueError(f"{name} contains unsupported control characters")
    if "++" in expression or "--" in expression or _EXPRESSION_ASSIGNMENT_RE.search(expression):
        raise ValueError(f"{name} must not modify the inferior")
    if _EXPRESSION_CALL_RE.search(expression):
        raise ValueError(f"{name} must not call functions in safe mode")


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
        target = target_endpoint or gdbserver_target_endpoint(listen, banner)
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


@mcp.tool(annotations=SESSION_MUTATION)
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
        _require_mi_word("core_path", core_path)
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
            f"-target-select core {core_path}",
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


@mcp.tool(annotations=TARGET_EXECUTION)
async def gdb_interrupt(session_id: str, timeout: float = 5.0) -> dict[str, Any]:
    """Interrupt a running target."""

    try:
        session = await manager.get(session_id)
        return _result(session, await session.interrupt(timeout=timeout))
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=TARGET_EXECUTION)
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


@mcp.tool(annotations=DESTRUCTIVE)
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


@mcp.tool(annotations=DESTRUCTIVE)
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


@mcp.tool(annotations=SESSION_MUTATION)
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


@mcp.tool(annotations=SESSION_MUTATION)
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


@mcp.tool(annotations=SESSION_MUTATION)
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


@mcp.tool(annotations=DESTRUCTIVE)
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


@mcp.tool(annotations=DESTRUCTIVE)
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


@mcp.tool(annotations=READ_ONLY)
async def gdb_list_breakpoints(session_id: str) -> dict[str, Any]:
    """List breakpoints as structured MI data."""

    try:
        session = await manager.get(session_id)
        return _result(session, await session.execute("-break-list", timeout=10.0))
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=SESSION_MUTATION)
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
async def gdb_eval_expression(
    session_id: str,
    expression: str,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Evaluate a read-safe expression in the selected frame."""

    try:
        _require_read_expression("expression", expression)
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(
                f"-data-evaluate-expression {c_escape(expression)}",
                timeout=timeout,
            ),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_print(
    session_id: str,
    expression: str,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Print a read-safe expression using GDB's normal formatting."""

    try:
        _require_read_expression("expression", expression)
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(f"print {expression}", timeout=timeout),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=TARGET_EXECUTION)
async def gdb_call_function(
    session_id: str,
    expression: str,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Call an inferior function or evaluate an unsafe expression. Requires unsafe mode."""

    try:
        _require_unsafe_tool("gdb_call_function")
        _require_single_line("expression", expression)
        if not expression.strip():
            raise ValueError("expression must not be empty")
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(f"print {expression}", timeout=timeout),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=DESTRUCTIVE)
async def gdb_set_variable(
    session_id: str,
    expression: str,
    value: str,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Set an inferior variable or lvalue expression. Requires unsafe mode."""

    try:
        _require_unsafe_tool("gdb_set_variable")
        _require_single_line("expression", expression)
        _require_single_line("value", value)
        if not expression.strip() or not value.strip():
            raise ValueError("expression and value must not be empty")
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(f"set var {expression} = {value}", timeout=timeout),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_disassemble(
    session_id: str,
    location: str | None = None,
    start_address: str | None = None,
    end_address: str | None = None,
    mixed: bool = False,
    raw_bytes: bool = False,
) -> dict[str, Any]:
    """Disassemble a function/location or an address range."""

    try:
        if location and (start_address or end_address):
            raise ValueError("Use either location or start_address/end_address, not both")
        if location:
            _require_cli_target("location", location)
            target = location
        else:
            if not start_address or not end_address:
                raise ValueError("Provide location or both start_address and end_address")
            _require_cli_target("start_address", start_address)
            _require_cli_target("end_address", end_address)
            target = f"{start_address},{end_address}"

        options = ""
        if mixed or raw_bytes:
            options = "/" + ("m" if mixed else "") + ("r" if raw_bytes else "")
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(
                f"disassemble {options} {target}".replace("  ", " "),
                timeout=10.0,
            ),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_current_location(session_id: str) -> dict[str, Any]:
    """Return the selected frame and last known stop location."""

    try:
        session = await manager.get(session_id)
        frame = _result(
            session,
            await session.execute("-stack-info-frame", timeout=10.0),
        )
        return {
            "ok": frame["ok"],
            "session_id": session_id,
            "last_stop": session.last_stop,
            "frame": frame,
        }
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_disassemble_current_frame(
    session_id: str,
    mixed: bool = False,
    raw_bytes: bool = False,
) -> dict[str, Any]:
    """Disassemble the selected frame's current function."""

    return await gdb_disassemble(
        session_id,
        location="$pc",
        mixed=mixed,
        raw_bytes=raw_bytes,
    )


@mcp.tool(annotations=READ_ONLY)
async def gdb_find_source(
    session_id: str,
    query: str,
    limit: int = 50,
) -> dict[str, Any]:
    """List known source files whose paths contain query."""

    try:
        _require_single_line("query", query)
        if not query:
            raise ValueError("query must not be empty")
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        session = await manager.get(session_id)
        result = _result(session, await session.execute("info sources", timeout=10.0))
        matches: list[str] = []
        if result["ok"]:
            for chunk in re.split(r"[\s,]+", result["console"]):
                source = chunk.strip()
                if source and query in source and source not in matches:
                    matches.append(source)
                    if len(matches) >= limit:
                        break
        return {**result, "matches": matches}
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_source(
    session_id: str,
    location: str | None = None,
) -> dict[str, Any]:
    """List source around the current frame or a source location."""

    try:
        if location is None:
            command = "list"
        else:
            _require_cli_target("location", location)
            command = f"list {location}"
        session = await manager.get(session_id)
        return _result(session, await session.execute(command, timeout=10.0))
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_thread_apply_all_backtrace(
    session_id: str,
    max_frames: int = 50,
) -> dict[str, Any]:
    """Run backtrace on every thread."""

    try:
        if not 1 <= max_frames <= 1_000:
            raise ValueError("max_frames must be between 1 and 1000")
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(
                f"thread apply all backtrace {max_frames}",
                timeout=15.0,
            ),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_stack_arguments(session_id: str, max_frames: int = 50) -> dict[str, Any]:
    """List stack frame arguments."""

    try:
        if not 1 <= max_frames <= 1_000:
            raise ValueError("max_frames must be between 1 and 1000")
        high = max_frames - 1
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(
                f"-stack-list-arguments --simple-values 0 {high}",
                timeout=10.0,
            ),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_frame_variables(session_id: str, mode: str = "locals") -> dict[str, Any]:
    """List variables for the selected frame. mode is locals, args, or all."""

    try:
        commands = {
            "locals": "-stack-list-locals --simple-values",
            "args": "-stack-list-arguments --simple-values 0 0",
            "all": "-stack-list-variables --simple-values",
        }
        command = commands.get(mode)
        if command is None:
            raise ValueError("mode must be one of: locals, args, all")
        session = await manager.get(session_id)
        return _result(session, await session.execute(command, timeout=10.0))
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


@mcp.tool(annotations=DESTRUCTIVE)
async def gdb_write_memory(
    session_id: str,
    address: str,
    data_hex: str,
) -> dict[str, Any]:
    """Write raw bytes to memory. Requires unsafe mode."""

    try:
        _require_unsafe_tool("gdb_write_memory")
        _require_single_line("address", address)
        data = _require_hex_bytes("data_hex", data_hex)
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(
                f"-data-write-memory-bytes {c_escape(address)} {data}",
                timeout=10.0,
            ),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_search_memory(
    session_id: str,
    start_address: str,
    length: int,
    pattern: str,
) -> dict[str, Any]:
    """Search memory for a GDB find pattern."""

    try:
        _require_cli_target("start_address", start_address)
        _require_single_line("pattern", pattern)
        if not 1 <= length <= 1_048_576:
            raise ValueError("length must be between 1 and 1048576 bytes")
        if not pattern.strip():
            raise ValueError("pattern must not be empty")
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(
                f"find {start_address}, +{length}, {pattern}",
                timeout=10.0,
            ),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_read_c_string(
    session_id: str,
    address: str,
    max_bytes: int = 4096,
) -> dict[str, Any]:
    """Read a NUL-terminated C string from memory."""

    try:
        if not 1 <= max_bytes <= 1_048_576:
            raise ValueError("max_bytes must be between 1 and 1048576")
        session = await manager.get(session_id)
        result = await session.execute(
            f"-data-read-memory-bytes {c_escape(address)} {max_bytes}",
            timeout=10.0,
        )
        payload = _result(session, result)
        string_value = ""
        if payload["ok"]:
            memory = payload["results"].get("memory", [])
            contents = ""
            if memory and isinstance(memory, list):
                contents = str(memory[0].get("contents", ""))
            data = bytes.fromhex(contents) if contents else b""
            string_value = data.split(b"\0", 1)[0].decode(errors="replace")
        return {**payload, "string": string_value}
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_shared_libraries(session_id: str) -> dict[str, Any]:
    """List shared libraries known to GDB."""

    try:
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute("-file-list-shared-libraries", timeout=10.0),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_info_files(session_id: str) -> dict[str, Any]:
    """Return GDB's info files output."""

    try:
        session = await manager.get(session_id)
        return _result(session, await session.execute("info files", timeout=10.0))
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_memory_mappings(session_id: str) -> dict[str, Any]:
    """Return process memory mappings when supported by the target."""

    try:
        session = await manager.get(session_id)
        return _result(session, await session.execute("info proc mappings", timeout=10.0))
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=SESSION_MUTATION)
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
                f"-gdb-set {name} {c_escape(value)}",
                timeout=10.0,
            )
            payload = _result(session, result)
            commands.append(payload)
            if not payload["ok"]:
                return {"ok": False, "session": session.describe(), "commands": commands}
        return {"ok": True, "session": session.describe(), "commands": commands}
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=DESTRUCTIVE)
async def gdb_detach_gdbserver(session_id: str, timeout: float = 10.0) -> dict[str, Any]:
    """Detach from a remote target or managed gdbserver."""

    return await gdb_detach(session_id, timeout=timeout)


@mcp.tool(annotations=READ_ONLY)
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
async def gdb_recent_commands(
    session_id: str,
    limit: int = 100,
) -> dict[str, Any]:
    """Return recent commands sent to GDB for one session."""

    try:
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        session = await manager.get(session_id)
        return {
            "ok": True,
            "session_id": session_id,
            "commands": session.recent_commands(limit),
        }
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_session_diagnostics(session_id: str) -> dict[str, Any]:
    """Return diagnostic state for one session."""

    try:
        session = await manager.get(session_id)
        return {
            "ok": True,
            "session": session.describe(),
            "recent_commands": session.recent_commands(20),
            "recent_events": session.recent_records(20),
        }
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=SESSION_MUTATION)
async def gdb_close_idle_sessions(max_idle_seconds: float = 3600.0) -> dict[str, Any]:
    """Close live sessions idle for at least max_idle_seconds."""

    try:
        if max_idle_seconds < 0:
            raise ValueError("max_idle_seconds must be non-negative")
        now = time.time()
        sessions = await manager.list()
        closed: list[dict[str, Any]] = []
        for session in sessions:
            idle = now - float(session["last_activity_at"])
            if idle < max_idle_seconds:
                continue
            try:
                result = await manager.close(str(session["session_id"]))
                closed.append({"session": session, "result": result, "idle_seconds": idle})
            except Exception as exc:
                closed.append({"session": session, "error": str(exc), "idle_seconds": idle})
        return {"ok": True, "closed": closed, "closed_count": len(closed)}
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
