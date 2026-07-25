"""Execution and target-control MCP tools."""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations

from ..mi import c_escape
from ..session import GdbMcpError, _truncate_text
from .progress import report_progress
from .shared import (
    _error,
    _require_cli_target,
    _require_single_line,
    _result,
    manager,
    runtime_config,
)

_RR_TRACE_RE = re.compile(
    r"trace directory [`'](?P<trace>.+?)[`']",
    re.IGNORECASE,
)
_RR_PERF_PERMISSION_MARKERS = (
    "perf_event_open",
    "perf_event_paranoid",
    "performance counters",
    "perf counters",
)
_PERF_EVENT_PARANOID_PATH = Path("/proc/sys/kernel/perf_event_paranoid")


def _read_perf_event_paranoid() -> int | None:
    try:
        return int(_PERF_EVENT_PARANOID_PATH.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _rr_perf_permission_details(
    output: str,
    *,
    disable_syscall_buffer: bool,
) -> dict[str, Any] | None:
    lowered = output.lower()
    if not any(marker in lowered for marker in _RR_PERF_PERMISSION_MARKERS):
        return None

    suggestions = [
        "Set kernel.perf_event_paranoid to 1 or lower, for example: "
        "sudo sysctl kernel.perf_event_paranoid=1.",
        "Persist the setting in /etc/sysctl.d/ when the host policy allows it.",
    ]
    if not disable_syscall_buffer:
        suggestions.append(
            "Retry with disable_syscall_buffer=true to ask rr to use "
            "--no-syscall-buffer; this is slower and may still require perf "
            "access on some systems."
        )

    return {
        "error": "rr cannot access perf_event_open performance counters",
        "error_type": "rr_perf_event_permission_denied",
        "perf_event_paranoid": _read_perf_event_paranoid(),
        "suggestions": suggestions,
    }


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
    mcp.tool(annotations=target_execution)(gdb_rr_record)
    mcp.tool(annotations=session_mutation)(gdb_start_rr_replay_session)
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
        session.invalidate_pagination()
        return _result(session, result)
    except Exception as exc:
        return _error(exc)


async def gdb_run(
    session_id: str,
    args: list[str] | None = None,
    timeout: float = 30.0,
    auto_interrupt: bool = True,
    context: Context | None = None,
) -> dict[str, Any]:
    """Run or restart the inferior and wait until it stops."""

    try:
        await report_progress(context, 0, "Preparing inferior run")
        session = await manager.get(session_id)
        if args:
            encoded_args = " ".join(c_escape(arg) for arg in args)
            args_result = await session.execute(
                f"-exec-arguments {encoded_args}",
                timeout=3.0,
            )
            if not _result(session, args_result)["ok"]:
                return _result(session, args_result)
        await report_progress(context, 50, "Run command dispatched")
        result = await session.execute(
            "-exec-run",
            timeout=timeout,
            wait_for_stop=True,
            auto_interrupt=auto_interrupt,
        )
        await report_progress(context, 100, "Run command finished")
        return _result(session, result)
    except Exception as exc:
        return _error(exc)


async def gdb_continue(
    session_id: str,
    timeout: float = 30.0,
    auto_interrupt: bool = True,
    context: Context | None = None,
) -> dict[str, Any]:
    """Continue execution and wait until the target stops."""

    try:
        await report_progress(context, 0, "Preparing target continuation")
        session = await manager.get(session_id)
        await report_progress(context, 50, "Continue command dispatched")
        result = await session.execute(
            "-exec-continue",
            timeout=timeout,
            wait_for_stop=True,
            auto_interrupt=auto_interrupt,
        )
        await report_progress(context, 100, "Continue command finished")
        return _result(session, result)
    except Exception as exc:
        return _error(exc)


async def gdb_restart(
    session_id: str,
    args: list[str] | None = None,
    timeout: float = 30.0,
    auto_interrupt: bool = True,
    context: Context | None = None,
) -> dict[str, Any]:
    """Restart the inferior and wait until it stops."""

    return await gdb_run(
        session_id,
        args=args,
        timeout=timeout,
        auto_interrupt=auto_interrupt,
        context=context,
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


def _default_rr_trace_dir(program: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", Path(program).name).strip("._")
    if not name:
        name = "trace"
    parent = tempfile.mkdtemp(prefix="gdb-mcp-rr-")
    return str(Path(parent) / name)


async def _terminate_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()


async def gdb_rr_record(
    program: str,
    args: list[str] | None = None,
    cwd: str | None = None,
    rr_path: str = "rr",
    trace_dir: str | None = None,
    disable_syscall_buffer: bool = False,
    timeout: float = 120.0,
    context: Context | None = None,
) -> dict[str, Any]:
    """Record one program run with rr and return the trace directory."""

    try:
        await report_progress(context, 0, "Preparing rr recording")
        _require_cli_target("program", program)
        if cwd is not None:
            _require_cli_target("cwd", cwd)
        if trace_dir is not None:
            _require_cli_target("trace_dir", trace_dir)
        for index, arg in enumerate(args or []):
            _require_single_line(f"args[{index}]", arg)

        resolved_rr = shutil.which(rr_path)
        if resolved_rr is None:
            raise GdbMcpError(f"rr executable not found: {rr_path}")

        actual_trace_dir = trace_dir or _default_rr_trace_dir(program)
        command = [resolved_rr, "record"]
        if disable_syscall_buffer:
            command.append("--no-syscall-buffer")
        command.extend([f"--output-trace-dir={actual_trace_dir}", "--", program])
        command.extend(args or [])

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=cwd,
        )
        await report_progress(context, 50, "rr recording started")
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.CancelledError:
            await _terminate_process(process)
            raise
        except asyncio.TimeoutError:
            await _terminate_process(process)
            raise TimeoutError(f"rr record timed out after {timeout} seconds") from None

        output = stdout.decode(errors="replace")
        match = _RR_TRACE_RE.search(output)
        if match is not None:
            actual_trace_dir = match.group("trace")
        truncated_output, truncated = _truncate_text(
            output.strip(),
            max(1_000, runtime_config.output_limit_chars // 2),
        )
        trace_exists = await asyncio.to_thread(os.path.exists, actual_trace_dir)
        if not trace_exists:
            response = {
                "ok": False,
                "error": "rr did not create a trace directory",
                "trace_dir": actual_trace_dir,
                "rr_returncode": process.returncode,
                "output": truncated_output,
                "truncated": truncated,
            }
            perf_details = _rr_perf_permission_details(
                output,
                disable_syscall_buffer=disable_syscall_buffer,
            )
            if perf_details is not None:
                response.update(perf_details)
            return response
        await report_progress(context, 100, "rr recording finished")
        return {
            "ok": True,
            "trace_dir": actual_trace_dir,
            "rr_returncode": process.returncode,
            "output": truncated_output,
            "truncated": truncated,
        }
    except Exception as exc:
        return _error(exc)


async def gdb_start_rr_replay_session(
    trace_dir: str | None = None,
    cwd: str | None = None,
    rr_path: str = "rr",
    startup_timeout: float = 15.0,
    context: Context | None = None,
) -> dict[str, Any]:
    """Start a GDB/MI session backed by rr replay."""

    try:
        await report_progress(context, 0, "Preparing rr replay session")
        resolved_rr = shutil.which(rr_path)
        if resolved_rr is None:
            raise GdbMcpError(f"rr executable not found: {rr_path}")
        replay_args = ["replay"]
        if trace_dir is not None:
            _require_cli_target("trace_dir", trace_dir)
            trace_exists = await asyncio.to_thread(os.path.exists, trace_dir)
            if not trace_exists:
                raise FileNotFoundError(f"rr trace directory not found: {trace_dir}")
            replay_args.append(trace_dir)
        if cwd is not None:
            _require_cli_target("cwd", cwd)
        replay_args.append("--")

        await report_progress(context, 50, "Starting rr replay debugger")
        session = await manager.create(
            gdb_path=resolved_rr,
            gdb_args=replay_args,
            cwd=cwd,
            rr_trace_dir=trace_dir,
            startup_timeout=startup_timeout,
        )
        await report_progress(context, 100, "rr replay session started")
        return {
            "ok": True,
            "session": session.describe(),
            "trace_dir": trace_dir,
            "rr_replay": True,
        }
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
