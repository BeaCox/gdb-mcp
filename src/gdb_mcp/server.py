"""MCP tool surface and command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import os
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


def _compact_frame(frame: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(frame, dict):
        return None
    compact = {
        key: frame[key]
        for key in ("level", "addr", "func", "file", "fullname", "line", "arch")
        if key in frame
    }
    if "args" in frame:
        compact["args"] = frame["args"]
    return compact


def _frame_from_location(location: dict[str, Any]) -> dict[str, Any] | None:
    frame = location.get("frame")
    if isinstance(frame, dict):
        results = frame.get("results")
        if isinstance(results, dict):
            compact = _compact_frame(results.get("frame"))
            if compact is not None:
                return compact
    last_stop = location.get("last_stop")
    if isinstance(last_stop, dict):
        return _compact_frame(last_stop.get("frame"))
    return None


def _stack_from_backtrace(backtrace: dict[str, Any]) -> list[dict[str, Any]]:
    results = backtrace.get("results")
    if not isinstance(results, dict):
        return []
    stack = results.get("stack")
    if not isinstance(stack, list):
        return []
    frames: list[dict[str, Any]] = []
    for item in stack:
        if not isinstance(item, dict):
            continue
        compact = _compact_frame(item.get("frame"))
        if compact is not None:
            frames.append(compact)
    return frames


def _variables_from_locals(locals_result: dict[str, Any]) -> list[dict[str, Any]]:
    results = locals_result.get("results")
    if not isinstance(results, dict):
        return []
    variables = results.get("variables")
    if not isinstance(variables, list):
        return []
    return [item for item in variables if isinstance(item, dict)]


def _last_stop_reason(payload: dict[str, Any]) -> str | None:
    stopped = payload.get("stopped")
    if isinstance(stopped, dict):
        reason = stopped.get("reason")
        if isinstance(reason, str):
            return reason
    last_stop = payload.get("last_stop")
    if isinstance(last_stop, dict):
        reason = last_stop.get("reason")
        if isinstance(reason, str):
            return reason
    return None


def _target_output(payload: dict[str, Any]) -> str:
    output = payload.get("target") or payload.get("log") or payload.get("console") or ""
    return output if isinstance(output, str) else ""


def _summary_lines(
    *,
    action: str,
    execution: dict[str, Any] | None,
    location: dict[str, Any],
    stack: list[dict[str, Any]],
    variables: list[dict[str, Any]],
) -> list[str]:
    lines = [f"action: {action}"]
    if execution is not None:
        reason = _last_stop_reason(execution)
        if reason:
            lines.append(f"stop: {reason}")
        output = _target_output(execution)
        if output:
            lines.append(f"output: {output}")

    frame = _frame_from_location(location)
    if frame is not None:
        function = frame.get("func", "??")
        file_name = frame.get("fullname") or frame.get("file")
        line = frame.get("line")
        if file_name and line:
            lines.append(f"location: {function} at {file_name}:{line}")
        elif file_name:
            lines.append(f"location: {function} at {file_name}")
        else:
            lines.append(f"location: {function}")

    if stack:
        rendered_stack = []
        for frame in stack:
            level = frame.get("level", "?")
            function = frame.get("func", "??")
            line = frame.get("line")
            suffix = f":{line}" if line else ""
            rendered_stack.append(f"#{level} {function}{suffix}")
        lines.append("backtrace: " + " <- ".join(rendered_stack))

    if variables:
        rendered_variables = []
        for variable in variables:
            name = variable.get("name")
            if not isinstance(name, str):
                continue
            value = variable.get("value")
            if isinstance(value, str):
                rendered_variables.append(f"{name}={value}")
            else:
                rendered_variables.append(name)
        if rendered_variables:
            lines.append("locals: " + ", ".join(rendered_variables))
    return lines


def _compact_payload(
    *,
    action: str,
    execution: dict[str, Any] | None,
    location: dict[str, Any],
    backtrace: dict[str, Any],
    locals_result: dict[str, Any],
    include_raw: bool,
) -> dict[str, Any]:
    stack = _stack_from_backtrace(backtrace)
    variables = _variables_from_locals(locals_result)
    frame = _frame_from_location(location)
    payload: dict[str, Any] = {
        "ok": all(
            item.get("ok")
            for item in (location, backtrace, locals_result)
        )
        and (execution is None or bool(execution.get("ok"))),
        "action": action,
        "summary": "\n".join(
            _summary_lines(
                action=action,
                execution=execution,
                location=location,
                stack=stack,
                variables=variables,
            )
        ),
        "stop_reason": _last_stop_reason(execution or location),
        "location": frame,
        "backtrace": stack,
        "locals": variables,
    }
    if execution is not None:
        payload["output"] = _target_output(execution)
        payload["execution"] = {
            key: execution.get(key)
            for key in (
                "ok",
                "command",
                "result_class",
                "stopped",
                "timed_out",
                "interrupted",
                "error",
                "truncated",
            )
        }
    if include_raw:
        payload["raw"] = {
            "execution": execution,
            "location": location,
            "backtrace": backtrace,
            "locals": locals_result,
        }
    return payload


def _execution_has_frame(execution: dict[str, Any]) -> bool:
    stopped = execution.get("stopped")
    return isinstance(stopped, dict) and isinstance(stopped.get("frame"), dict)


def _require_max_frames(max_frames: int) -> None:
    if not 1 <= max_frames <= 1_000:
        raise ValueError("max_frames must be between 1 and 1000")


def _execution_only_payload(
    *,
    action: str,
    execution: dict[str, Any],
    include_raw: bool,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ok": bool(execution.get("ok")),
        "action": action,
        "summary": "\n".join(
            _summary_lines(
                action=action,
                execution=execution,
                location={},
                stack=[],
                variables=[],
            )
        ),
        "stop_reason": _last_stop_reason(execution),
        "location": None,
        "backtrace": [],
        "locals": [],
        "output": _target_output(execution),
        "execution": {
            key: execution.get(key)
            for key in (
                "ok",
                "command",
                "result_class",
                "stopped",
                "timed_out",
                "interrupted",
                "error",
                "truncated",
            )
        },
    }
    if include_raw:
        payload["raw"] = {"execution": execution}
    return payload


async def _collect_context(
    session_id: str,
    *,
    action: str,
    execution: dict[str, Any] | None = None,
    max_frames: int = 10,
    include_raw: bool = False,
) -> dict[str, Any]:
    _require_max_frames(max_frames)
    if execution is not None and not _execution_has_frame(execution):
        return _execution_only_payload(
            action=action,
            execution=execution,
            include_raw=include_raw,
        )

    location, backtrace, locals_result = await asyncio.gather(
        gdb_current_location(session_id),
        gdb_backtrace(session_id, max_frames=max_frames),
        gdb_locals(session_id),
    )
    return _compact_payload(
        action=action,
        execution=execution,
        location=location,
        backtrace=backtrace,
        locals_result=locals_result,
        include_raw=include_raw,
    )


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
_REGISTER_NAME_RE = re.compile(r"^\$?[A-Za-z_][A-Za-z0-9_]*$")
_SOURCE_LINE_RE = re.compile(r"^\s*(?:=>\s*)?(?P<line>[0-9]+)\s+(?P<text>.*)$")
_INFO_LINE_RE = re.compile(r'Line (?P<line>[0-9]+) of "(?P<file>[^"]+)"')
_INFO_SOURCE_RE = re.compile(r"Current source file is (?P<file>.+?)(?:\n|$)")
_HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
_MAPPING_LINE_RE = re.compile(
    r"^\s*(?P<start>0x[0-9a-fA-F]+)\s+"
    r"(?P<end>0x[0-9a-fA-F]+)\s+"
    r"(?P<size>0x[0-9a-fA-F]+)\s+"
    r"(?P<offset>0x[0-9a-fA-F]+)"
    r"(?:\s+(?P<perms>[rwxps-]{3,5}))?"
    r"(?:\s+(?P<objfile>.*))?$"
)
_DISASSEMBLY_LINE_RE = re.compile(
    r"^\s*(?P<current>=>)?\s*"
    r"(?P<addr>0x[0-9a-fA-F]+)"
    r"(?:\s+<(?P<symbol>[^>]+)>)?:\s*"
    r"(?P<asm>.*)$"
)
_BUILD_ID_RE = re.compile(r"Build ID:\s*(?P<build_id>[0-9A-Fa-f]+)")


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


def _require_register_name(register: str) -> str:
    _require_single_line("register", register)
    normalized = register.strip()
    if not _REGISTER_NAME_RE.fullmatch(normalized):
        raise ValueError("register must be a single register name such as rax or $pc")
    return normalized if normalized.startswith("$") else f"${normalized}"


def _parse_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    match = _HEX_RE.search(value)
    if match is not None:
        return int(match.group(0), 16)
    stripped = value.strip()
    if stripped.isdigit():
        return int(stripped, 10)
    return None


def _hex_or_none(value: int | None) -> str | None:
    return hex(value) if value is not None else None


def _mapping_name(mapping: dict[str, Any]) -> str:
    objfile = str(mapping.get("objfile") or "")
    if objfile:
        return os.path.basename(objfile) or objfile
    return str(mapping.get("name") or "")


def _classify_mapping(mapping: dict[str, Any]) -> str:
    objfile = str(mapping.get("objfile") or "")
    name = _mapping_name(mapping)
    lowered = f"{objfile} {name}".lower()
    if "[stack" in lowered:
        return "stack"
    if "[heap" in lowered:
        return "heap"
    if "[vdso" in lowered:
        return "vdso"
    if "[vvar" in lowered:
        return "vvar"
    if "[anon" in lowered or not objfile:
        return "anonymous"
    if "libc" in lowered:
        return "libc"
    if "ld-linux" in lowered or "/ld-" in lowered:
        return "loader"
    return "file"


def _parse_mappings(console: str) -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []
    for line in console.splitlines():
        match = _MAPPING_LINE_RE.match(line)
        if match is None:
            continue
        start = int(match.group("start"), 16)
        end = int(match.group("end"), 16)
        offset = int(match.group("offset"), 16)
        objfile = (match.group("objfile") or "").strip()
        perms = match.group("perms") or ""
        mapping = {
            "start": hex(start),
            "end": hex(end),
            "size": hex(end - start),
            "offset": hex(offset),
            "perms": perms,
            "objfile": objfile,
            "name": os.path.basename(objfile) if objfile else f"[anon_{start >> 32:#x}]",
            "kind": "",
        }
        mapping["kind"] = _classify_mapping(mapping)
        mappings.append(mapping)
    return mappings


def _address_in_mapping(address: int, mapping: dict[str, Any]) -> bool:
    start = _parse_int(mapping.get("start"))
    end = _parse_int(mapping.get("end"))
    return start is not None and end is not None and start <= address < end


def _find_mapping(address: int, mappings: list[dict[str, Any]]) -> dict[str, Any] | None:
    for mapping in mappings:
        if _address_in_mapping(address, mapping):
            return mapping
    return None


def _address_mapping_info(
    address: int | None,
    mappings: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if address is None:
        return None
    mapping = _find_mapping(address, mappings)
    if mapping is None:
        return None
    start = _parse_int(mapping.get("start"))
    file_offset = _parse_int(mapping.get("offset"))
    offset_in_mapping = address - start if start is not None else None
    module_offset = (
        file_offset + offset_in_mapping
        if file_offset is not None and offset_in_mapping is not None
        else None
    )
    return {
        "mapping": mapping,
        "offset_in_mapping": _hex_or_none(offset_in_mapping),
        "file_offset": _hex_or_none(module_offset),
        "module": _mapping_name(mapping),
        "module_offset": _hex_or_none(address - start) if start is not None else None,
        "module_file_offset": _hex_or_none(module_offset),
    }


def _parse_disassembly(console: str, current_address: int | None = None) -> list[dict[str, Any]]:
    instructions: list[dict[str, Any]] = []
    for line in console.splitlines():
        match = _DISASSEMBLY_LINE_RE.match(line)
        if match is None:
            continue
        address = int(match.group("addr"), 16)
        assembly = match.group("asm").strip()
        instruction = {
            "address": hex(address),
            "symbol": match.group("symbol") or "",
            "asm": assembly,
            "current": bool(match.group("current"))
            or (current_address is not None and address == current_address),
            "raw": line,
        }
        target = _parse_int(assembly)
        if target is not None:
            instruction["target"] = hex(target)
        instructions.append(instruction)
    return instructions


def _read_memory_contents(payload: dict[str, Any]) -> bytes:
    memory = payload.get("results", {}).get("memory", [])
    if not isinstance(memory, list) or not memory:
        return b""
    contents = memory[0].get("contents", "")
    if not isinstance(contents, str) or not contents:
        return b""
    try:
        return bytes.fromhex(contents)
    except ValueError:
        return b""


def _source_context(
    list_console: str,
    info_line_console: str = "",
    info_source_console: str = "",
) -> dict[str, Any]:
    lines: list[dict[str, Any]] = []
    for raw_line in list_console.splitlines():
        match = _SOURCE_LINE_RE.match(raw_line)
        if match is None:
            continue
        lines.append(
            {
                "line": int(match.group("line")),
                "text": match.group("text"),
                "raw": raw_line,
            }
        )

    info_line = _INFO_LINE_RE.search(info_line_console)
    info_source = _INFO_SOURCE_RE.search(info_source_console)
    file_path = ""
    current_line = 0
    if info_line is not None:
        file_path = info_line.group("file")
        current_line = int(info_line.group("line"))
    elif info_source is not None:
        file_path = info_source.group("file").strip().strip('"')

    line_start = lines[0]["line"] if lines else 0
    line_end = lines[-1]["line"] if lines else 0
    context: dict[str, Any] = {
        "file_path": file_path,
        "line_start": line_start,
        "line_end": line_end,
        "current_line": current_line,
        "lines": lines,
    }
    if file_path and line_start:
        context["vscode_uri"] = f"vscode://file{file_path}:{line_start}"
    return context


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


@mcp.tool(annotations=SESSION_MUTATION)
async def gdb_stop_recording(session_id: str, timeout: float = 10.0) -> dict[str, Any]:
    """Stop GDB process recording when a recording target is active."""

    try:
        session = await manager.get(session_id)
        return _result(session, await session.execute("record stop", timeout=timeout))
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_record_status(session_id: str) -> dict[str, Any]:
    """Return GDB recording status."""

    try:
        session = await manager.get(session_id)
        return _result(session, await session.execute("info record", timeout=10.0))
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=TARGET_EXECUTION)
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


@mcp.tool(annotations=TARGET_EXECUTION)
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


@mcp.tool(annotations=TARGET_EXECUTION)
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


@mcp.tool(annotations=TARGET_EXECUTION)
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


@mcp.tool(annotations=SESSION_MUTATION)
async def gdb_set_breakpoint(
    session_id: str,
    location: str,
    condition: str | None = None,
    temporary: bool = False,
    hardware: bool = False,
) -> dict[str, Any]:
    """Set a breakpoint using GDB CLI syntax."""

    try:
        _require_single_line("location", location)
        if condition is not None:
            _require_single_line("condition", condition)
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
async def gdb_context(
    session_id: str,
    max_frames: int = 10,
    include_raw: bool = False,
) -> dict[str, Any]:
    """Return a compact current location, backtrace, and locals summary."""

    try:
        return await _collect_context(
            session_id,
            action="context",
            max_frames=max_frames,
            include_raw=include_raw,
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=TARGET_EXECUTION)
async def gdb_run_and_context(
    session_id: str,
    args: list[str] | None = None,
    timeout: float = 30.0,
    auto_interrupt: bool = True,
    max_frames: int = 10,
    include_raw: bool = False,
) -> dict[str, Any]:
    """Run or restart the inferior, then return a compact stop context."""

    try:
        _require_max_frames(max_frames)
        execution = await gdb_run(
            session_id,
            args=args,
            timeout=timeout,
            auto_interrupt=auto_interrupt,
        )
        return await _collect_context(
            session_id,
            action="run",
            execution=execution,
            max_frames=max_frames,
            include_raw=include_raw,
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=TARGET_EXECUTION)
async def gdb_continue_and_context(
    session_id: str,
    timeout: float = 30.0,
    auto_interrupt: bool = True,
    max_frames: int = 10,
    include_raw: bool = False,
) -> dict[str, Any]:
    """Continue execution, then return a compact stop or exit summary."""

    try:
        _require_max_frames(max_frames)
        execution = await gdb_continue(
            session_id,
            timeout=timeout,
            auto_interrupt=auto_interrupt,
        )
        return await _collect_context(
            session_id,
            action="continue",
            execution=execution,
            max_frames=max_frames,
            include_raw=include_raw,
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=TARGET_EXECUTION)
async def gdb_step_and_context(
    session_id: str,
    instruction: bool = False,
    timeout: float = 15.0,
    max_frames: int = 10,
    include_raw: bool = False,
) -> dict[str, Any]:
    """Step into one source line or instruction, then return compact context."""

    try:
        _require_max_frames(max_frames)
        execution = await gdb_step(
            session_id,
            instruction=instruction,
            timeout=timeout,
        )
        return await _collect_context(
            session_id,
            action="step",
            execution=execution,
            max_frames=max_frames,
            include_raw=include_raw,
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=TARGET_EXECUTION)
async def gdb_next_and_context(
    session_id: str,
    instruction: bool = False,
    timeout: float = 15.0,
    max_frames: int = 10,
    include_raw: bool = False,
) -> dict[str, Any]:
    """Step over one source line or instruction, then return compact context."""

    try:
        _require_max_frames(max_frames)
        execution = await gdb_next(
            session_id,
            instruction=instruction,
            timeout=timeout,
        )
        return await _collect_context(
            session_id,
            action="next",
            execution=execution,
            max_frames=max_frames,
            include_raw=include_raw,
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=TARGET_EXECUTION)
async def gdb_reverse_continue_and_context(
    session_id: str,
    timeout: float = 30.0,
    auto_interrupt: bool = True,
    max_frames: int = 10,
    include_raw: bool = False,
) -> dict[str, Any]:
    """Run backward, then return a compact stop or exit summary."""

    try:
        _require_max_frames(max_frames)
        execution = await gdb_reverse_continue(
            session_id,
            timeout=timeout,
            auto_interrupt=auto_interrupt,
        )
        return await _collect_context(
            session_id,
            action="reverse-continue",
            execution=execution,
            max_frames=max_frames,
            include_raw=include_raw,
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=TARGET_EXECUTION)
async def gdb_reverse_step_and_context(
    session_id: str,
    instruction: bool = False,
    timeout: float = 15.0,
    max_frames: int = 10,
    include_raw: bool = False,
) -> dict[str, Any]:
    """Step backward into one line or instruction, then return compact context."""

    try:
        _require_max_frames(max_frames)
        execution = await gdb_reverse_step(
            session_id,
            instruction=instruction,
            timeout=timeout,
        )
        return await _collect_context(
            session_id,
            action="reverse-step",
            execution=execution,
            max_frames=max_frames,
            include_raw=include_raw,
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=TARGET_EXECUTION)
async def gdb_reverse_next_and_context(
    session_id: str,
    instruction: bool = False,
    timeout: float = 15.0,
    max_frames: int = 10,
    include_raw: bool = False,
) -> dict[str, Any]:
    """Step backward over one line or instruction, then return compact context."""

    try:
        _require_max_frames(max_frames)
        execution = await gdb_reverse_next(
            session_id,
            instruction=instruction,
            timeout=timeout,
        )
        return await _collect_context(
            session_id,
            action="reverse-next",
            execution=execution,
            max_frames=max_frames,
            include_raw=include_raw,
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=TARGET_EXECUTION)
async def gdb_reverse_finish_and_context(
    session_id: str,
    timeout: float = 15.0,
    max_frames: int = 10,
    include_raw: bool = False,
) -> dict[str, Any]:
    """Run backward to the caller, then return compact context."""

    try:
        _require_max_frames(max_frames)
        execution = await gdb_reverse_finish(session_id, timeout=timeout)
        return await _collect_context(
            session_id,
            action="reverse-finish",
            execution=execution,
            max_frames=max_frames,
            include_raw=include_raw,
        )
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
async def gdb_disassemble_around_pc(
    session_id: str,
    bytes_before: int = 32,
    bytes_after: int = 96,
    mixed: bool = False,
    raw_bytes: bool = False,
) -> dict[str, Any]:
    """Disassemble a byte window around the current program counter."""

    try:
        if not 0 <= bytes_before <= 4096:
            raise ValueError("bytes_before must be between 0 and 4096")
        if not 1 <= bytes_after <= 4096:
            raise ValueError("bytes_after must be between 1 and 4096")
        options = ""
        if mixed or raw_bytes:
            options = "/" + ("m" if mixed else "") + ("r" if raw_bytes else "")
        command = (
            f"disassemble {options} $pc-{bytes_before},$pc+{bytes_after}"
        ).replace("  ", " ")
        session = await manager.get(session_id)
        return _result(session, await session.execute(command, timeout=10.0))
    except Exception as exc:
        return _error(exc)


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
        payload = _result(session, await session.execute(command, timeout=10.0))
        info_line = _result(session, await session.execute("info line", timeout=5.0))
        info_source = _result(session, await session.execute("info source", timeout=5.0))
        return {
            **payload,
            "source": _source_context(
                str(payload.get("console") or ""),
                str(info_line.get("console") or ""),
                str(info_source.get("console") or ""),
            ),
            "source_metadata": {
                "info_line_ok": info_line.get("ok"),
                "info_source_ok": info_source.get("ok"),
            },
        }
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
async def gdb_register_names(
    session_id: str,
    register_numbers: list[int] | None = None,
) -> dict[str, Any]:
    """List register names, optionally limited to GDB register numbers."""

    try:
        if register_numbers and any(item < 0 for item in register_numbers):
            raise ValueError("Register numbers must be non-negative")
        suffix = ""
        if register_numbers:
            suffix = " " + " ".join(str(item) for item in register_numbers)
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(f"-data-list-register-names{suffix}", timeout=10.0),
        )
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_read_register(
    session_id: str,
    register: str,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Read one register by architecture name, such as rax, pc, sp, or $rip."""

    try:
        expression = _require_register_name(register)
        session = await manager.get(session_id)
        payload = _result(
            session,
            await session.execute(
                f"-data-evaluate-expression {c_escape(expression)}",
                timeout=timeout,
            ),
        )
        value = payload.get("results", {}).get("value")
        return {
            **payload,
            "register": expression.removeprefix("$"),
            "expression": expression,
            "value": value,
        }
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


async def _evaluate_address(
    session: GdbSession,
    expression: str,
    *,
    timeout: float = 10.0,
) -> tuple[dict[str, Any], int | None]:
    _require_read_expression("expression", expression)
    payload = _result(
        session,
        await session.execute(
            f"-data-evaluate-expression {c_escape(expression)}",
            timeout=timeout,
        ),
    )
    value = payload.get("results", {}).get("value")
    address = _parse_int(value)
    if address is None:
        address = _parse_int(expression)
    return payload, address


async def _structured_mappings(session: GdbSession) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    primary = _result(session, await session.execute("info proc mappings", timeout=10.0))
    mappings = _parse_mappings(str(primary.get("console") or ""))
    fallback: dict[str, Any] | None = None
    if not mappings:
        fallback = _result(
            session,
            await session.execute("maintenance info sections", timeout=10.0),
        )
        mappings = _parse_mappings(str(fallback.get("console") or ""))
    payload = {
        **primary,
        "mappings": mappings,
        "mapping_count": len(mappings),
        "fallback": fallback,
    }
    return payload, mappings


@mcp.tool(annotations=READ_ONLY)
async def gdb_vmmap_structured(
    session_id: str,
    address: str | None = None,
    module: str | None = None,
    executable: bool = False,
    writable: bool = False,
    include_gaps: bool = False,
) -> dict[str, Any]:
    """Return structured virtual memory mappings with address/module/perms filters."""

    try:
        if address is not None:
            _require_read_expression("address", address)
        if module is not None:
            _require_single_line("module", module)
        session = await manager.get(session_id)
        address_payload: dict[str, Any] | None = None
        address_value: int | None = None
        if address is not None:
            address_payload, address_value = await _evaluate_address(session, address)
        payload, mappings = await _structured_mappings(session)
        filtered = mappings
        if address_value is not None:
            filtered = [item for item in filtered if _address_in_mapping(address_value, item)]
        if module:
            lowered = module.lower()
            filtered = [
                item
                for item in filtered
                if lowered in str(item.get("objfile", "")).lower()
                or lowered in str(item.get("name", "")).lower()
            ]
        if executable:
            filtered = [item for item in filtered if "x" in str(item.get("perms", ""))]
        if writable:
            filtered = [item for item in filtered if "w" in str(item.get("perms", ""))]

        gaps: list[dict[str, str]] = []
        if include_gaps:
            ordered = sorted(
                mappings,
                key=lambda item: _parse_int(item.get("start")) or 0,
            )
            for left, right in zip(ordered, ordered[1:], strict=False):
                left_end = _parse_int(left.get("end"))
                right_start = _parse_int(right.get("start"))
                if left_end is not None and right_start is not None and left_end < right_start:
                    gaps.append(
                        {
                            "start": hex(left_end),
                            "end": hex(right_start),
                            "size": hex(right_start - left_end),
                        }
                    )
        return {
            **payload,
            "ok": bool(payload.get("ok")),
            "filters": {
                "address": address,
                "module": module,
                "executable": executable,
                "writable": writable,
            },
            "address": _hex_or_none(address_value),
            "address_evaluation": address_payload,
            "mappings": filtered,
            "all_mapping_count": len(mappings),
            "mapping_count": len(filtered),
            "gaps": gaps,
        }
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_address_info(
    session_id: str,
    expression: str,
    read_string: bool = True,
    string_max_bytes: int = 256,
) -> dict[str, Any]:
    """Resolve an address expression to mapping, module offset, symbol, and string context."""

    try:
        if not 1 <= string_max_bytes <= 4096:
            raise ValueError("string_max_bytes must be between 1 and 4096")
        session = await manager.get(session_id)
        evaluation, address = await _evaluate_address(session, expression)
        vmmap_payload, mappings = await _structured_mappings(session)
        mapping_info = _address_mapping_info(address, mappings)
        symbol: dict[str, Any] | None = None
        string_payload: dict[str, Any] | None = None
        string_value = ""
        if address is not None:
            symbol_result = _result(
                session,
                await session.execute(f"info symbol {hex(address)}", timeout=5.0),
            )
            symbol = {
                "ok": symbol_result.get("ok"),
                "console": symbol_result.get("console"),
            }
            if read_string and mapping_info is not None:
                perms = str(mapping_info["mapping"].get("perms", ""))
                if "r" in perms or not perms:
                    string_payload = await gdb_read_c_string(
                        session_id,
                        hex(address),
                        max_bytes=string_max_bytes,
                    )
                    string_value = str(string_payload.get("string") or "")
        return {
            "ok": bool(evaluation.get("ok")),
            "session_id": session_id,
            "expression": expression,
            "address": _hex_or_none(address),
            "evaluation": evaluation,
            "mapping_info": mapping_info,
            "symbol": symbol,
            "string": string_value,
            "string_result": string_payload,
            "vmmap_ok": vmmap_payload.get("ok"),
        }
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_telescope(
    session_id: str,
    address: str = "$sp",
    count: int = 8,
    pointer_size: int = 8,
    max_depth: int = 1,
    reverse: bool = False,
) -> dict[str, Any]:
    """Read pointer-sized stack/memory slots and annotate recursively dereferenced values."""

    try:
        if not 1 <= count <= 128:
            raise ValueError("count must be between 1 and 128")
        if pointer_size not in {4, 8}:
            raise ValueError("pointer_size must be 4 or 8")
        if not 0 <= max_depth <= 4:
            raise ValueError("max_depth must be between 0 and 4")
        session = await manager.get(session_id)
        evaluation, start = await _evaluate_address(session, address)
        if start is None:
            return {
                "ok": False,
                "session_id": session_id,
                "error": f"Could not resolve address expression: {address}",
                "evaluation": evaluation,
            }
        if reverse:
            start -= count * pointer_size
        vmmap_payload, mappings = await _structured_mappings(session)
        memory = _result(
            session,
            await session.execute(
                f"-data-read-memory-bytes {c_escape(hex(start))} {count * pointer_size}",
                timeout=10.0,
            ),
        )
        data = _read_memory_contents(memory)
        entries: list[dict[str, Any]] = []
        for index in range(count):
            offset = index * pointer_size
            chunk = data[offset : offset + pointer_size]
            if len(chunk) < pointer_size:
                break
            value = int.from_bytes(chunk, "little")
            entry: dict[str, Any] = {
                "index": index,
                "address": hex(start + offset),
                "value": hex(value),
                "mapping_info": _address_mapping_info(value, mappings),
                "chain": [],
            }
            current = value
            for depth in range(max_depth):
                current_info = _address_mapping_info(current, mappings)
                if current_info is None:
                    break
                perms = str(current_info["mapping"].get("perms", ""))
                if "r" not in perms and perms:
                    break
                deref = _result(
                    session,
                    await session.execute(
                        f"-data-read-memory-bytes {c_escape(hex(current))} {pointer_size}",
                        timeout=5.0,
                    ),
                )
                deref_data = _read_memory_contents(deref)
                if len(deref_data) < pointer_size:
                    break
                next_value = int.from_bytes(deref_data[:pointer_size], "little")
                entry["chain"].append(
                    {
                        "depth": depth + 1,
                        "address": hex(current),
                        "value": hex(next_value),
                        "mapping_info": _address_mapping_info(next_value, mappings),
                    }
                )
                current = next_value
            entries.append(entry)
        return {
            "ok": bool(memory.get("ok")),
            "session_id": session_id,
            "start": hex(start),
            "address_expression": address,
            "count": count,
            "pointer_size": pointer_size,
            "entries": entries,
            "evaluation": evaluation,
            "memory": memory,
            "vmmap_ok": vmmap_payload.get("ok"),
        }
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_nearpc(
    session_id: str,
    pc: str = "$pc",
    lines: int = 12,
    reverse: int = 4,
    instruction_bytes: int = 8,
) -> dict[str, Any]:
    """Disassemble near an address and return parsed instruction rows."""

    try:
        if not 1 <= lines <= 200:
            raise ValueError("lines must be between 1 and 200")
        if not 0 <= reverse <= 100:
            raise ValueError("reverse must be between 0 and 100")
        if not 1 <= instruction_bytes <= 16:
            raise ValueError("instruction_bytes must be between 1 and 16")
        session = await manager.get(session_id)
        evaluation, address = await _evaluate_address(session, pc)
        start_expression = pc
        if address is not None and reverse:
            start_expression = hex(max(0, address - reverse * instruction_bytes))
        command = f"x/{lines}i {start_expression}"
        disassembly = _result(session, await session.execute(command, timeout=10.0))
        instructions = _parse_disassembly(str(disassembly.get("console") or ""), address)
        vmmap_payload, mappings = await _structured_mappings(session)
        for instruction in instructions:
            target = _parse_int(instruction.get("target"))
            addr = _parse_int(instruction.get("address"))
            instruction["address_info"] = _address_mapping_info(addr, mappings)
            instruction["target_info"] = _address_mapping_info(target, mappings)
        return {
            **disassembly,
            "pc": _hex_or_none(address),
            "pc_expression": pc,
            "start_expression": start_expression,
            "instructions": instructions,
            "evaluation": evaluation,
            "vmmap_ok": vmmap_payload.get("ok"),
        }
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_piebase(
    session_id: str,
    offset: int = 0,
    module: str | None = None,
) -> dict[str, Any]:
    """Calculate a runtime virtual address from a PIE/module base plus offset."""

    try:
        if offset < 0:
            raise ValueError("offset must be non-negative")
        if module is not None:
            _require_single_line("module", module)
        session = await manager.get(session_id)
        payload, mappings = await _structured_mappings(session)
        candidates = mappings
        if module:
            lowered = module.lower()
            candidates = [
                item
                for item in candidates
                if lowered in str(item.get("objfile", "")).lower()
                or lowered in str(item.get("name", "")).lower()
            ]
        elif session.program:
            program = os.path.basename(session.program)
            candidates = [
                item
                for item in candidates
                if os.path.basename(str(item.get("objfile") or "")) == program
            ] or candidates
        candidates = sorted(candidates, key=lambda item: _parse_int(item.get("start")) or 0)
        base = _parse_int(candidates[0].get("start")) if candidates else None
        return {
            "ok": bool(payload.get("ok")) and base is not None,
            "session_id": session_id,
            "module": module,
            "base": _hex_or_none(base),
            "offset": hex(offset),
            "address": _hex_or_none(base + offset if base is not None else None),
            "mapping": candidates[0] if candidates else None,
            "mappings_considered": len(candidates),
            "vmmap": payload,
        }
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=SESSION_MUTATION)
async def gdb_break_rva(
    session_id: str,
    offset: int,
    module: str | None = None,
    temporary: bool = False,
    hardware: bool = False,
) -> dict[str, Any]:
    """Set a breakpoint at module PIE base plus an RVA-style offset."""

    try:
        base = await gdb_piebase(session_id, offset=offset, module=module)
        address = base.get("address")
        if not base.get("ok") or not isinstance(address, str):
            return {"ok": False, "error": "Could not calculate PIE base", "piebase": base}
        breakpoint = await gdb_set_breakpoint(
            session_id,
            f"*{address}",
            temporary=temporary,
            hardware=hardware,
        )
        return {
            "ok": bool(breakpoint.get("ok")),
            "address": address,
            "piebase": base,
            "breakpoint": breakpoint,
        }
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_pwn_context(
    session_id: str,
    max_frames: int = 10,
    telescope_count: int = 8,
    nearpc_lines: int = 12,
) -> dict[str, Any]:
    """Return a pwndbg-style structured context for stripped/optimized binaries."""

    try:
        _require_max_frames(max_frames)
        if not 1 <= telescope_count <= 64:
            raise ValueError("telescope_count must be between 1 and 64")
        if not 1 <= nearpc_lines <= 100:
            raise ValueError("nearpc_lines must be between 1 and 100")
        await manager.get(session_id)
        (
            location,
            backtrace,
            registers,
            pc,
            sp,
            vmmap,
        ) = await asyncio.gather(
            gdb_current_location(session_id),
            gdb_backtrace(session_id, max_frames=max_frames),
            gdb_registers(session_id),
            gdb_read_register(session_id, "pc"),
            gdb_read_register(session_id, "sp"),
            gdb_vmmap_structured(session_id),
        )
        nearpc = await gdb_nearpc(session_id, lines=nearpc_lines)
        telescope = await gdb_telescope(session_id, count=telescope_count)
        pc_info = None
        pc_value = pc.get("value")
        if isinstance(pc_value, str):
            pc_info = await gdb_address_info(session_id, pc_value, read_string=False)
        return {
            "ok": any(
                bool(item.get("ok"))
                for item in (location, backtrace, registers, pc, sp, vmmap, nearpc, telescope)
            ),
            "session_id": session_id,
            "summary": "\n".join(
                line
                for line in (
                    f"pc: {pc.get('value')}" if pc.get("value") else "",
                    f"sp: {sp.get('value')}" if sp.get("value") else "",
                    f"mappings: {vmmap.get('mapping_count')}"
                    if vmmap.get("mapping_count") is not None
                    else "",
                )
                if line
            ),
            "location": location,
            "backtrace": backtrace,
            "registers": registers,
            "pc": pc,
            "sp": sp,
            "pc_info": pc_info,
            "nearpc": nearpc,
            "stack": telescope,
            "vmmap": vmmap,
        }
    except Exception as exc:
        return _error(exc)


async def _run_readelf(file_path: str, args: list[str], timeout: float) -> dict[str, Any]:
    readelf = shutil.which("readelf")
    if readelf is None:
        return {"ok": False, "error": "readelf is not available on PATH"}
    process = await asyncio.create_subprocess_exec(
        readelf,
        "-W",
        *args,
        file_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return {"ok": False, "error": f"readelf timed out after {timeout} seconds"}
    return {
        "ok": process.returncode == 0,
        "returncode": process.returncode,
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
    }


async def _resolve_elf_file(
    *,
    session_id: str | None,
    file_path: str | None,
) -> tuple[str, GdbSession | None]:
    if file_path is not None:
        _require_single_line("file_path", file_path)
        return file_path, None
    if session_id is None:
        raise ValueError("Provide session_id or file_path")
    session = await manager.get(session_id)
    if not session.program:
        raise ValueError("Session has no loaded program; provide file_path")
    return session.program, session


def _parse_elf_header(header: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in header.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip().lower().replace(" ", "_")] = value.strip()
    return fields


def _parse_checksec(
    header: str,
    program_headers: str,
    dynamic: str,
    symbols: str,
) -> dict[str, Any]:
    header_fields = _parse_elf_header(header)
    elf_type = header_fields.get("type", "")
    gnu_stack_line = next(
        (line for line in program_headers.splitlines() if "GNU_STACK" in line),
        "",
    )
    has_gnu_relro = "GNU_RELRO" in program_headers
    bind_now = "BIND_NOW" in dynamic or "(FLAGS)" in dynamic and "NOW" in dynamic
    canary = "__stack_chk_fail" in symbols
    stack_exec = False
    if gnu_stack_line:
        parts = gnu_stack_line.split()
        flags = parts[-1] if parts else ""
        stack_exec = "E" in flags
    if has_gnu_relro and bind_now:
        relro = "Full RELRO"
    elif has_gnu_relro:
        relro = "Partial RELRO"
    else:
        relro = "No RELRO"
    return {
        "arch": header_fields.get("machine", ""),
        "type": elf_type,
        "entry": header_fields.get("entry_point_address", ""),
        "pie": "DYN" in elf_type,
        "nx": not stack_exec,
        "canary": canary,
        "relro": relro,
        "bind_now": bind_now,
        "gnu_stack": gnu_stack_line.strip(),
    }


def _parse_sections(sections_output: str) -> list[dict[str, str]]:
    sections: list[dict[str, str]] = []
    section_re = re.compile(
        r"^\s*\[\s*(?P<index>\d+)\]\s+"
        r"(?P<name>\S+)\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<addr>[0-9A-Fa-f]+)\s+"
        r"(?P<off>[0-9A-Fa-f]+)\s+"
        r"(?P<size>[0-9A-Fa-f]+)\s+"
        r"(?P<entsize>[0-9A-Fa-f]+)\s+"
        r"(?P<flags>\S*)"
    )
    for line in sections_output.splitlines():
        match = section_re.match(line)
        if match is None:
            continue
        item = match.groupdict()
        item["addr"] = hex(int(item["addr"], 16))
        item["offset"] = hex(int(item.pop("off"), 16))
        item["size"] = hex(int(item["size"], 16))
        sections.append(item)
    return sections


@mcp.tool(annotations=READ_ONLY)
async def gdb_checksec(
    session_id: str | None = None,
    file_path: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Return ELF hardening settings such as PIE, NX, RELRO, and stack canary."""

    try:
        path, session = await _resolve_elf_file(session_id=session_id, file_path=file_path)
        header, program_headers, dynamic, symbols, notes = await asyncio.gather(
            _run_readelf(path, ["-h"], timeout),
            _run_readelf(path, ["-l"], timeout),
            _run_readelf(path, ["-d"], timeout),
            _run_readelf(path, ["-s"], timeout),
            _run_readelf(path, ["-n"], timeout),
        )
        ok = bool(header.get("ok") and program_headers.get("ok"))
        security = _parse_checksec(
            str(header.get("stdout") or ""),
            str(program_headers.get("stdout") or ""),
            str(dynamic.get("stdout") or ""),
            str(symbols.get("stdout") or ""),
        )
        notes_stdout = str(notes.get("stdout") or "")
        build_id_match = _BUILD_ID_RE.search(notes_stdout)
        security["build_id"] = build_id_match.group("build_id") if build_id_match else ""
        security["ibt"] = "IBT" in notes_stdout
        security["shstk"] = "SHSTK" in notes_stdout
        return {
            "ok": ok,
            "session_id": session.session_id if session else session_id,
            "file_path": path,
            "security": security,
            "commands": {
                "header": header,
                "program_headers": program_headers,
                "dynamic": dynamic,
                "symbols": symbols,
                "notes": notes,
            },
        }
    except Exception as exc:
        return _error(exc)


@mcp.tool(annotations=READ_ONLY)
async def gdb_elf_info(
    session_id: str | None = None,
    file_path: str | None = None,
    include_raw: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Return ELF header, security, section, segment, and build-id metadata."""

    try:
        path, session = await _resolve_elf_file(session_id=session_id, file_path=file_path)
        header, sections, program_headers, dynamic, notes = await asyncio.gather(
            _run_readelf(path, ["-h"], timeout),
            _run_readelf(path, ["-S"], timeout),
            _run_readelf(path, ["-l"], timeout),
            _run_readelf(path, ["-d"], timeout),
            _run_readelf(path, ["-n"], timeout),
        )
        symbols = await _run_readelf(path, ["-s"], timeout)
        header_stdout = str(header.get("stdout") or "")
        sections_stdout = str(sections.get("stdout") or "")
        notes_stdout = str(notes.get("stdout") or "")
        build_id_match = _BUILD_ID_RE.search(notes_stdout)
        payload: dict[str, Any] = {
            "ok": bool(header.get("ok")),
            "session_id": session.session_id if session else session_id,
            "file_path": path,
            "header": _parse_elf_header(header_stdout),
            "sections": _parse_sections(sections_stdout),
            "section_count": len(_parse_sections(sections_stdout)),
            "security": _parse_checksec(
                header_stdout,
                str(program_headers.get("stdout") or ""),
                str(dynamic.get("stdout") or ""),
                str(symbols.get("stdout") or ""),
            ),
            "build_id": build_id_match.group("build_id") if build_id_match else "",
        }
        if include_raw:
            payload["raw"] = {
                "header": header,
                "sections": sections,
                "program_headers": program_headers,
                "dynamic": dynamic,
                "notes": notes,
                "symbols": symbols,
            }
        return payload
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
async def gdb_command_reference() -> dict[str, Any]:
    """Return common safe tool flows and GDB/MI command equivalents."""

    return {
        "ok": True,
        "recommended_flow": [
            "gdb_create_session",
            "gdb_set_breakpoint",
            "gdb_run_and_context",
            "gdb_context",
            "gdb_pwn_context",
            "gdb_address_info",
            "gdb_read_register",
            "gdb_nearpc",
            "gdb_telescope",
            "gdb_continue_and_context",
            "gdb_close_session",
        ],
        "safe_tools": {
            "breakpoints": ["gdb_set_breakpoint", "gdb_list_breakpoints"],
            "execution": [
                "gdb_run_and_context",
                "gdb_continue_and_context",
                "gdb_step_and_context",
                "gdb_next_and_context",
            ],
            "state": [
                "gdb_context",
                "gdb_backtrace",
                "gdb_locals",
                "gdb_read_register",
                "gdb_register_names",
                "gdb_read_memory",
                "gdb_pwn_context",
                "gdb_address_info",
                "gdb_telescope",
                "gdb_vmmap_structured",
            ],
            "source": [
                "gdb_source",
                "gdb_find_source",
                "gdb_disassemble",
                "gdb_disassemble_around_pc",
                "gdb_nearpc",
            ],
            "binary_analysis": [
                "gdb_pwn_context",
                "gdb_vmmap_structured",
                "gdb_address_info",
                "gdb_telescope",
                "gdb_nearpc",
                "gdb_piebase",
                "gdb_break_rva",
                "gdb_checksec",
                "gdb_elf_info",
            ],
        },
        "common_mi_commands": [
            {"mi": "-break-insert LOCATION", "tool": "gdb_set_breakpoint"},
            {"mi": "-break-delete NUM", "tool": "gdb_delete_breakpoint"},
            {"mi": "-exec-run", "tool": "gdb_run"},
            {"mi": "-exec-continue", "tool": "gdb_continue"},
            {"mi": "-exec-step", "tool": "gdb_step"},
            {"mi": "-exec-next", "tool": "gdb_next"},
            {"mi": "-stack-list-frames 0 N", "tool": "gdb_backtrace"},
            {"mi": "-data-evaluate-expression EXPR", "tool": "gdb_eval_expression"},
            {"mi": "-data-list-register-values FMT", "tool": "gdb_registers"},
            {"mi": "-data-read-memory-bytes ADDRESS COUNT", "tool": "gdb_read_memory"},
        ],
        "unsafe_note": (
            "Use gdb_execute only with --unsafe or GDB_MCP_ALLOW_UNSAFE=1. "
            "Prefer dedicated tools when available."
        ),
    }


@mcp.tool(annotations=READ_ONLY)
async def gdb_capabilities() -> dict[str, Any]:
    """Return a workflow-oriented capability index for agent tool selection."""

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
                "gdb_nearpc",
                "gdb_telescope",
                "gdb_piebase",
                "gdb_break_rva",
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


@mcp.tool(annotations=READ_ONLY)
async def gdb_server_health() -> dict[str, Any]:
    """Report server capabilities, safety mode, dependencies, and session count."""

    try:
        package_version = version("gdb-mcp")
    except PackageNotFoundError:
        package_version = "0+unknown"
    gdb_path = shutil.which("gdb")
    gdbserver_path = shutil.which("gdbserver")
    gdb_version, gdbserver_version = await asyncio.gather(
        _executable_version(gdb_path, "--version"),
        _executable_version(gdbserver_path, "--version"),
    )
    sessions = await manager.list()
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Full gdb-mcp backend server")
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
    return parser


def main() -> None:
    args = _build_parser().parse_args()

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
