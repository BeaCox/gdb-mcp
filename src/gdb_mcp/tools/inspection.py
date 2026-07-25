"""Inspection, source, register, and memory MCP tools."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..analysis import read_memory_contents as _read_memory_contents
from ..analysis import source_context as _source_context
from ..pagination import paginate_range, paginate_text_lines
from .execution import (
    gdb_continue,
    gdb_next,
    gdb_reverse_continue,
    gdb_reverse_finish,
    gdb_reverse_next,
    gdb_reverse_step,
    gdb_run,
    gdb_step,
)
from .shared import (
    _cli_disassemble_command,
    _cli_find_command,
    _cli_print_command,
    _cli_set_var_command,
    _compact_payload,
    _error,
    _execution_has_frame,
    _execution_only_payload,
    _mi_eval_expression_command,
    _mi_read_memory_bytes_command,
    _mi_write_memory_bytes_command,
    _profile_command_payload,
    _register_number_suffix,
    _require_cli_target,
    _require_hex_bytes,
    _require_max_frames,
    _require_output_profile,
    _require_positive_decimal_id,
    _require_read_expression,
    _require_register_name,
    _require_single_line,
    _require_unsafe_tool,
    _result,
    _stack_from_backtrace,
    _variables_from_locals,
    manager,
)


def register_tools(
    mcp: FastMCP[Any],
    *,
    read_only: ToolAnnotations,
    session_mutation: ToolAnnotations,
    target_execution: ToolAnnotations,
    destructive: ToolAnnotations,
) -> None:
    """Register thread, frame, expression, source, register, and memory tools."""

    mcp.tool(annotations=read_only)(gdb_threads)
    mcp.tool(annotations=session_mutation)(gdb_select_thread)
    mcp.tool(annotations=read_only)(gdb_backtrace)
    mcp.tool(annotations=session_mutation)(gdb_select_frame)
    mcp.tool(annotations=read_only)(gdb_locals)
    mcp.tool(annotations=read_only)(gdb_eval_expression)
    mcp.tool(annotations=read_only)(gdb_print)
    mcp.tool(annotations=target_execution)(gdb_call_function)
    mcp.tool(annotations=destructive)(gdb_set_variable)
    mcp.tool(annotations=read_only)(gdb_disassemble)
    mcp.tool(annotations=read_only)(gdb_current_location)
    mcp.tool(annotations=read_only)(gdb_context)
    mcp.tool(annotations=target_execution)(gdb_run_and_context)
    mcp.tool(annotations=target_execution)(gdb_continue_and_context)
    mcp.tool(annotations=target_execution)(gdb_step_and_context)
    mcp.tool(annotations=target_execution)(gdb_next_and_context)
    mcp.tool(annotations=target_execution)(gdb_reverse_continue_and_context)
    mcp.tool(annotations=target_execution)(gdb_reverse_step_and_context)
    mcp.tool(annotations=target_execution)(gdb_reverse_next_and_context)
    mcp.tool(annotations=target_execution)(gdb_reverse_finish_and_context)
    mcp.tool(annotations=read_only)(gdb_disassemble_current_frame)
    mcp.tool(annotations=read_only)(gdb_disassemble_around_pc)
    mcp.tool(annotations=read_only)(gdb_find_source)
    mcp.tool(annotations=read_only)(gdb_source)
    mcp.tool(annotations=read_only)(gdb_thread_apply_all_backtrace)
    mcp.tool(annotations=read_only)(gdb_stack_arguments)
    mcp.tool(annotations=read_only)(gdb_frame_variables)
    mcp.tool(annotations=read_only)(gdb_registers)
    mcp.tool(annotations=read_only)(gdb_register_names)
    mcp.tool(annotations=read_only)(gdb_read_register)
    mcp.tool(annotations=read_only)(gdb_read_memory)
    mcp.tool(annotations=destructive)(gdb_write_memory)
    mcp.tool(annotations=read_only)(gdb_search_memory)
    mcp.tool(annotations=read_only)(gdb_read_c_string)
    mcp.tool(annotations=read_only)(gdb_shared_libraries)
    mcp.tool(annotations=read_only)(gdb_info_files)
    mcp.tool(annotations=read_only)(gdb_memory_mappings)


async def _collect_context(
    session_id: str,
    *,
    action: str,
    execution: dict[str, Any] | None = None,
    max_frames: int = 10,
    include_raw: bool = False,
    output: str = "structured",
) -> dict[str, Any]:
    _require_max_frames(max_frames)
    profile = "raw" if include_raw else _require_output_profile(output)
    if execution is not None and not _execution_has_frame(execution):
        return _execution_only_payload(
            action=action,
            execution=execution,
            include_raw=include_raw,
            output=output,
        )

    child_output = "raw" if profile == "raw" else "structured"
    location, backtrace, locals_result = await asyncio.gather(
        gdb_current_location(session_id),
        gdb_backtrace(session_id, max_frames=max_frames, output=child_output),
        gdb_locals(session_id, output=child_output),
    )
    return _compact_payload(
        action=action,
        execution=execution,
        location=location,
        backtrace=backtrace,
        locals_result=locals_result,
        include_raw=include_raw,
        output=output,
    )


async def gdb_threads(session_id: str) -> dict[str, Any]:
    """List threads."""

    try:
        session = await manager.get(session_id)
        return _result(session, await session.execute("-thread-info", timeout=10.0))
    except Exception as exc:
        return _error(exc)


async def gdb_select_thread(session_id: str, thread_id: str) -> dict[str, Any]:
    """Select the current thread."""

    try:
        _require_positive_decimal_id("thread_id", thread_id)
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(f"-thread-select {thread_id}", timeout=10.0),
        )
    except Exception as exc:
        return _error(exc)


async def gdb_backtrace(
    session_id: str,
    max_frames: int = 50,
    output: str = "structured",
) -> dict[str, Any]:
    """Get stack frames."""

    try:
        if not 1 <= max_frames <= 1_000:
            raise ValueError("max_frames must be between 1 and 1000")
        _require_output_profile(output)
        high = max_frames - 1
        session = await manager.get(session_id)
        payload = _result(
            session,
            await session.execute(f"-stack-list-frames 0 {high}", timeout=10.0),
        )
        stack = _stack_from_backtrace(payload)
        return _profile_command_payload(
            payload,
            output,
            summary_fields={"frame_count": len(stack), "frames": stack[:5]},
        )
    except Exception as exc:
        return _error(exc)


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


async def gdb_locals(session_id: str, output: str = "structured") -> dict[str, Any]:
    """List local variables in the selected frame."""

    try:
        _require_output_profile(output)
        session = await manager.get(session_id)
        payload = _result(
            session,
            await session.execute(
                "-stack-list-variables --simple-values",
                timeout=10.0,
            ),
        )
        variables = _variables_from_locals(payload)
        return _profile_command_payload(
            payload,
            output,
            summary_fields={"variable_count": len(variables), "variables": variables[:20]},
        )
    except Exception as exc:
        return _error(exc)


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
                _mi_eval_expression_command(expression),
                timeout=timeout,
            ),
        )
    except Exception as exc:
        return _error(exc)


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
            await session.execute(_cli_print_command(expression), timeout=timeout),
        )
    except Exception as exc:
        return _error(exc)


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
        payload = _result(
            session,
            await session.execute(_cli_print_command(expression), timeout=timeout),
        )
        session.invalidate_pagination()
        return payload
    except Exception as exc:
        return _error(exc)


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
        payload = _result(
            session,
            await session.execute(_cli_set_var_command(expression, value), timeout=timeout),
        )
        session.invalidate_pagination()
        return payload
    except Exception as exc:
        return _error(exc)


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
                _cli_disassemble_command(options, target),
                timeout=10.0,
            ),
        )
    except Exception as exc:
        return _error(exc)


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


async def gdb_context(
    session_id: str,
    max_frames: int = 10,
    include_raw: bool = False,
    output: str = "structured",
) -> dict[str, Any]:
    """Return a compact current location, backtrace, and locals summary."""

    try:
        return await _collect_context(
            session_id,
            action="context",
            max_frames=max_frames,
            include_raw=include_raw,
            output=output,
        )
    except Exception as exc:
        return _error(exc)


async def gdb_run_and_context(
    session_id: str,
    args: list[str] | None = None,
    timeout: float = 30.0,
    auto_interrupt: bool = True,
    max_frames: int = 10,
    include_raw: bool = False,
    output: str = "structured",
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
            output=output,
        )
    except Exception as exc:
        return _error(exc)


async def gdb_continue_and_context(
    session_id: str,
    timeout: float = 30.0,
    auto_interrupt: bool = True,
    max_frames: int = 10,
    include_raw: bool = False,
    output: str = "structured",
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
            output=output,
        )
    except Exception as exc:
        return _error(exc)


async def gdb_step_and_context(
    session_id: str,
    instruction: bool = False,
    timeout: float = 15.0,
    max_frames: int = 10,
    include_raw: bool = False,
    output: str = "structured",
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
            output=output,
        )
    except Exception as exc:
        return _error(exc)


async def gdb_next_and_context(
    session_id: str,
    instruction: bool = False,
    timeout: float = 15.0,
    max_frames: int = 10,
    include_raw: bool = False,
    output: str = "structured",
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
            output=output,
        )
    except Exception as exc:
        return _error(exc)


async def gdb_reverse_continue_and_context(
    session_id: str,
    timeout: float = 30.0,
    auto_interrupt: bool = True,
    max_frames: int = 10,
    include_raw: bool = False,
    output: str = "structured",
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
            output=output,
        )
    except Exception as exc:
        return _error(exc)


async def gdb_reverse_step_and_context(
    session_id: str,
    instruction: bool = False,
    timeout: float = 15.0,
    max_frames: int = 10,
    include_raw: bool = False,
    output: str = "structured",
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
            output=output,
        )
    except Exception as exc:
        return _error(exc)


async def gdb_reverse_next_and_context(
    session_id: str,
    instruction: bool = False,
    timeout: float = 15.0,
    max_frames: int = 10,
    include_raw: bool = False,
    output: str = "structured",
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
            output=output,
        )
    except Exception as exc:
        return _error(exc)


async def gdb_reverse_finish_and_context(
    session_id: str,
    timeout: float = 15.0,
    max_frames: int = 10,
    include_raw: bool = False,
    output: str = "structured",
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
            output=output,
        )
    except Exception as exc:
        return _error(exc)


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
        command = _cli_disassemble_command(
            options,
            f"$pc-{bytes_before},$pc+{bytes_after}",
        )
        session = await manager.get(session_id)
        return _result(session, await session.execute(command, timeout=10.0))
    except Exception as exc:
        return _error(exc)


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


async def gdb_thread_apply_all_backtrace(
    session_id: str,
    max_frames: int = 50,
    output: str = "structured",
    cursor: str | None = None,
    page_size: int | None = None,
) -> dict[str, Any]:
    """Run backtrace on every thread."""

    try:
        if not 1 <= max_frames <= 1_000:
            raise ValueError("max_frames must be between 1 and 1000")
        _require_output_profile(output)
        session = await manager.get(session_id)
        payload = _result(
            session,
            await session.execute(
                f"thread apply all backtrace {max_frames}",
                timeout=15.0,
            ),
        )
        lines, pagination = paginate_text_lines(
            str(payload.get("console") or ""),
            cursor=cursor,
            page_size=page_size,
            default_page_size=200,
            max_page_size=2_000,
            cursor_scope=f"session:{session_id}:thread-all-backtrace:{max_frames}",
        )
        payload = {
            **payload,
            "lines": lines,
            "line_count": len(lines),
            "pagination": pagination,
        }
        if output != "raw":
            payload["console"] = "\n".join(lines)
        if output == "structured":
            payload.pop("console", None)
        return _profile_command_payload(payload, output)
    except Exception as exc:
        return _error(exc)


async def gdb_stack_arguments(
    session_id: str,
    max_frames: int = 50,
    output: str = "structured",
) -> dict[str, Any]:
    """List stack frame arguments."""

    try:
        if not 1 <= max_frames <= 1_000:
            raise ValueError("max_frames must be between 1 and 1000")
        _require_output_profile(output)
        high = max_frames - 1
        session = await manager.get(session_id)
        payload = _result(
            session,
            await session.execute(
                f"-stack-list-arguments --simple-values 0 {high}",
                timeout=10.0,
            ),
        )
        return _profile_command_payload(payload, output)
    except Exception as exc:
        return _error(exc)


async def gdb_frame_variables(
    session_id: str,
    mode: str = "locals",
    output: str = "structured",
) -> dict[str, Any]:
    """List variables for the selected frame. mode is locals, args, or all."""

    try:
        _require_output_profile(output)
        commands = {
            "locals": "-stack-list-locals --simple-values",
            "args": "-stack-list-arguments --simple-values 0 0",
            "all": "-stack-list-variables --simple-values",
        }
        command = commands.get(mode)
        if command is None:
            raise ValueError("mode must be one of: locals, args, all")
        session = await manager.get(session_id)
        payload = _result(session, await session.execute(command, timeout=10.0))
        variables = _variables_from_locals(payload)
        return _profile_command_payload(
            payload,
            output,
            summary_fields={"mode": mode, "variable_count": len(variables)},
        )
    except Exception as exc:
        return _error(exc)


async def gdb_registers(
    session_id: str,
    register_numbers: list[int] | None = None,
    fmt: str = "x",
) -> dict[str, Any]:
    """Read register values."""

    try:
        if fmt not in {"x", "o", "t", "d", "r", "N"}:
            raise ValueError("fmt must be one of: x, o, t, d, r, N")
        suffix = _register_number_suffix(register_numbers)
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


async def gdb_register_names(
    session_id: str,
    register_numbers: list[int] | None = None,
) -> dict[str, Any]:
    """List register names, optionally limited to GDB register numbers."""

    try:
        suffix = _register_number_suffix(register_numbers)
        session = await manager.get(session_id)
        return _result(
            session,
            await session.execute(f"-data-list-register-names{suffix}", timeout=10.0),
        )
    except Exception as exc:
        return _error(exc)


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
                _mi_eval_expression_command(expression),
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


async def gdb_read_memory(
    session_id: str,
    address: str,
    count: int,
    output: str = "structured",
    cursor: str | None = None,
    page_size: int | None = None,
) -> dict[str, Any]:
    """Read raw memory bytes."""

    try:
        _require_read_expression("address", address)
        if not 1 <= count <= 1_048_576:
            raise ValueError("count must be between 1 and 1048576 bytes")
        _require_output_profile(output)
        session = await manager.get(session_id)
        page_start, page_end, pagination = paginate_range(
            count,
            cursor=cursor,
            page_size=page_size,
            default_page_size=count,
            max_page_size=1_048_576,
            cursor_scope=f"session:{session_id}:memory:{address}:{count}",
            snapshot=str(session.pagination_version),
        )
        read_count = max(0, page_end - page_start)
        read_address = f"({address})+{page_start}" if page_start else address
        if read_count:
            payload = _result(
                session,
                await session.execute(
                    _mi_read_memory_bytes_command(read_address, read_count),
                    timeout=10.0,
                ),
            )
        else:
            payload = {
                "ok": True,
                "session_id": session_id,
                "command": None,
                "result_class": "done",
                "results": {"memory": []},
                "truncated": False,
                "output_limit_chars": session.output_limit_chars,
            }
        byte_count = len(_read_memory_contents(payload))
        payload = {
            **payload,
            "address": address,
            "read_address": read_address,
            "requested_byte_count": count,
            "requested_page_bytes": read_count,
            "returned_byte_count": byte_count,
            "pagination": pagination,
        }
        return _profile_command_payload(
            payload,
            output,
            summary_fields={
                "address": address,
                "read_address": read_address,
                "requested_byte_count": count,
                "requested_page_bytes": read_count,
                "returned_byte_count": byte_count,
                "pagination": pagination,
            },
        )
    except Exception as exc:
        return _error(exc)


async def gdb_write_memory(
    session_id: str,
    address: str,
    data_hex: str,
) -> dict[str, Any]:
    """Write raw bytes to memory. Requires unsafe mode."""

    try:
        _require_unsafe_tool("gdb_write_memory")
        _require_cli_target("address", address)
        data = _require_hex_bytes("data_hex", data_hex)
        session = await manager.get(session_id)
        payload = _result(
            session,
            await session.execute(
                _mi_write_memory_bytes_command(address, data),
                timeout=10.0,
            ),
        )
        session.invalidate_pagination()
        return payload
    except Exception as exc:
        return _error(exc)


async def gdb_search_memory(
    session_id: str,
    start_address: str,
    length: int,
    pattern: str,
    output: str = "structured",
) -> dict[str, Any]:
    """Search memory for a GDB find pattern."""

    try:
        _require_read_expression("start_address", start_address)
        _require_read_expression("pattern", pattern)
        if not 1 <= length <= 1_048_576:
            raise ValueError("length must be between 1 and 1048576 bytes")
        if not pattern.strip():
            raise ValueError("pattern must not be empty")
        _require_output_profile(output)
        session = await manager.get(session_id)
        payload = _result(
            session,
            await session.execute(
                _cli_find_command(start_address, length, pattern),
                timeout=10.0,
            ),
        )
        return _profile_command_payload(payload, output)
    except Exception as exc:
        return _error(exc)


async def gdb_read_c_string(
    session_id: str,
    address: str,
    max_bytes: int = 4096,
    output: str = "structured",
) -> dict[str, Any]:
    """Read a NUL-terminated C string from memory."""

    try:
        _require_read_expression("address", address)
        if not 1 <= max_bytes <= 1_048_576:
            raise ValueError("max_bytes must be between 1 and 1048576")
        _require_output_profile(output)
        session = await manager.get(session_id)
        result = await session.execute(
            _mi_read_memory_bytes_command(address, max_bytes),
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
        return _profile_command_payload(
            {**payload, "string": string_value},
            output,
            summary_fields={
                "address": address,
                "max_bytes": max_bytes,
                "string": string_value,
            },
        )
    except Exception as exc:
        return _error(exc)


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


async def gdb_info_files(session_id: str) -> dict[str, Any]:
    """Return GDB's info files output."""

    try:
        session = await manager.get(session_id)
        return _result(session, await session.execute("info files", timeout=10.0))
    except Exception as exc:
        return _error(exc)


async def gdb_memory_mappings(
    session_id: str,
    output: str = "structured",
    cursor: str | None = None,
    page_size: int | None = None,
) -> dict[str, Any]:
    """Return process memory mappings when supported by the target."""

    try:
        _require_output_profile(output)
        session = await manager.get(session_id)
        payload = _result(session, await session.execute("info proc mappings", timeout=10.0))
        lines, pagination = paginate_text_lines(
            str(payload.get("console") or ""),
            cursor=cursor,
            page_size=page_size,
            default_page_size=200,
            max_page_size=2_000,
            cursor_scope=f"session:{session_id}:memory-mappings",
        )
        payload = {
            **payload,
            "lines": lines,
            "line_count": len(lines),
            "pagination": pagination,
        }
        if output != "raw":
            payload["console"] = "\n".join(lines)
        if output == "structured":
            payload.pop("console", None)
        return _profile_command_payload(payload, output)
    except Exception as exc:
        return _error(exc)
