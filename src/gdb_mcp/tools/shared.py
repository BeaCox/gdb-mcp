"""Shared dependencies and helper functions for tool modules."""

from __future__ import annotations

import re
from typing import Any

from ..config import ServerConfig
from ..mi import c_escape
from ..responses import command_response, error_response
from ..session import CommandResult, GdbMcpError, GdbSession, SessionManager

_manager: SessionManager | None = None
_runtime_config: ServerConfig | None = None


def configure(*, manager: SessionManager, runtime_config: ServerConfig) -> None:
    """Inject shared server state used by split tool modules."""

    global _manager, _runtime_config
    _manager = manager
    _runtime_config = runtime_config


def require_manager() -> SessionManager:
    if _manager is None:
        raise RuntimeError("tool modules are not configured")
    return _manager


def require_runtime_config() -> ServerConfig:
    if _runtime_config is None:
        raise RuntimeError("tool modules are not configured")
    return _runtime_config


class _ManagerProxy:
    def __getattr__(self, name: str) -> Any:
        return getattr(require_manager(), name)


class _RuntimeConfigProxy:
    def __getattr__(self, name: str) -> Any:
        return getattr(require_runtime_config(), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(require_runtime_config(), name, value)


manager = _ManagerProxy()
runtime_config = _RuntimeConfigProxy()


def _error(exc: Exception) -> dict[str, Any]:
    return error_response(exc)


def _result(session: GdbSession, result: CommandResult) -> dict[str, Any]:
    return command_response(session, result)


def _mi_eval_expression_command(expression: str) -> str:
    return f"-data-evaluate-expression {c_escape(expression)}"


def _mi_read_memory_bytes_command(address: str, count: int) -> str:
    return f"-data-read-memory-bytes {c_escape(address)} {count}"


def _mi_write_memory_bytes_command(address: str, data_hex: str) -> str:
    return f"-data-write-memory-bytes {c_escape(address)} {data_hex}"


def _gdb_set_string_command(name: str, value: str) -> str:
    return f"-gdb-set {name} {c_escape(value)}"


def _cli_print_command(expression: str) -> str:
    return f"print {expression}"


def _cli_set_var_command(expression: str, value: str) -> str:
    return f"set var {expression} = {value}"


def _cli_disassemble_command(options: str, target: str) -> str:
    return f"disassemble {options} {target}".replace("  ", " ")


def _cli_find_command(start_address: str, length: int, pattern: str) -> str:
    return f"find {start_address}, +{length}, {pattern}"


def _cli_info_symbol_command(address: int) -> str:
    return f"info symbol {hex(address)}"


def _cli_x_instructions_command(lines: int, start_expression: str) -> str:
    return f"x/{lines}i {start_expression}"


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
        "ok": all(item.get("ok") for item in (location, backtrace, locals_result))
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
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", number) is None:
        raise ValueError("Breakpoint number must be digits with optional dotted subparts")


def _require_positive_decimal_id(name: str, value: str) -> None:
    if not value.isdigit() or int(value) <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _register_number_suffix(register_numbers: list[int] | None) -> str:
    if not register_numbers:
        return ""
    if len(register_numbers) > 512:
        raise ValueError("register_numbers must contain at most 512 items")
    for item in register_numbers:
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            raise ValueError("Register numbers must be non-negative integers")
    return " " + " ".join(str(item) for item in register_numbers)


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
