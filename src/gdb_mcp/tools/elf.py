"""ELF subprocess execution and large-payload profiling helpers."""

# ruff: noqa: ASYNC109

from __future__ import annotations

import asyncio
import shutil
from typing import Any

from ..pagination import paginate_text_lines
from ..session import GdbSession, _truncate_text
from .shared import (
    _require_cli_target,
    _require_output_profile,
    manager,
    runtime_config,
)


def _strip_large_fields(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_large_fields(item)
            for key, item in value.items()
            if key not in {"raw", "console", "target", "log", "stdout", "stderr"}
        }
    if isinstance(value, list):
        return [_strip_large_fields(item) for item in value]
    return value


def _command_status(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: payload.get(key)
        for key in (
            "ok",
            "returncode",
            "result_class",
            "truncated",
            "stdout_truncated",
            "stderr_truncated",
            "output_limit_chars",
        )
        if key in payload
    }


def _profile_large_payload(
    payload: dict[str, Any],
    output: str,
    *,
    summary_fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    profile = _require_output_profile(output)
    if profile == "raw":
        return {**payload, "output_profile": "raw"}
    if profile == "structured":
        structured = _strip_large_fields(payload)
        structured["output_profile"] = "structured"
        return structured

    keys = (
        "ok",
        "session_id",
        "file_path",
        "query",
        "kind",
        "module",
        "entry_count",
        "all_entry_count",
        "symbol_count",
        "mapping_count",
        "all_mapping_count",
        "section_count",
    )
    summary = {key: payload[key] for key in keys if key in payload}
    summary["output_profile"] = "summary"
    if summary_fields:
        summary.update(summary_fields)
    return summary


async def _terminate_readelf(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    process.kill()
    await process.wait()


async def _run_readelf(
    file_path: str,
    args: list[str],
    timeout: float,
    output: str = "raw",
    cursor: str | None = None,
    page_size: int | None = None,
) -> dict[str, Any]:
    _require_output_profile(output)
    readelf = shutil.which("readelf")
    if readelf is None:
        return {"ok": False, "error": "readelf is not available on PATH"}
    process = await asyncio.create_subprocess_exec(
        readelf,
        "-W",
        *args,
        "--",
        file_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.CancelledError:
        await _terminate_readelf(process)
        raise
    except asyncio.TimeoutError:
        await _terminate_readelf(process)
        return {"ok": False, "error": f"readelf timed out after {timeout} seconds"}

    stdout_text = stdout.decode(errors="replace")
    stdout_lines, stdout_pagination = paginate_text_lines(
        stdout_text,
        cursor=cursor,
        page_size=page_size,
        default_page_size=max(1, min(len(stdout_text.splitlines()) or 1, 10_000)),
        max_page_size=10_000,
        cursor_scope=f"readelf:{file_path}:{args}",
    )
    if cursor is not None or page_size is not None:
        stdout_text = "\n".join(stdout_lines)

    output_limit = max(1_000, runtime_config.output_limit_chars // 8)
    decoded_stdout, stdout_truncated = _truncate_text(stdout_text, output_limit)
    decoded_stderr, stderr_truncated = _truncate_text(
        stderr.decode(errors="replace"),
        output_limit,
    )
    payload = {
        "ok": process.returncode == 0,
        "command": ["readelf", "-W", *args, "--", file_path],
        "file_path": file_path,
        "returncode": process.returncode,
        "stdout": decoded_stdout,
        "stderr": decoded_stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "truncated": stdout_truncated or stderr_truncated,
        "output_limit_chars": output_limit,
        "stdout_pagination": stdout_pagination,
    }
    return _profile_large_payload(
        payload,
        output,
        summary_fields={
            "command": payload["command"],
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
            "stdout_pagination": stdout_pagination,
        },
    )


async def _resolve_elf_file(
    *,
    session_id: str | None,
    file_path: str | None,
) -> tuple[str, GdbSession | None]:
    if file_path is not None:
        _require_cli_target("file_path", file_path)
        return file_path, None
    if session_id is None:
        raise ValueError("Provide session_id or file_path")
    session = await manager.get(session_id)
    if not session.program:
        raise ValueError("Session has no loaded program; provide file_path")
    return session.program, session


async def collect_elf_bundle(file_path: str, timeout: float) -> dict[str, dict[str, Any]]:
    """Run all standard readelf metadata queries once in parallel."""

    (
        header,
        sections,
        program_headers,
        dynamic,
        symbols,
        notes,
    ) = await asyncio.gather(
        _run_readelf(file_path, ["-h"], timeout),
        _run_readelf(file_path, ["-S"], timeout),
        _run_readelf(file_path, ["-l"], timeout),
        _run_readelf(file_path, ["-d"], timeout),
        _run_readelf(file_path, ["-s"], timeout),
        _run_readelf(file_path, ["-n"], timeout),
    )
    return {
        "header": header,
        "sections": sections,
        "program_headers": program_headers,
        "dynamic": dynamic,
        "symbols": symbols,
        "notes": notes,
    }
