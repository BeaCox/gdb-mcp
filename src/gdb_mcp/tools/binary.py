"""Binary-analysis and pwn-oriented MCP tools."""

from __future__ import annotations

import asyncio
import os
import shutil
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..analysis import (
    BUILD_ID_RE as _BUILD_ID_RE,
)
from ..analysis import (
    address_in_mapping as _address_in_mapping,
)
from ..analysis import (
    address_mapping_info as _address_mapping_info,
)
from ..analysis import (
    group_registers as _group_registers,
)
from ..analysis import (
    hex_or_none as _hex_or_none,
)
from ..analysis import (
    parse_checksec as _parse_checksec,
)
from ..analysis import (
    parse_disassembly as _parse_disassembly,
)
from ..analysis import (
    parse_elf_header as _parse_elf_header,
)
from ..analysis import (
    parse_gdb_symbols as _parse_gdb_symbols,
)
from ..analysis import (
    parse_int as _parse_int,
)
from ..analysis import (
    parse_mappings as _parse_mappings,
)
from ..analysis import (
    parse_readelf_relocations as _parse_readelf_relocations,
)
from ..analysis import (
    parse_sections as _parse_sections,
)
from ..analysis import (
    read_memory_contents as _read_memory_contents,
)
from ..analysis import (
    register_rows as _register_rows,
)
from ..session import GdbSession, _truncate_text
from .breakpoints import gdb_set_breakpoint
from .inspection import (
    gdb_backtrace,
    gdb_current_location,
    gdb_read_c_string,
    gdb_read_register,
    gdb_register_names,
    gdb_registers,
)
from .shared import (
    _cli_info_symbol_command,
    _cli_x_instructions_command,
    _error,
    _mi_eval_expression_command,
    _mi_read_memory_bytes_command,
    _require_cli_target,
    _require_max_frames,
    _require_read_expression,
    _require_single_line,
    _result,
    manager,
    runtime_config,
)


def register_tools(
    mcp: FastMCP[Any],
    *,
    read_only: ToolAnnotations,
    session_mutation: ToolAnnotations,
) -> None:
    """Register binary-analysis and pwn-oriented tools."""

    mcp.tool(annotations=read_only)(gdb_vmmap_structured)
    mcp.tool(annotations=read_only)(gdb_address_info)
    mcp.tool(annotations=read_only)(gdb_telescope)
    mcp.tool(annotations=read_only)(gdb_nearpc)
    mcp.tool(annotations=read_only)(gdb_piebase)
    mcp.tool(annotations=session_mutation)(gdb_break_rva)
    mcp.tool(annotations=read_only)(gdb_pwn_context)
    mcp.tool(annotations=read_only)(gdb_checksec)
    mcp.tool(annotations=read_only)(gdb_elf_info)
    mcp.tool(annotations=read_only)(gdb_register_context)
    mcp.tool(annotations=read_only)(gdb_symbols)
    mcp.tool(annotations=read_only)(gdb_got)
    mcp.tool(annotations=read_only)(gdb_rva_info)
    mcp.tool(annotations=read_only)(gdb_binary_summary)


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
            _mi_eval_expression_command(expression),
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
                await session.execute(_cli_info_symbol_command(address), timeout=5.0),
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
                _mi_read_memory_bytes_command(hex(start), count * pointer_size),
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
                        _mi_read_memory_bytes_command(hex(current), pointer_size),
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
        command = _cli_x_instructions_command(lines, start_expression)
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
        "--",
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
    output_limit = max(1_000, runtime_config.output_limit_chars // 8)
    decoded_stdout, stdout_truncated = _truncate_text(
        stdout.decode(errors="replace"),
        output_limit,
    )
    decoded_stderr, stderr_truncated = _truncate_text(
        stderr.decode(errors="replace"),
        output_limit,
    )
    return {
        "ok": process.returncode == 0,
        "returncode": process.returncode,
        "stdout": decoded_stdout,
        "stderr": decoded_stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "truncated": stdout_truncated or stderr_truncated,
        "output_limit_chars": output_limit,
    }


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


async def gdb_register_context(session_id: str) -> dict[str, Any]:
    """Return pwndbg-style grouped registers for quick pwn context inspection."""

    try:
        names, values = await asyncio.gather(
            gdb_register_names(session_id),
            gdb_registers(session_id),
        )
        rows = _register_rows(names, values)
        return {
            "ok": bool(names.get("ok") and values.get("ok")),
            "session_id": session_id,
            "registers": rows,
            "groups": _group_registers(rows),
            "commands": {"names": names, "values": values},
        }
    except Exception as exc:
        return _error(exc)


async def gdb_symbols(
    session_id: str,
    query: str = "",
    kind: str = "functions",
    limit: int = 100,
) -> dict[str, Any]:
    """Search GDB-known functions or variables and return parsed symbol rows."""

    try:
        _require_single_line("query", query)
        if kind not in {"functions", "variables"}:
            raise ValueError("kind must be one of: functions, variables")
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        command = f"info {kind}"
        if query:
            command += f" {query}"
        session = await manager.get(session_id)
        payload = _result(session, await session.execute(command, timeout=10.0))
        symbols = _parse_gdb_symbols(str(payload.get("console") or ""), limit)
        return {
            **payload,
            "query": query,
            "kind": kind,
            "symbols": symbols,
            "symbol_count": len(symbols),
        }
    except Exception as exc:
        return _error(exc)


async def gdb_got(
    session_id: str | None = None,
    file_path: str | None = None,
    query: str = "",
    module: str | None = None,
    limit: int = 200,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """List dynamic relocation/GOT entries, optionally annotated with runtime VAs."""

    try:
        _require_single_line("query", query)
        if module is not None:
            _require_single_line("module", module)
        if not 1 <= limit <= 2000:
            raise ValueError("limit must be between 1 and 2000")
        path, session = await _resolve_elf_file(session_id=session_id, file_path=file_path)
        if session is None and session_id is not None:
            session = await manager.get(session_id)
        relocations_result, checksec = await asyncio.gather(
            _run_readelf(path, ["-r"], timeout),
            gdb_checksec(session_id=session.session_id if session else None, file_path=path),
        )
        relocations = _parse_readelf_relocations(str(relocations_result.get("stdout") or ""))
        if query:
            lowered = query.lower()
            relocations = [
                item
                for item in relocations
                if lowered in str(item.get("symbol", "")).lower()
                or lowered in str(item.get("type", "")).lower()
            ]

        runtime_base: int | None = None
        piebase: dict[str, Any] | None = None
        security = checksec.get("security", {})
        needs_base = isinstance(security, dict) and bool(security.get("pie"))
        if session is not None and needs_base:
            piebase = await gdb_piebase(session.session_id, module=module)
            runtime_base = _parse_int(piebase.get("base"))

        annotated: list[dict[str, Any]] = []
        for item in relocations[:limit]:
            offset = _parse_int(item.get("offset"))
            runtime_address = (
                runtime_base + offset if runtime_base is not None and offset is not None else offset
            )
            annotated.append({**item, "runtime_address": _hex_or_none(runtime_address)})

        return {
            "ok": bool(relocations_result.get("ok")),
            "session_id": session.session_id if session else session_id,
            "file_path": path,
            "query": query,
            "module": module,
            "entries": annotated,
            "entry_count": len(annotated),
            "all_entry_count": len(relocations),
            "piebase": piebase,
            "checksec": checksec,
            "readelf": relocations_result,
        }
    except Exception as exc:
        return _error(exc)


async def gdb_rva_info(
    session_id: str,
    offset: int,
    module: str | None = None,
    read_string: bool = False,
) -> dict[str, Any]:
    """Resolve a module RVA to a runtime address and annotate it like pwndbg xinfo."""

    try:
        if offset < 0:
            raise ValueError("offset must be non-negative")
        if module is not None:
            _require_single_line("module", module)
        base = await gdb_piebase(session_id, offset=offset, module=module)
        address = base.get("address")
        address_info = None
        if isinstance(address, str):
            address_info = await gdb_address_info(
                session_id,
                address,
                read_string=read_string,
            )
        return {
            "ok": bool(base.get("ok")) and isinstance(address, str),
            "session_id": session_id,
            "module": module,
            "offset": hex(offset),
            "address": address,
            "piebase": base,
            "address_info": address_info,
        }
    except Exception as exc:
        return _error(exc)


async def gdb_binary_summary(
    session_id: str | None = None,
    file_path: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Return a pwn-oriented binary summary: ELF metadata, checksec, base, and maps."""

    try:
        path, session = await _resolve_elf_file(session_id=session_id, file_path=file_path)
        if session is None and session_id is not None:
            session = await manager.get(session_id)
        checksec, elf_info = await asyncio.gather(
            gdb_checksec(
                session_id=session.session_id if session else None,
                file_path=path,
                timeout=timeout,
            ),
            gdb_elf_info(
                session_id=session.session_id if session else None,
                file_path=path,
                timeout=timeout,
            ),
        )
        vmmap: dict[str, Any] | None = None
        piebase: dict[str, Any] | None = None
        entry_info: dict[str, Any] | None = None
        mapping_summary: dict[str, int] = {}
        if session is not None:
            vmmap = await gdb_vmmap_structured(session.session_id)
            piebase = await gdb_piebase(session.session_id)
            for mapping in vmmap.get("mappings", []) if isinstance(vmmap, dict) else []:
                if not isinstance(mapping, dict):
                    continue
                kind = str(mapping.get("kind") or "unknown")
                mapping_summary[kind] = mapping_summary.get(kind, 0) + 1
            entry = _parse_int(checksec.get("security", {}).get("entry"))
            base = _parse_int(piebase.get("base")) if isinstance(piebase, dict) else None
            is_pie = bool(checksec.get("security", {}).get("pie"))
            if entry is not None:
                runtime_entry = base + entry if is_pie and base is not None else entry
                entry_info = await gdb_address_info(
                    session.session_id,
                    hex(runtime_entry),
                    read_string=False,
                )
        return {
            "ok": bool(checksec.get("ok") or elf_info.get("ok")),
            "session_id": session.session_id if session else session_id,
            "file_path": path,
            "summary": {
                "arch": checksec.get("security", {}).get("arch"),
                "entry": checksec.get("security", {}).get("entry"),
                "pie": checksec.get("security", {}).get("pie"),
                "nx": checksec.get("security", {}).get("nx"),
                "canary": checksec.get("security", {}).get("canary"),
                "relro": checksec.get("security", {}).get("relro"),
                "base": piebase.get("base") if isinstance(piebase, dict) else None,
                "mapping_summary": mapping_summary,
            },
            "checksec": checksec,
            "elf_info": elf_info,
            "piebase": piebase,
            "entry_info": entry_info,
            "vmmap": vmmap,
        }
    except Exception as exc:
        return _error(exc)
