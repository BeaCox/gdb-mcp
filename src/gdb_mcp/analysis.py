"""Pure parsing and analysis helpers for GDB and ELF tool output."""

from __future__ import annotations

import os
import re
from typing import Any

BUILD_ID_RE = re.compile(r"Build ID:\s*(?P<build_id>[0-9A-Fa-f]+)")

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
_SOURCE_LINE_RE = re.compile(r"^\s*(?:=>\s*)?(?P<line>[0-9]+)\s+(?P<text>.*)$")
_INFO_LINE_RE = re.compile(r'Line (?P<line>[0-9]+) of "(?P<file>[^"]+)"')
_INFO_SOURCE_RE = re.compile(r"Current source file is (?P<file>.+?)(?:\n|$)")
_READELF_RELOCATION_RE = re.compile(r"^\s*(?P<offset>[0-9A-Fa-f]+)\s+")
_GDB_SYMBOL_RE = re.compile(
    r"^\s*(?:(?P<address>0x[0-9a-fA-F]+)\s+)?(?P<declaration>.+?);?\s*$"
)


def parse_int(value: Any) -> int | None:
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


def hex_or_none(value: int | None) -> str | None:
    return hex(value) if value is not None else None


def mapping_name(mapping: dict[str, Any]) -> str:
    objfile = str(mapping.get("objfile") or "")
    if objfile:
        return os.path.basename(objfile) or objfile
    return str(mapping.get("name") or "")


def classify_mapping(mapping: dict[str, Any]) -> str:
    objfile = str(mapping.get("objfile") or "")
    name = mapping_name(mapping)
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


def parse_mappings(console: str) -> list[dict[str, Any]]:
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
        mapping["kind"] = classify_mapping(mapping)
        mappings.append(mapping)
    return mappings


def address_in_mapping(address: int, mapping: dict[str, Any]) -> bool:
    start = parse_int(mapping.get("start"))
    end = parse_int(mapping.get("end"))
    return start is not None and end is not None and start <= address < end


def find_mapping(address: int, mappings: list[dict[str, Any]]) -> dict[str, Any] | None:
    for mapping in mappings:
        if address_in_mapping(address, mapping):
            return mapping
    return None


def address_mapping_info(
    address: int | None,
    mappings: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if address is None:
        return None
    mapping = find_mapping(address, mappings)
    if mapping is None:
        return None
    start = parse_int(mapping.get("start"))
    file_offset = parse_int(mapping.get("offset"))
    offset_in_mapping = address - start if start is not None else None
    module_offset = (
        file_offset + offset_in_mapping
        if file_offset is not None and offset_in_mapping is not None
        else None
    )
    return {
        "mapping": mapping,
        "offset_in_mapping": hex_or_none(offset_in_mapping),
        "file_offset": hex_or_none(module_offset),
        "module": mapping_name(mapping),
        "module_offset": hex_or_none(address - start) if start is not None else None,
        "module_file_offset": hex_or_none(module_offset),
    }


def parse_disassembly(console: str, current_address: int | None = None) -> list[dict[str, Any]]:
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
        target = parse_int(assembly)
        if target is not None:
            instruction["target"] = hex(target)
        instructions.append(instruction)
    return instructions


def read_memory_contents(payload: dict[str, Any]) -> bytes:
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


def source_context(
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


def parse_elf_header(header: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in header.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip().lower().replace(" ", "_")] = value.strip()
    return fields


def parse_checksec(
    header: str,
    program_headers: str,
    dynamic: str,
    symbols: str,
) -> dict[str, Any]:
    header_fields = parse_elf_header(header)
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


def parse_sections(sections_output: str) -> list[dict[str, str]]:
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


def parse_readelf_relocations(relocations_output: str) -> list[dict[str, Any]]:
    relocations: list[dict[str, Any]] = []
    for line in relocations_output.splitlines():
        if _READELF_RELOCATION_RE.match(line) is None:
            continue
        columns = line.split()
        if len(columns) < 3:
            continue
        symbol = ""
        addend = ""
        if len(columns) >= 5:
            symbol = columns[4]
            if len(columns) > 5:
                addend = " ".join(columns[5:])
        relocations.append(
            {
                "offset": hex(int(columns[0], 16)),
                "info": columns[1] if len(columns) > 1 else "",
                "type": columns[2],
                "symbol_value": f"0x{columns[3]}" if len(columns) > 3 else "",
                "symbol": symbol,
                "addend": addend,
                "raw": line.strip(),
            }
        )
    return relocations


def parse_gdb_symbols(console: str, limit: int) -> list[dict[str, str]]:
    symbols: list[dict[str, str]] = []
    current_file = ""
    for line in console.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("All "):
            continue
        if stripped.endswith(":") and not stripped.startswith("0x"):
            current_file = stripped[:-1]
            continue
        match = _GDB_SYMBOL_RE.match(stripped)
        if match is None:
            continue
        declaration = match.group("declaration").rstrip(";")
        if declaration.startswith(("Non-debugging", "File ")):
            continue
        symbols.append(
            {
                "address": match.group("address") or "",
                "declaration": declaration,
                "file": current_file,
                "name": declaration.split("(", 1)[0].split()[-1] if declaration else "",
            }
        )
        if len(symbols) >= limit:
            break
    return symbols


def register_rows(
    names_payload: dict[str, Any],
    values_payload: dict[str, Any],
) -> list[dict[str, str]]:
    names = names_payload.get("results", {}).get("register-names", [])
    values = values_payload.get("results", {}).get("register-values", [])
    if not isinstance(names, list) or not isinstance(values, list):
        return []
    by_number: dict[int, str] = {}
    for item in values:
        if not isinstance(item, dict):
            continue
        number = parse_int(item.get("number"))
        value = item.get("value")
        if number is not None and isinstance(value, str):
            by_number[number] = value
    rows: list[dict[str, str]] = []
    for number, name in enumerate(names):
        if not isinstance(name, str) or not name:
            continue
        rows.append(
            {
                "number": str(number),
                "name": name,
                "value": by_number.get(number, ""),
            }
        )
    return rows


def group_registers(rows: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    groups = {
        "instruction": {"pc", "rip", "eip"},
        "stack": {"sp", "rsp", "esp", "bp", "rbp", "ebp"},
        "arguments": {"rdi", "rsi", "rdx", "rcx", "r8", "r9", "edi", "esi", "edx", "ecx"},
        "return": {"rax", "eax", "x0", "a0", "v0"},
        "general": set(),
    }
    output: dict[str, list[dict[str, str]]] = {
        "instruction": [],
        "stack": [],
        "arguments": [],
        "return": [],
        "general": [],
    }
    assigned: set[str] = set()
    for group, names in groups.items():
        if group == "general":
            continue
        for row in rows:
            name = row["name"].lower()
            if name in names:
                output[group].append(row)
                assigned.add(row["name"])
    for row in rows:
        if row["name"] not in assigned:
            output["general"].append(row)
    return output
