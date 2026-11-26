"""Tool discovery profiles shared by the backend and lazy proxy."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from mcp.types import Tool

CORE_TOOL_PROFILE = [
    "gdb_create_session",
    "gdb_attach",
    "gdb_load_core",
    "gdb_list_sessions",
    "gdb_status",
    "gdb_close_session",
    "gdb_set_breakpoint",
    "gdb_delete_breakpoint",
    "gdb_list_breakpoints",
    "gdb_run_and_context",
    "gdb_continue_and_context",
    "gdb_step_and_context",
    "gdb_next_and_context",
    "gdb_interrupt",
    "gdb_context",
    "gdb_current_location",
    "gdb_backtrace",
    "gdb_threads",
    "gdb_select_thread",
    "gdb_locals",
    "gdb_eval_expression",
    "gdb_read_register",
    "gdb_registers",
    "gdb_source",
    "gdb_disassemble_around_pc",
    "gdb_read_memory",
    "gdb_capabilities",
    "gdb_server_health",
    "gdb_command_reference",
]

ADVANCED_TOOL_GROUPS: dict[str, dict[str, Any]] = {
    "binary_analysis": {
        "description": "Address, register, mapping, and ELF workflows for stripped binaries.",
        "resource_uri": "gdb://workflows/binary-analysis",
        "tools": [
            "gdb_pwn_context",
            "gdb_binary_summary",
            "gdb_register_context",
            "gdb_vmmap_structured",
            "gdb_address_info",
            "gdb_rva_info",
            "gdb_telescope",
            "gdb_nearpc",
            "gdb_symbols",
            "gdb_got",
            "gdb_piebase",
            "gdb_break_rva",
            "gdb_checksec",
            "gdb_elf_info",
        ],
    },
    "reverse_debugging": {
        "description": "rr replay, GDB process-record, and reverse execution controls.",
        "resource_uri": "gdb://tools/decision-guide",
        "tools": [
            "gdb_rr_record",
            "gdb_start_rr_replay_session",
            "gdb_start_recording",
            "gdb_record_status",
            "gdb_reverse_continue",
            "gdb_reverse_continue_and_context",
            "gdb_reverse_step",
            "gdb_reverse_step_and_context",
            "gdb_reverse_next",
            "gdb_reverse_next_and_context",
            "gdb_reverse_finish",
            "gdb_reverse_finish_and_context",
            "gdb_stop_recording",
        ],
    },
    "remote_target": {
        "description": "Existing or managed gdbserver targets and remote library paths.",
        "resource_uri": "gdb://tools/decision-guide",
        "tools": [
            "gdb_connect_gdbserver",
            "gdb_launch_gdbserver",
            "gdb_set_remote_paths",
            "gdb_gdbserver_status",
            "gdb_detach_gdbserver",
        ],
    },
    "diagnostics": {
        "description": "Server and session troubleshooting beyond the compact health check.",
        "resource_uri": "gdb://tools/decision-guide",
        "tools": [
            "gdb_session_diagnostics",
            "gdb_export_session_bundle",
            "gdb_recent_commands",
            "gdb_recent_events",
            "gdb_close_idle_sessions",
        ],
    },
    "unsafe": {
        "description": "Explicitly unsafe target mutation or raw GDB command execution.",
        "resource_uri": "gdb://tools/decision-guide",
        "requires": "--unsafe or GDB_MCP_ALLOW_UNSAFE=1",
        "tools": [
            "gdb_execute",
            "gdb_call_function",
            "gdb_set_variable",
            "gdb_write_memory",
            "gdb_breakpoint_commands",
        ],
    },
}


@dataclass(frozen=True)
class ToolProfile:
    """A validated discovery profile."""

    name: str
    advanced_groups: tuple[str, ...] = ()

    @property
    def canonical_name(self) -> str:
        if self.name != "advanced":
            return self.name
        return f"advanced:{','.join(self.advanced_groups)}"

    def allowed_names(self, all_names: set[str]) -> set[str]:
        if self.name == "full":
            return set(all_names)
        allowed = set(CORE_TOOL_PROFILE)
        for group in self.advanced_groups:
            allowed.update(ADVANCED_TOOL_GROUPS[group]["tools"])
        return allowed & all_names


def parse_tool_profile(value: str | None) -> ToolProfile:
    """Parse ``full``, ``core``, or ``advanced:group[,group]``."""

    raw = (value or "full").strip().lower().replace("-", "_")
    if raw == "full":
        return ToolProfile("full")
    if raw == "core":
        return ToolProfile("core")

    group_text = raw.removeprefix("advanced:")
    groups = tuple(dict.fromkeys(item.strip() for item in group_text.split(",") if item.strip()))
    unknown = sorted(set(groups) - ADVANCED_TOOL_GROUPS.keys())
    if not groups or unknown:
        choices = ", ".join(sorted(ADVANCED_TOOL_GROUPS))
        detail = f"; unknown groups: {', '.join(unknown)}" if unknown else ""
        raise ValueError(
            "tool profile must be full, core, or advanced:<group>[,<group>] "
            f"where group is one of: {choices}{detail}"
        )
    return ToolProfile("advanced", groups)


def parse_tool_names(values: str | Sequence[str] | None) -> tuple[str, ...]:
    """Parse comma-separated or repeated tool names in stable order."""

    if values is None:
        return ()
    raw_items = [values] if isinstance(values, str) else list(values)
    names: list[str] = []
    seen: set[str] = set()
    for raw in raw_items:
        for part in raw.split(","):
            name = part.strip()
            if not name or name in seen:
                continue
            seen.add(name)
            names.append(name)
    return tuple(names)


@dataclass(frozen=True)
class ToolSelection:
    """Validated tool selection combining a profile, --tools, and --exclude-tools."""

    profile: ToolProfile
    profile_explicit: bool = False
    include_tools: tuple[str, ...] = ()
    exclude_tools: tuple[str, ...] = ()

    @property
    def canonical_name(self) -> str:
        if not self.include_tools and not self.exclude_tools:
            return self.profile.canonical_name
        parts: list[str] = []
        if self.profile_explicit or not self.include_tools:
            parts.append(self.profile.canonical_name)
        if self.include_tools:
            parts.append(f"+{','.join(self.include_tools)}")
        if self.exclude_tools:
            parts.append(f"-{','.join(self.exclude_tools)}")
        return ";".join(parts)

    def allowed_names(self, all_names: set[str]) -> set[str]:
        unknown = sorted((set(self.include_tools) | set(self.exclude_tools)) - all_names)
        if unknown:
            raise ValueError(f"Unknown tool name(s): {', '.join(unknown)}")

        if self.include_tools and not self.profile_explicit:
            allowed = set(self.include_tools)
        else:
            allowed = self.profile.allowed_names(all_names) | set(self.include_tools)
        allowed -= set(self.exclude_tools)
        return allowed & all_names

    def filter_tools(self, tools: list[Tool]) -> list[Tool]:
        allowed = self.allowed_names({tool.name for tool in tools})
        return [tool for tool in tools if tool.name in allowed]


def parse_tool_selection(
    profile_value: str | None = None,
    *,
    include_tools: str | Sequence[str] | None = None,
    exclude_tools: str | Sequence[str] | None = None,
    profile_explicit: bool | None = None,
) -> ToolSelection:
    """Parse profile plus optional include/exclude tool filters."""

    explicit = (
        profile_explicit
        if profile_explicit is not None
        else bool(profile_value and profile_value.strip())
    )
    return ToolSelection(
        profile=parse_tool_profile(profile_value),
        profile_explicit=explicit,
        include_tools=parse_tool_names(include_tools),
        exclude_tools=parse_tool_names(exclude_tools),
    )


def filter_tools(
    tools: list[Tool],
    profile: ToolProfile | ToolSelection,
) -> list[Tool]:
    """Filter a discovered tool list while retaining registration order."""

    allowed = profile.allowed_names({tool.name for tool in tools})
    return [tool for tool in tools if tool.name in allowed]


def profile_snapshot(
    tools: list[Tool],
    profile: ToolProfile | ToolSelection,
) -> list[str]:
    """Return a stable sorted tool-name snapshot for tests and diagnostics."""

    return sorted(tool.name for tool in filter_tools(tools, profile))
