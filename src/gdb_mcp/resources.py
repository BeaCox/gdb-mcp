"""Static MCP resources for debugger workflows and reference material."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from mcp.server.fastmcp import FastMCP

RESOURCE_MIME_TYPE = "application/json"

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

MI_COMMANDS = [
    {
        "mi": "-break-insert LOCATION",
        "tool": "gdb_set_breakpoint",
        "notes": "Use GDB location syntax such as main, file.c:42, or *0x401000.",
    },
    {
        "mi": "-break-delete NUM",
        "tool": "gdb_delete_breakpoint",
        "notes": "Use gdb_list_breakpoints first when the breakpoint number is unknown.",
    },
    {
        "mi": "-exec-run",
        "tool": "gdb_run",
        "preferred_tool": "gdb_run_and_context",
        "notes": "Prefer the context variant for agent workflows.",
    },
    {
        "mi": "-exec-continue",
        "tool": "gdb_continue",
        "preferred_tool": "gdb_continue_and_context",
        "notes": "Prefer the context variant to get stop reason, frame, backtrace, and locals.",
    },
    {
        "mi": "-exec-step",
        "tool": "gdb_step",
        "preferred_tool": "gdb_step_and_context",
        "notes": "Pass instruction=true for instruction stepping.",
    },
    {
        "mi": "-exec-next",
        "tool": "gdb_next",
        "preferred_tool": "gdb_next_and_context",
        "notes": "Pass instruction=true for instruction-level next.",
    },
    {
        "mi": "-stack-list-frames 0 N",
        "tool": "gdb_backtrace",
        "notes": "Use max_frames to bound the returned stack.",
    },
    {
        "mi": "-stack-list-variables --simple-values",
        "tool": "gdb_locals",
        "notes": "For arguments across multiple frames, use gdb_stack_arguments.",
    },
    {
        "mi": "-data-evaluate-expression EXPR",
        "tool": "gdb_eval_expression",
        "notes": "The safe tool rejects function calls and mutations.",
    },
    {
        "mi": "-data-list-register-values FMT",
        "tool": "gdb_registers",
        "notes": "Use gdb_read_register for one named register such as pc, sp, or rax.",
    },
    {
        "mi": "-data-read-memory-bytes ADDRESS COUNT",
        "tool": "gdb_read_memory",
        "notes": "Use bounded counts; for strings prefer gdb_read_c_string.",
    },
]

RESOURCE_INDEX = [
    {
        "uri": "gdb://workflows/basic",
        "name": "basic_workflows",
        "title": "Basic GDB Workflows",
        "description": "Common local, attach, source, and reverse-debugging tool sequences.",
    },
    {
        "uri": "gdb://workflows/core-dump",
        "name": "core_dump_workflow",
        "title": "Core Dump Workflow",
        "description": "Core loading, path setup, and post-mortem inspection sequence.",
    },
    {
        "uri": "gdb://workflows/binary-analysis",
        "name": "binary_analysis_workflow",
        "title": "Binary Analysis Workflow",
        "description": "Stripped-binary and exploit-development oriented inspection flows.",
    },
    {
        "uri": "gdb://commands/mi",
        "name": "mi_command_map",
        "title": "GDB/MI Command Map",
        "description": "Common GDB/MI commands and the preferred dedicated MCP tools.",
    },
    {
        "uri": "gdb://tools/decision-guide",
        "name": "tool_decision_guide",
        "title": "Tool Decision Guide",
        "description": "Core profile, advanced groups, output strategy, and safety guidance.",
    },
]

REFERENCE_RESOURCES: dict[str, dict[str, Any]] = {
    "gdb://workflows/basic": {
        "kind": "workflow-reference",
        "summary": "Use these flows for ordinary source-level debugging and target control.",
        "core_tool_profile": "core_default",
        "workflows": [
            {
                "name": "local_program",
                "use_when": "You have a local executable and want to run it under GDB.",
                "steps": [
                    {
                        "tool": "gdb_create_session",
                        "purpose": "Start an isolated GDB session for the executable.",
                    },
                    {
                        "tool": "gdb_set_breakpoint",
                        "purpose": "Set a breakpoint at a function, file:line, or address.",
                    },
                    {
                        "tool": "gdb_run_and_context",
                        "purpose": (
                            "Run and return stop reason, selected frame, backtrace, "
                            "and locals."
                        ),
                    },
                    {
                        "tool": "gdb_context",
                        "purpose": "Refresh compact state after manual inspection.",
                    },
                    {
                        "tool": "gdb_continue_and_context",
                        "purpose": "Resume and collect the next stop context.",
                    },
                    {
                        "tool": "gdb_close_session",
                        "purpose": "Close GDB when finished.",
                    },
                ],
            },
            {
                "name": "running_process",
                "use_when": "A Linux process is already running and should be inspected.",
                "steps": [
                    {
                        "tool": "gdb_attach",
                        "purpose": "Attach to the process, optionally creating a session first.",
                    },
                    {
                        "tool": "gdb_context",
                        "purpose": "Inspect the current stop location and local state.",
                    },
                    {
                        "tool": "gdb_threads",
                        "purpose": "List threads before selecting a thread or reading backtraces.",
                    },
                    {
                        "tool": "gdb_detach",
                        "purpose": "Detach without killing the target.",
                    },
                ],
            },
            {
                "name": "source_debugging",
                "use_when": "Debug symbols or source paths are available.",
                "steps": [
                    {
                        "tool": "gdb_backtrace",
                        "purpose": "Identify relevant frames.",
                    },
                    {
                        "tool": "gdb_select_frame",
                        "purpose": "Switch to a frame before inspecting locals or source.",
                    },
                    {
                        "tool": "gdb_locals",
                        "purpose": "Inspect local variables for the selected frame.",
                    },
                    {
                        "tool": "gdb_source",
                        "purpose": "Show source around the selected location or file:line.",
                    },
                    {
                        "tool": "gdb_eval_expression",
                        "purpose": "Evaluate safe expressions without calling target functions.",
                    },
                ],
            },
            {
                "name": "reverse_debugging",
                "use_when": (
                    "rr or GDB process recording is available and the bug requires "
                    "time travel."
                ),
                "steps": [
                    {
                        "tool": "gdb_rr_record",
                        "purpose": (
                            "Optionally record a reproducible run with rr and return "
                            "the trace directory."
                        ),
                    },
                    {
                        "tool": "gdb_start_rr_replay_session",
                        "purpose": (
                            "Optionally start a GDB/MI replay session from the rr trace."
                        ),
                    },
                    {
                        "tool": "gdb_start_recording",
                        "purpose": (
                            "Enable process recording before the interesting execution "
                            "window."
                        ),
                    },
                    {
                        "tool": "gdb_continue_and_context",
                        "purpose": "Run forward until the failure or suspicious state.",
                    },
                    {
                        "tool": "gdb_reverse_continue_and_context",
                        "purpose": "Run backward to the previous stop and inspect context.",
                    },
                    {
                        "tool": "gdb_reverse_step_and_context",
                        "purpose": "Step backward line by line or instruction by instruction.",
                    },
                    {
                        "tool": "gdb_stop_recording",
                        "purpose": "Stop recording when reverse execution is no longer needed.",
                    },
                ],
            },
        ],
    },
    "gdb://workflows/core-dump": {
        "kind": "workflow-reference",
        "summary": "Post-mortem core dump triage without running target code.",
        "workflow": {
            "name": "core_dump_triage",
            "steps": [
                {
                    "tool": "gdb_load_core",
                    "purpose": "Load a core file with an optional executable path.",
                    "notes": "Use a fresh session_id when you want a predictable session name.",
                },
                {
                    "tool": "gdb_set_remote_paths",
                    "purpose": "Set sysroot or solib-search-path when libraries are not found.",
                    "notes": "This is useful for container, chroot, and copied-production cores.",
                },
                {
                    "tool": "gdb_threads",
                    "purpose": "List threads captured in the core.",
                },
                {
                    "tool": "gdb_thread_apply_all_backtrace",
                    "purpose": "Collect bounded backtraces from all threads.",
                },
                {
                    "tool": "gdb_context",
                    "purpose": "Inspect selected frame, locals, and compact crash context.",
                },
                {
                    "tool": "gdb_shared_libraries",
                    "purpose": "Check loaded libraries and path resolution.",
                },
            ],
            "expected_result_shape": {
                "ok": True,
                "session": "session description",
                "current_location": "selected frame or stop metadata when available",
                "backtrace": "bounded frame list",
                "locals": "selected-frame locals",
            },
        },
        "security": {
            "target_code_execution": False,
            "notes": (
                "Loading a core is read-oriented, but inspect untrusted files in an "
                "isolated workspace."
            ),
        },
    },
    "gdb://workflows/binary-analysis": {
        "kind": "workflow-reference",
        "summary": "Use these tools when symbols or source are sparse and addresses matter.",
        "workflows": [
            {
                "name": "stripped_binary_orientation",
                "steps": [
                    {
                        "tool": "gdb_binary_summary",
                        "purpose": (
                            "Read ELF metadata, checksec, runtime base, entry context, "
                            "and mappings."
                        ),
                    },
                    {
                        "tool": "gdb_pwn_context",
                        "purpose": (
                            "Collect location, backtrace, registers, near-PC rows, "
                            "stack telescope, and vmmap."
                        ),
                    },
                    {
                        "tool": "gdb_nearpc",
                        "purpose": (
                            "Inspect instructions near the current or supplied program "
                            "counter."
                        ),
                    },
                    {
                        "tool": "gdb_telescope",
                        "purpose": "Read pointer-sized slots and annotate pointer chains.",
                    },
                    {
                        "tool": "gdb_address_info",
                        "purpose": (
                            "Resolve an address to mappings, module offsets, and "
                            "nearest symbols."
                        ),
                    },
                ],
            },
            {
                "name": "pie_and_rva_work",
                "steps": [
                    {
                        "tool": "gdb_piebase",
                        "purpose": "Calculate runtime VA from a PIE or module-relative offset.",
                    },
                    {
                        "tool": "gdb_rva_info",
                        "purpose": (
                            "Annotate a module RVA with mapping, symbol, and optional "
                            "string context."
                        ),
                    },
                    {
                        "tool": "gdb_break_rva",
                        "purpose": "Set a breakpoint at module base plus RVA.",
                    },
                ],
            },
            {
                "name": "symbol_and_relocation_search",
                "steps": [
                    {
                        "tool": "gdb_symbols",
                        "purpose": "Search functions or variables known to GDB.",
                    },
                    {
                        "tool": "gdb_got",
                        "purpose": "List dynamic relocation or GOT entries and runtime addresses.",
                    },
                    {
                        "tool": "gdb_elf_info",
                        "purpose": "Read ELF headers, sections, Build-ID, and hardening metadata.",
                    },
                ],
            },
        ],
        "output_notes": [
            "Start with summary/context tools before requesting raw readelf output.",
            "Use query and limit arguments on symbol-heavy tools.",
            "Prefer address_info or rva_info over raw memory dumps when resolving one address.",
        ],
    },
    "gdb://commands/mi": {
        "kind": "command-reference",
        "summary": "Common GDB/MI commands and their dedicated MCP tool equivalents.",
        "commands": MI_COMMANDS,
        "raw_command_policy": {
            "tool": "gdb_execute",
            "requires": "--unsafe or GDB_MCP_ALLOW_UNSAFE=1",
            "preferred": "Use dedicated tools whenever possible.",
        },
    },
    "gdb://tools/decision-guide": {
        "kind": "tool-reference",
        "summary": "Choose the smallest tool group that fits the debugging request.",
        "core_default": {
            "description": "Recommended default profile for common local debugging.",
            "tool_count": len(CORE_TOOL_PROFILE),
            "tools": CORE_TOOL_PROFILE,
        },
        "advanced_groups": ADVANCED_TOOL_GROUPS,
        "selection_rules": [
            {
                "when": "Starting normal source debugging",
                "use": ["gdb_create_session", "gdb_set_breakpoint", "gdb_run_and_context"],
            },
            {
                "when": "Need one compact snapshot",
                "use": ["gdb_context", "gdb_current_location", "gdb_backtrace", "gdb_locals"],
            },
            {
                "when": "The binary is stripped or optimized",
                "use": ["gdb_pwn_context", "gdb_binary_summary", "gdb_address_info"],
            },
            {
                "when": "The target is remote",
                "use": ["gdb_connect_gdbserver", "gdb_set_remote_paths", "gdb_gdbserver_status"],
            },
            {
                "when": "Need deterministic replay or stronger reverse execution",
                "use": ["gdb_rr_record", "gdb_start_rr_replay_session", "gdb_context"],
            },
            {
                "when": "A tool could execute target code or mutate memory",
                "use": ["gdb_call_function", "gdb_set_variable", "gdb_write_memory"],
                "requires": "--unsafe or GDB_MCP_ALLOW_UNSAFE=1",
            },
        ],
        "output_strategy": {
            "prefer": "summary and structured fields from dedicated tools",
            "profiles": {
                "summary": "Short bounded summary and counts.",
                "structured": "Default parsed data without duplicate raw command text.",
                "raw": "Include raw MI/readelf payloads where available.",
            },
            "raw_escape_hatch": (
                "Set output='raw' or legacy include_raw=true only when compact fields "
                "are insufficient."
            ),
            "large_output_candidates": [
                "gdb_symbols",
                "gdb_got",
                "gdb_elf_info",
                "gdb_read_memory",
                "gdb_thread_apply_all_backtrace",
                "gdb_recent_commands",
            ],
            "pagination": {
                "cursor_format": "non-negative decimal offset",
                "fields": ["cursor", "page_size", "pagination.next_cursor"],
                "tools": [
                    "gdb_symbols",
                    "gdb_got",
                    "gdb_read_memory",
                    "gdb_thread_apply_all_backtrace",
                    "gdb_memory_mappings",
                    "gdb_vmmap_structured",
                    "gdb_recent_commands",
                    "gdb_recent_events",
                ],
            },
        },
    },
}


def resource_index() -> list[dict[str, Any]]:
    """Return the public resource index without exposing mutable module state."""

    return deepcopy(RESOURCE_INDEX)


def command_reference_index() -> dict[str, Any]:
    """Return the compact tool response that points clients at resource URIs."""

    return {
        "recommended_flow": [
            "gdb_create_session",
            "gdb_set_breakpoint",
            "gdb_run_and_context",
            "gdb_context",
            "gdb_continue_and_context",
            "gdb_close_session",
        ],
        "resource_index": resource_index(),
        "core_tool_profile": {
            "name": "core_default",
            "tool_count": len(CORE_TOOL_PROFILE),
            "resource_uri": "gdb://tools/decision-guide",
        },
        "mi_command_reference": "gdb://commands/mi",
        "unsafe_note": (
            "Use gdb_execute only with --unsafe or GDB_MCP_ALLOW_UNSAFE=1. "
            "Prefer dedicated tools when available."
        ),
    }


def tool_profile() -> dict[str, Any]:
    """Return core and advanced tool groups for gdb_capabilities."""

    return {
        "core_default": {
            "description": "Recommended default set for common debugging.",
            "tool_count": len(CORE_TOOL_PROFILE),
            "tools": deepcopy(CORE_TOOL_PROFILE),
            "resource_uri": "gdb://tools/decision-guide",
        },
        "advanced_groups": deepcopy(ADVANCED_TOOL_GROUPS),
    }


def read_reference_resource(uri: str) -> dict[str, Any]:
    """Return one static reference resource by URI."""

    return deepcopy(REFERENCE_RESOURCES[uri])


def _make_resource_reader(uri: str):
    def read_resource() -> dict[str, Any]:
        return read_reference_resource(uri)

    return read_resource


def register_resources(mcp: FastMCP[Any]) -> None:
    """Register static workflow and reference resources on an MCP server."""

    for resource in RESOURCE_INDEX:
        mcp.resource(
            resource["uri"],
            name=resource["name"],
            title=resource["title"],
            description=resource["description"],
            mime_type=RESOURCE_MIME_TYPE,
        )(_make_resource_reader(resource["uri"]))
