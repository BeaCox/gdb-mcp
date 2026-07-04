"""Compatibility wrapper for session lifecycle MCP tools."""

from __future__ import annotations

from .session import (
    configure,
    gdb_close_session,
    gdb_connect_gdbserver,
    gdb_create_session,
    gdb_launch_gdbserver,
    gdb_list_sessions,
    gdb_status,
    register_tools,
)

__all__ = [
    "configure",
    "gdb_close_session",
    "gdb_connect_gdbserver",
    "gdb_create_session",
    "gdb_launch_gdbserver",
    "gdb_list_sessions",
    "gdb_status",
    "register_tools",
]
