import os
import unittest
from unittest.mock import patch

from gdb_mcp.config import ServerConfig


class ConfigTests(unittest.TestCase):
    def test_from_env_parses_valid_overrides(self) -> None:
        env = {
            "GDB_MCP_ALLOW_UNSAFE": "true",
            "GDB_MCP_MAX_SESSIONS": "0",
            "GDB_MCP_OUTPUT_LIMIT_CHARS": "25000",
            "GDB_MCP_TOOL_PROFILE": "core",
            "GDB_MCP_TOOLS": "gdb_symbols,gdb_got",
            "GDB_MCP_EXCLUDE_TOOLS": "gdb_source",
            "GDB_MCP_IDLE_SESSION_TTL_SECONDS": "120.5",
            "GDB_MCP_MAX_RECENT_RECORDS": "250",
            "GDB_MCP_MAX_RECENT_COMMANDS": "100",
            "GDB_MCP_LOG_LEVEL": "INFO",
            "GDB_MCP_PROGRESS": "1",
        }
        with patch.dict(os.environ, env, clear=True):
            cfg = ServerConfig.from_env()

        self.assertTrue(cfg.allow_unsafe_execute)
        self.assertEqual(cfg.max_sessions, 0)
        self.assertEqual(cfg.output_limit_chars, 25_000)
        self.assertEqual(cfg.tool_profile, "core")
        self.assertTrue(cfg.tool_profile_explicit)
        self.assertEqual(cfg.include_tools, ("gdb_symbols", "gdb_got"))
        self.assertEqual(cfg.exclude_tools, ("gdb_source",))
        self.assertEqual(cfg.idle_session_ttl_seconds, 120.5)
        self.assertEqual(cfg.max_recent_records, 250)
        self.assertEqual(cfg.max_recent_commands, 100)
        self.assertEqual(cfg.log_level, "info")
        self.assertTrue(cfg.progress_notifications)

    def test_from_env_rejects_invalid_values(self) -> None:
        invalid_cases = [
            {"GDB_MCP_ALLOW_UNSAFE": "maybe"},
            {"GDB_MCP_PROGRESS": "2"},
            {"GDB_MCP_MAX_SESSIONS": "abc"},
            {"GDB_MCP_MAX_SESSIONS": "-1"},
            {"GDB_MCP_OUTPUT_LIMIT_CHARS": "999"},
            {"GDB_MCP_IDLE_SESSION_TTL_SECONDS": "-5"},
            {"GDB_MCP_IDLE_SESSION_TTL_SECONDS": "nan"},
            {"GDB_MCP_MAX_RECENT_RECORDS": "5"},
            {"GDB_MCP_MAX_RECENT_COMMANDS": "5000"},
            {"GDB_MCP_LOG_LEVEL": "verbose"},
            {"GDB_MCP_TOOL_PROFILE": "nonexistent"},
        ]
        for env in invalid_cases:
            with self.subTest(env=env), patch.dict(os.environ, env, clear=True):
                with self.assertRaises(ValueError):
                    ServerConfig.from_env()


if __name__ == "__main__":
    unittest.main()
