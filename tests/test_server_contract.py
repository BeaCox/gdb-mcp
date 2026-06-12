import ast
import asyncio
import unittest
from pathlib import Path

from gdb_mcp.server import (
    gdb_execute,
    gdb_set_breakpoint,
    mcp,
    runtime_config,
)


class ServerContractTests(unittest.TestCase):
    def test_tools_have_stable_mcp_metadata(self) -> None:
        asyncio.run(self._test_tools())

    async def _test_tools(self) -> None:
        tools = await mcp.list_tools()
        names = [tool.name for tool in tools]
        self.assertEqual(len(names), len(set(names)))
        self.assertIn("gdb_server_health", names)
        self.assertIn("gdb_recent_events", names)
        for tool in tools:
            with self.subTest(tool=tool.name):
                self.assertTrue(tool.description)
                self.assertEqual(tool.inputSchema.get("type"), "object")
                self.assertEqual(tool.outputSchema.get("type"), "object")
                self.assertIsNotNone(tool.annotations)

    def test_unsafe_execute_is_disabled_by_default(self) -> None:
        asyncio.run(self._test_unsafe_execute())

    async def _test_unsafe_execute(self) -> None:
        previous = runtime_config.allow_unsafe_execute
        runtime_config.allow_unsafe_execute = False
        try:
            result = await gdb_execute("missing", "shell id")
        finally:
            runtime_config.allow_unsafe_execute = previous
        self.assertFalse(result["ok"])
        self.assertIn("disabled by default", result["error"])

    def test_protocol_module_has_no_print_calls(self) -> None:
        path = Path(__file__).resolve().parents[1] / "src" / "gdb_mcp" / "session.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        offenders = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "print"
        ]
        self.assertEqual(offenders, [])

    def test_breakpoint_tool_rejects_multiline_input(self) -> None:
        result = asyncio.run(gdb_set_breakpoint("missing", "main\nshell id"))
        self.assertFalse(result["ok"])
        self.assertIn("line breaks", result["error"])


if __name__ == "__main__":
    unittest.main()
