import asyncio
import json
import sys
import unittest
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from gdb_mcp.lazy import LazyBackend, list_proxy_tools


def _tool_payload(result):
    if result.structuredContent is not None:
        return result.structuredContent
    text = "\n".join(
        item.text for item in result.content if getattr(item, "text", None) is not None
    )
    return json.loads(text)


class LazyProxyTests(unittest.TestCase):
    def test_static_tool_list_matches_full_server_without_backend(self) -> None:
        asyncio.run(self._test_static_tool_list())

    async def _test_static_tool_list(self) -> None:
        tools = await list_proxy_tools()
        names = {tool.name for tool in tools}
        self.assertIn("gdb_create_session", names)
        self.assertIn("gdb_server_health", names)

        backend = LazyBackend(command="/definitely/missing/gdb-mcp-backend")
        self.assertIsNone(backend._session)
        self.assertIsNone(backend._stack)

    def test_stdio_list_tools_does_not_start_backend(self) -> None:
        asyncio.run(self._test_stdio_list_tools_does_not_start_backend())

    async def _test_stdio_list_tools_does_not_start_backend(self) -> None:
        params = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m",
                "gdb_mcp.lazy",
                "--backend-command",
                "/definitely/missing/gdb-mcp-backend",
            ],
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()

        names = {tool.name for tool in tools.tools}
        self.assertIn("gdb_create_session", names)
        self.assertIn("gdb_server_health", names)

    def test_stdio_call_tool_starts_backend_and_forwards(self) -> None:
        asyncio.run(self._test_stdio_call_tool_starts_backend_and_forwards())

    async def _test_stdio_call_tool_starts_backend_and_forwards(self) -> None:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "gdb_mcp.lazy"],
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("gdb_server_health", {})

        payload = _tool_payload(result)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["name"], "gdb-mcp")

    def test_user_facing_gdb_mcp_command_is_lazy_proxy(self) -> None:
        asyncio.run(self._test_user_facing_gdb_mcp_command_is_lazy_proxy())

    async def _test_user_facing_gdb_mcp_command_is_lazy_proxy(self) -> None:
        params = StdioServerParameters(command="uv", args=["run", "gdb-mcp"])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()

        names = {tool.name for tool in tools.tools}
        self.assertIn("gdb_create_session", names)
        self.assertIn("gdb_server_health", names)

    def test_stdio_proxy_preserves_backend_multi_session_state(self) -> None:
        asyncio.run(self._test_stdio_proxy_preserves_backend_multi_session_state())

    async def _test_stdio_proxy_preserves_backend_multi_session_state(self) -> None:
        fake_gdb = Path(__file__).parent / "fixtures" / "fake_gdb.py"
        fake_gdb.chmod(0o755)
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "gdb_mcp.lazy"],
        )
        session_ids: list[str] = []
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                for _ in range(2):
                    result = await session.call_tool(
                        "gdb_create_session",
                        {"gdb_path": str(fake_gdb)},
                    )
                    payload = _tool_payload(result)
                    self.assertTrue(payload["ok"])
                    session_ids.append(payload["session"]["session_id"])

                result = await session.call_tool("gdb_list_sessions", {})
                payload = _tool_payload(result)
                self.assertTrue(payload["ok"])
                self.assertGreaterEqual(len(payload["sessions"]), 2)
                listed = {item["session_id"] for item in payload["sessions"]}
                self.assertTrue(set(session_ids).issubset(listed))

                for session_id in session_ids:
                    await session.call_tool(
                        "gdb_close_session",
                        {"session_id": session_id},
                    )


if __name__ == "__main__":
    unittest.main()
