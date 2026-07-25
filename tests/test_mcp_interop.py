import asyncio
import json
import os
import socket
import sys
import unittest
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import McpError
from mcp.types import CancelledNotification, CancelledNotificationParams

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
FAKE_GDB = ROOT / "tests" / "fixtures" / "fake_gdb.py"


def _source_env(**extra: str) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(SRC), *(item for item in [env.get("PYTHONPATH")] if item)]
    )
    env.update(extra)
    return env


def _payload(result) -> dict:
    if result.structuredContent is not None:
        return result.structuredContent
    text = "\n".join(
        content.text
        for content in result.content
        if getattr(content, "text", None) is not None
    )
    return json.loads(text)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _wait_for_port(port: int, process: asyncio.subprocess.Process) -> None:
    for _ in range(100):
        if process.returncode is not None:
            stdout, _ = await process.communicate()
            raise AssertionError(
                f"HTTP backend exited with {process.returncode}: "
                + stdout.decode(errors="replace")
            )
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.05)
            continue
        writer.close()
        await writer.wait_closed()
        return
    raise AssertionError("HTTP backend did not listen within 5 seconds")


class McpInteroperabilityTests(unittest.TestCase):
    def test_stdio_real_client_workflow_and_cancellation(self) -> None:
        asyncio.run(self._test_stdio_workflow())

    async def _test_stdio_workflow(self) -> None:
        FAKE_GDB.chmod(0o755)
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "gdb_mcp.server"],
            env=_source_env(FAKE_GDB_HOLD_RUN="1"),
            cwd=ROOT,
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                self.assertIsNotNone(initialized.capabilities.tools)
                self.assertIsNotNone(initialized.capabilities.resources)
                self.assertIsNotNone(initialized.capabilities.prompts)

                tools = await session.list_tools()
                resources = await session.list_resources()
                resource = await session.read_resource("gdb://workflows/basic")
                prompts = await session.list_prompts()
                prompt = await session.get_prompt("debug_local", {"program": "/tmp/a"})
                self.assertIn("gdb_create_session", {tool.name for tool in tools.tools})
                self.assertEqual(len(resources.resources), 5)
                self.assertIn("local_program", resource.contents[0].text)
                self.assertIn("debug_local", {item.name for item in prompts.prompts})
                self.assertIn("Safety boundary:", prompt.messages[0].content.text)

                created = _payload(
                    await session.call_tool(
                        "gdb_create_session",
                        {"gdb_path": str(FAKE_GDB)},
                    )
                )
                self.assertTrue(created["ok"], created)
                session_id = created["session"]["session_id"]
                try:
                    first = _payload(
                        await session.call_tool(
                            "gdb_read_memory",
                            {
                                "session_id": session_id,
                                "address": "$sp",
                                "count": 16,
                                "page_size": 8,
                                "output": "summary",
                            },
                        )
                    )
                    second = _payload(
                        await session.call_tool(
                            "gdb_read_memory",
                            {
                                "session_id": session_id,
                                "address": "$sp",
                                "count": 16,
                                "page_size": 8,
                                "cursor": first["pagination"]["next_cursor"],
                                "output": "summary",
                            },
                        )
                    )
                    self.assertEqual(second["pagination"]["page_start"], 8)

                    dispatched = asyncio.Event()
                    progress_events = []

                    async def progress_callback(progress, total, message) -> None:
                        progress_events.append((progress, total, message))
                        if progress >= 50:
                            dispatched.set()

                    request_id = session._request_id
                    running = asyncio.create_task(
                        session.call_tool(
                            "gdb_run",
                            {"session_id": session_id, "timeout": 5.0},
                            progress_callback=progress_callback,
                        )
                    )
                    await asyncio.wait_for(dispatched.wait(), timeout=2.0)
                    await asyncio.sleep(0.1)
                    await session.send_notification(
                        CancelledNotification(
                            params=CancelledNotificationParams(
                                requestId=request_id,
                                reason="interoperability cancellation test",
                            )
                        )
                    )
                    with self.assertRaises(McpError):
                        await running
                    self.assertEqual([event[0] for event in progress_events], [0, 50])

                    await asyncio.sleep(0.1)
                    commands = _payload(
                        await session.call_tool(
                            "gdb_recent_commands",
                            {"session_id": session_id, "limit": 20},
                        )
                    )
                    run_rows = [
                        row for row in commands["commands"] if row["command"] == "-exec-run"
                    ]
                    self.assertTrue(run_rows, commands)
                    self.assertEqual(run_rows[-1]["status"], "cancelled")
                finally:
                    await session.call_tool(
                        "gdb_close_session", {"session_id": session_id}
                    )

    def test_streamable_http_real_client_workflow(self) -> None:
        asyncio.run(self._test_streamable_http_workflow())

    async def _test_streamable_http_workflow(self) -> None:
        port = _free_port()
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "gdb_mcp.server",
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            cwd=ROOT,
            env=_source_env(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            await _wait_for_port(port, process)
            async with streamable_http_client(f"http://127.0.0.1:{port}/mcp") as streams:
                read, write, _ = streams
                async with ClientSession(read, write) as session:
                    initialized = await session.initialize()
                    tools = await session.list_tools()
                    resources = await session.list_resources()
                    prompt = await session.get_prompt(
                        "triage_core", {"core_path": "/tmp/core"}
                    )
                    health = _payload(await session.call_tool("gdb_server_health", {}))

            self.assertIsNotNone(initialized.capabilities.tools)
            self.assertIn("gdb_server_health", {tool.name for tool in tools.tools})
            self.assertEqual(len(resources.resources), 5)
            self.assertIn("Safety boundary:", prompt.messages[0].content.text)
            self.assertTrue(health["ok"], health)
        finally:
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=3.0)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()


if __name__ == "__main__":
    unittest.main()
