import asyncio
import hashlib
import os
import sys
import unittest
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from gdb_mcp.lazy import list_proxy_tools
from gdb_mcp.tool_profiles import parse_tool_profile

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

PROFILE_SNAPSHOTS = {
    "core": (29, "dd909becfbc450f3b79030ae32473eb3c4789278dc1f4496a1299e3551600b79"),
    "advanced:binary_analysis": (
        43,
        "7552ff5d28fdf5ed183d5a8641402a21e9ebeb6b5638ab01265bb803344bf9a6",
    ),
    "advanced:reverse_debugging": (
        42,
        "1fec47b3585e7a81b5865a73570f4f6126e0e89eacbbd188dacd37f698b31fcf",
    ),
    "advanced:remote_target": (
        34,
        "fbda4481b91c8dfb17438ceef8d9579f104c9f73eeb41008b2e394bded461b7f",
    ),
    "advanced:diagnostics": (
        34,
        "6c2772c6003f38a10bb901ea7f7e9e794e9e13e34ffd533320dc593c0e768634",
    ),
    "advanced:unsafe": (
        34,
        "5ec82c3562f1c76555700a7c621d91e7792645dca80e7c6c900ea73bac2ed891",
    ),
    "full": (98, "eebdcb0bd3bee6b9e8f1c40011ed601bd6b7ff0ba381c26a1d87867cbf0e9fda"),
}


class ToolProfileTests(unittest.TestCase):
    def test_core_profile_matches_over_direct_backend_and_lazy_cli(self) -> None:
        async def check() -> None:
            env = os.environ.copy()
            env["PYTHONPATH"] = os.pathsep.join(
                [str(SRC), *(item for item in [env.get("PYTHONPATH")] if item)]
            )
            commands = [
                ["-m", "gdb_mcp.server", "--tool-profile", "core"],
                [
                    "-m",
                    "gdb_mcp.cli",
                    "--tool-profile",
                    "core",
                    "--backend-command",
                    "/definitely/missing/gdb-mcp-backend",
                ],
            ]
            discovered = []
            for args in commands:
                params = StdioServerParameters(
                    command=sys.executable,
                    args=args,
                    env=env,
                    cwd=ROOT,
                )
                async with stdio_client(params) as (read, write):
                    async with ClientSession(read, write) as session:
                        await session.initialize()
                        tools = await session.list_tools()
                discovered.append([tool.name for tool in tools.tools])

            self.assertEqual(discovered[0], discovered[1])
            self.assertEqual(len(discovered[0]), 29)
            self.assertNotIn("gdb_execute", discovered[0])

        asyncio.run(check())

    def test_profile_snapshots_are_stable(self) -> None:
        asyncio.run(self._test_profile_snapshots_are_stable())

    async def _test_profile_snapshots_are_stable(self) -> None:
        for profile, (expected_count, expected_digest) in PROFILE_SNAPSHOTS.items():
            with self.subTest(profile=profile):
                names = sorted(tool.name for tool in await list_proxy_tools(profile))
                digest = hashlib.sha256("\n".join(names).encode()).hexdigest()
                self.assertEqual(len(names), expected_count)
                self.assertEqual(digest, expected_digest)

    def test_advanced_profiles_include_core_and_selected_groups(self) -> None:
        async def check() -> None:
            core = {tool.name for tool in await list_proxy_tools("core")}
            remote = {tool.name for tool in await list_proxy_tools("advanced:remote_target")}
            combined = {
                tool.name
                for tool in await list_proxy_tools(
                    "advanced:remote_target,binary_analysis"
                )
            }
            self.assertLess(core, remote)
            self.assertIn("gdb_connect_gdbserver", remote)
            self.assertNotIn("gdb_symbols", remote)
            self.assertIn("gdb_symbols", combined)

        asyncio.run(check())

    def test_invalid_profile_reports_available_groups(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown groups: missing"):
            parse_tool_profile("advanced:missing")


if __name__ == "__main__":
    unittest.main()
