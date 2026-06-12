import asyncio
import shutil
import tempfile
import unittest
from pathlib import Path

from gdb_mcp.session import SessionManager

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "tests" / "fixtures" / "sample.c"


class GdbSessionSmokeTests(unittest.TestCase):
    def test_multiple_sessions_and_breakpoint_smoke(self) -> None:
        if shutil.which("cc") is None:
            self.skipTest("cc is not available")
        if shutil.which("gdb") is None:
            self.skipTest("gdb is not available")

        asyncio.run(self._run_smoke())

    async def _run_smoke(self) -> None:
        manager = SessionManager()
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "sample"
            compiler = await asyncio.create_subprocess_exec(
                "cc",
                "-g",
                "-gdwarf-4",
                "-O0",
                str(SAMPLE),
                "-o",
                str(binary),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await compiler.communicate()
            if compiler.returncode != 0:
                self.fail(stderr.decode(errors="replace"))

            try:
                first = await manager.create(program=str(binary), startup_timeout=10)
                second = await manager.create(program=str(binary), startup_timeout=10)

                info = (await first.execute("info files", timeout=10)).to_dict()
                self.assertTrue(info["ok"], info)
                self.assertIn("Symbols from", info["console"])

                breakpoint = (await first.execute("break main", timeout=10)).to_dict()
                self.assertTrue(breakpoint["ok"], breakpoint)

                breakpoints = (await first.execute("-break-list", timeout=10)).to_dict()
                self.assertTrue(breakpoints["ok"], breakpoints)
                self.assertEqual(
                    breakpoints["results"]["BreakpointTable"]["body"][0]["bkpt"]["func"],
                    "main",
                )

                second_info = (await second.execute("info files", timeout=10)).to_dict()
                self.assertTrue(second_info["ok"], second_info)
                self.assertNotEqual(first.session_id, second.session_id)
            finally:
                await manager.close_all()


if __name__ == "__main__":
    unittest.main()
