import asyncio
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from gdb_mcp.server import (
    gdb_attach,
    gdb_close_session,
    gdb_continue,
    gdb_create_session,
    gdb_current_location,
    gdb_detach,
    gdb_disassemble,
    gdb_eval_expression,
    gdb_frame_variables,
    gdb_info_files,
    gdb_launch_gdbserver,
    gdb_load_core,
    gdb_memory_mappings,
    gdb_print,
    gdb_run,
    gdb_set_breakpoint,
    gdb_set_watchpoint,
    gdb_source,
    gdb_stack_arguments,
    gdb_thread_apply_all_backtrace,
)
from gdb_mcp.session import SessionManager

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "tests" / "fixtures" / "sample.c"
ATTACH_TARGET = ROOT / "tests" / "fixtures" / "attach_target.c"


async def compile_fixture(test: unittest.TestCase, source: Path, binary: Path) -> None:
    compiler = await asyncio.create_subprocess_exec(
        "cc",
        "-g",
        "-gdwarf-4",
        "-O0",
        str(source),
        "-o",
        str(binary),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await compiler.communicate()
    if compiler.returncode != 0:
        test.fail(stderr.decode(errors="replace"))


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
            await compile_fixture(self, SAMPLE, binary)

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

    def test_launch_gdbserver_with_ephemeral_port_smoke(self) -> None:
        if shutil.which("cc") is None:
            self.skipTest("cc is not available")
        if shutil.which("gdb") is None:
            self.skipTest("gdb is not available")
        if shutil.which("gdbserver") is None:
            self.skipTest("gdbserver is not available")

        asyncio.run(self._run_gdbserver_smoke())

    async def _run_gdbserver_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "sample"
            await compile_fixture(self, SAMPLE, binary)

            launched = await gdb_launch_gdbserver(
                program=str(binary),
                listen="localhost:0",
                timeout=10.0,
            )
            self.assertTrue(launched["ok"], launched)
            session = launched["session"]
            session_id = session["session_id"]
            self.assertRegex(session["gdbserver_endpoint"], r"^localhost:[0-9]+$")
            self.assertNotEqual(session["gdbserver_endpoint"], "localhost:0")

            try:
                continued = await gdb_continue(session_id, timeout=10.0)
                self.assertTrue(continued["ok"], continued)
                self.assertEqual(continued["result_class"], "running")
                self.assertEqual(continued["stopped"]["reason"], "exited-normally")
            finally:
                await gdb_close_session(session_id)

    def test_dedicated_inspection_tools_smoke(self) -> None:
        if shutil.which("cc") is None:
            self.skipTest("cc is not available")
        if shutil.which("gdb") is None:
            self.skipTest("gdb is not available")

        asyncio.run(self._run_dedicated_inspection_smoke())

    async def _run_dedicated_inspection_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "sample"
            await compile_fixture(self, SAMPLE, binary)

            created = await gdb_create_session(program=str(binary), startup_timeout=10)
            self.assertTrue(created["ok"], created)
            session_id = created["session"]["session_id"]
            try:
                source = await gdb_source(session_id, "main")
                self.assertTrue(source["ok"], source)
                self.assertIn("int value", source["console"])

                disassembly = await gdb_disassemble(session_id, location="main")
                self.assertTrue(disassembly["ok"], disassembly)
                self.assertIn("main", disassembly["console"])

                evaluated = await gdb_eval_expression(session_id, "2 + 40")
                self.assertTrue(evaluated["ok"], evaluated)
                self.assertEqual(evaluated["results"]["value"], "42")

                printed = await gdb_print(session_id, "2 + 40")
                self.assertTrue(printed["ok"], printed)
                self.assertIn("$", printed["console"])

                info_files = await gdb_info_files(session_id)
                self.assertTrue(info_files["ok"], info_files)
                self.assertIn("Symbols from", info_files["console"])

                breakpoint = await gdb_set_breakpoint(session_id, "main")
                self.assertTrue(breakpoint["ok"], breakpoint)
                run = await gdb_run(session_id, timeout=10.0)
                self.assertTrue(run["ok"], run)

                current = await gdb_current_location(session_id)
                self.assertTrue(current["ok"], current)
                self.assertEqual(current["frame"]["result_class"], "done")

                stack_args = await gdb_stack_arguments(session_id, max_frames=3)
                self.assertTrue(stack_args["ok"], stack_args)

                variables = await gdb_frame_variables(session_id, mode="all")
                self.assertTrue(variables["ok"], variables)

                all_threads = await gdb_thread_apply_all_backtrace(session_id, max_frames=3)
                self.assertTrue(all_threads["ok"], all_threads)

                mappings = await gdb_memory_mappings(session_id)
                self.assertTrue(mappings["ok"], mappings)

                watchpoint = await gdb_set_watchpoint(session_id, "value")
                self.assertTrue(watchpoint["ok"], watchpoint)
            finally:
                await gdb_close_session(session_id)

    def test_attach_smoke(self) -> None:
        if not sys.platform.startswith("linux"):
            self.skipTest("attach smoke uses Linux ptrace behavior")
        if shutil.which("cc") is None:
            self.skipTest("cc is not available")
        if shutil.which("gdb") is None:
            self.skipTest("gdb is not available")

        asyncio.run(self._run_attach_smoke())

    async def _run_attach_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "attach-target"
            await compile_fixture(self, ATTACH_TARGET, binary)
            process = await asyncio.create_subprocess_exec(
                str(binary),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            session_id: str | None = None
            try:
                assert process.stdout is not None
                ready = await asyncio.wait_for(process.stdout.readline(), timeout=5.0)
                self.assertEqual(ready.decode(errors="replace").strip(), "ready")

                attached = await gdb_attach(
                    process.pid,
                    program=str(binary),
                    timeout=10.0,
                )
                if not attached["ok"] and "Operation not permitted" in str(attached):
                    self.skipTest(f"ptrace attach is not permitted: {attached}")
                self.assertTrue(attached["ok"], attached)
                session_id = attached["session"]["session_id"]

                evaluated = await gdb_eval_expression(session_id, "marker")
                self.assertTrue(evaluated["ok"], evaluated)
                self.assertEqual(evaluated["results"]["value"], "1234")

                detached = await gdb_detach(session_id)
                self.assertTrue(detached["ok"], detached)
            finally:
                if session_id is not None:
                    await gdb_close_session(session_id)
                if process.returncode is None:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=2.0)
                    except asyncio.TimeoutError:
                        process.kill()
                        await process.wait()

    def test_load_core_smoke(self) -> None:
        if shutil.which("cc") is None:
            self.skipTest("cc is not available")
        if shutil.which("gdb") is None:
            self.skipTest("gdb is not available")

        asyncio.run(self._run_load_core_smoke())

    async def _run_load_core_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "attach-target"
            core = Path(tmp) / "core.sample"
            await compile_fixture(self, ATTACH_TARGET, binary)

            gcore = await asyncio.create_subprocess_exec(
                "gdb",
                "-batch",
                "-q",
                str(binary),
                "-ex",
                "set confirm off",
                "-ex",
                "start",
                "-ex",
                f"gcore {core}",
                "-ex",
                "kill",
                "-ex",
                "quit",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    gcore.communicate(),
                    timeout=15.0,
                )
            except asyncio.TimeoutError:
                gcore.kill()
                stdout, stderr = await gcore.communicate()
                self.skipTest(
                    "gcore timed out: "
                    + (stdout + stderr).decode(errors="replace").strip()
                )
            if gcore.returncode != 0 or not core.exists():
                self.skipTest(
                    "gcore failed: "
                    + (stdout + stderr).decode(errors="replace").strip()
                )

            loaded = await gdb_load_core(str(core), program=str(binary), timeout=10.0)
            self.assertTrue(loaded["ok"], loaded)
            session_id = loaded["session"]["session_id"]
            try:
                evaluated = await gdb_eval_expression(session_id, "marker")
                self.assertTrue(evaluated["ok"], evaluated)
                self.assertEqual(evaluated["results"]["value"], "1234")
            finally:
                await gdb_close_session(session_id)


if __name__ == "__main__":
    unittest.main()
