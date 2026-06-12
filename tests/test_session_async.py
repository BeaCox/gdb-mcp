import asyncio
import os
import tempfile
import unittest
from pathlib import Path

from gdb_mcp.session import GdbMcpError, GdbSession, SessionManager


class GdbSessionAsyncTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fake_gdb = Path(__file__).parent / "fixtures" / "fake_gdb.py"
        self.fake_gdb.chmod(0o755)

    def test_running_command_can_be_interrupted_concurrently(self) -> None:
        asyncio.run(self._test_interrupt())

    async def _test_interrupt(self) -> None:
        manager = SessionManager()
        try:
            session = await manager.create(gdb_path=str(self.fake_gdb))
            running = asyncio.create_task(
                session.execute(
                    "-exec-run",
                    timeout=2.0,
                    wait_for_stop=True,
                )
            )
            await asyncio.sleep(0.05)
            self.assertEqual(session.state, "running")

            interrupted = await session.interrupt(timeout=1.0)
            run_result = await running

            self.assertEqual(interrupted.result_record.record_class, "done")
            self.assertEqual(interrupted.stopped_record.record_class, "stopped")
            self.assertEqual(run_result.result_record.record_class, "running")
            self.assertEqual(run_result.stopped_record.record_class, "stopped")
            self.assertEqual(session.state, "stopped")
        finally:
            await manager.close_all()

    def test_arguments_use_mi_c_strings(self) -> None:
        asyncio.run(self._test_arguments())

    async def _test_arguments(self) -> None:
        manager = SessionManager()
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "commands.log"
            args = ["hello world", "x'y", 'a"b', "back\\slash"]
            try:
                await manager.create(
                    gdb_path=str(self.fake_gdb),
                    args=args,
                    env={"FAKE_GDB_LOG": str(log_path)},
                )
            finally:
                await manager.close_all()

            commands = log_path.read_text(encoding="utf-8")
            self.assertIn(
                '-exec-arguments "hello world" "x\'y" "a\\"b" "back\\\\slash"',
                commands,
            )
            self.assertNotIn("'\"'\"'", commands)

    def test_startup_timeout_reaps_process(self) -> None:
        asyncio.run(self._test_startup_timeout())

    async def _test_startup_timeout(self) -> None:
        session = GdbSession(
            gdb_path=str(self.fake_gdb),
            env={**os.environ, "FAKE_GDB_NO_PROMPT": "1"},
        )
        with self.assertRaises(asyncio.TimeoutError):
            await session.start(startup_timeout=0.05)
        self.assertFalse(session.is_alive())
        self.assertEqual(session.state, "closed")

    def test_session_limit_includes_concurrent_starts(self) -> None:
        asyncio.run(self._test_session_limit())

    async def _test_session_limit(self) -> None:
        manager = SessionManager(max_sessions=1)
        try:
            results = await asyncio.gather(
                manager.create(gdb_path=str(self.fake_gdb)),
                manager.create(gdb_path=str(self.fake_gdb)),
                return_exceptions=True,
            )
            self.assertEqual(sum(isinstance(item, GdbSession) for item in results), 1)
            self.assertEqual(sum(isinstance(item, GdbMcpError) for item in results), 1)
        finally:
            await manager.close_all()


if __name__ == "__main__":
    unittest.main()
