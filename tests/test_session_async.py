import asyncio
import os
import tempfile
import unittest
from pathlib import Path

from gdb_mcp.mi import MIRecord
from gdb_mcp.session import CommandResult, GdbMcpError, GdbSession, SessionManager


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

    def test_command_result_compacts_full_hex_values(self) -> None:
        result = CommandResult(
            command="-break-list",
            records=[],
            result_record=MIRecord(
                kind="result",
                raw='1^done,bkpt={addr="0x0000000000401136"}',
                token=1,
                record_class="done",
                results={
                    "bkpt": {
                        "addr": "0x0000000000401136",
                        "script": "break *0x0000000000401136",
                    },
                    "locations": ["0x0000000000000000", "not-hex"],
                },
            ),
        )

        payload = result.to_dict()

        self.assertEqual(payload["results"]["bkpt"]["addr"], "0x401136")
        self.assertEqual(payload["results"]["bkpt"]["script"], "break *0x0000000000401136")
        self.assertEqual(payload["results"]["locations"], ["0x0", "not-hex"])

    def test_command_result_truncates_nested_payloads(self) -> None:
        result = CommandResult(
            command="-stack-list-variables",
            records=[
                MIRecord(
                    kind="stream",
                    raw='~"aaaaaaaa"',
                    stream="console",
                    text="a" * 1500,
                ),
                *[
                    MIRecord(
                        kind="notify",
                        raw=f'=thread-created,id="{index}"',
                        record_class="thread-created",
                        results={"id": str(index), "detail": "b" * 80},
                    )
                    for index in range(40)
                ],
            ],
            result_record=MIRecord(
                kind="result",
                raw='1^done,variables=[{name="value"}]',
                token=1,
                record_class="done",
                results={
                    "variables": [
                        {
                            "name": "large",
                            "value": "c" * 1500,
                            "children": [{"name": "child", "value": "d" * 1500}],
                        }
                    ]
                },
            ),
        )

        payload = result.to_dict(output_limit_chars=20)

        self.assertTrue(payload["ok"])
        self.assertTrue(payload["truncated"])
        self.assertIn("truncated", payload["console"])
        self.assertIsInstance(payload["results"], dict)
        self.assertIsInstance(payload["async"], list)
        self.assertIsInstance(payload["raw"], list)
        self.assertLess(len(payload["console"]), 1100)
        self.assertLess(len(repr(payload["async"])), 1300)
        self.assertLess(len(repr(payload["raw"])), 1300)

    def test_command_result_marks_missing_result_record_as_not_ok(self) -> None:
        result = CommandResult(
            command="-exec-run",
            records=[
                MIRecord(
                    kind="exec",
                    raw='*stopped,reason="exited-normally"',
                    record_class="stopped",
                    results={"reason": "exited-normally"},
                )
            ],
            stopped_record=MIRecord(
                kind="exec",
                raw='*stopped,reason="exited-normally"',
                record_class="stopped",
                results={"reason": "exited-normally"},
            ),
        )

        payload = result.to_dict()

        self.assertFalse(payload["ok"])
        self.assertIsNone(payload["result_class"])
        self.assertEqual(payload["stopped"]["reason"], "exited-normally")

    def test_recent_commands_include_completion_diagnostics(self) -> None:
        asyncio.run(self._test_recent_command_diagnostics())

    async def _test_recent_command_diagnostics(self) -> None:
        manager = SessionManager()
        try:
            session = await manager.create(gdb_path=str(self.fake_gdb))
            done = await session.execute("info files", timeout=1.0)
            self.assertEqual(done.result_record.record_class, "done")

            last = session.recent_commands(1)[0]
            self.assertEqual(last["command"], "info files")
            self.assertEqual(last["status"], "done")
            self.assertEqual(last["result_class"], "done")
            self.assertFalse(last["timed_out"])
            self.assertIsNone(last["error"])
            self.assertGreaterEqual(last["duration_seconds"], 0.0)
            self.assertGreater(last["record_count"], 0)
            self.assertIn("finished_at", last)

            timed_out = await session.execute(
                "-exec-run",
                timeout=0.05,
                wait_for_stop=True,
            )
            self.assertTrue(timed_out.timed_out)

            last = session.recent_commands(1)[0]
            self.assertEqual(last["command"], "-exec-run")
            self.assertEqual(last["status"], "timeout")
            self.assertEqual(last["result_class"], "running")
            self.assertTrue(last["timed_out"])
            self.assertIn("Timed out after", last["error"])

            failed = await session.execute("-bad-command", timeout=1.0)
            self.assertEqual(failed.result_record.record_class, "error")

            last = session.recent_commands(1)[0]
            self.assertEqual(last["command"], "-bad-command")
            self.assertEqual(last["status"], "error")
            self.assertEqual(last["result_class"], "error")
            self.assertEqual(last["error"], "Undefined MI command")
        finally:
            await manager.close_all()

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
