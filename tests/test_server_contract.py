import ast
import asyncio
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gdb_mcp.server import (
    _run_readelf,
    gdb_address_info,
    gdb_attach,
    gdb_binary_summary,
    gdb_break_rva,
    gdb_breakpoint_commands,
    gdb_breakpoint_condition,
    gdb_call_function,
    gdb_capabilities,
    gdb_checksec,
    gdb_close_idle_sessions,
    gdb_command_reference,
    gdb_connect_gdbserver,
    gdb_context,
    gdb_continue_and_context,
    gdb_current_location,
    gdb_detach,
    gdb_detach_gdbserver,
    gdb_disable_breakpoint,
    gdb_disassemble,
    gdb_disassemble_around_pc,
    gdb_disassemble_current_frame,
    gdb_elf_info,
    gdb_enable_breakpoint,
    gdb_eval_expression,
    gdb_execute,
    gdb_find_source,
    gdb_frame_variables,
    gdb_gdbserver_status,
    gdb_got,
    gdb_info_files,
    gdb_kill,
    gdb_load_core,
    gdb_memory_mappings,
    gdb_nearpc,
    gdb_next_and_context,
    gdb_piebase,
    gdb_print,
    gdb_pwn_context,
    gdb_read_c_string,
    gdb_read_memory,
    gdb_read_register,
    gdb_recent_commands,
    gdb_record_status,
    gdb_register_context,
    gdb_register_names,
    gdb_registers,
    gdb_reverse_continue,
    gdb_reverse_continue_and_context,
    gdb_reverse_finish,
    gdb_reverse_finish_and_context,
    gdb_reverse_next,
    gdb_reverse_next_and_context,
    gdb_reverse_step,
    gdb_reverse_step_and_context,
    gdb_rva_info,
    gdb_search_memory,
    gdb_select_thread,
    gdb_session_diagnostics,
    gdb_set_breakpoint,
    gdb_set_remote_paths,
    gdb_set_variable,
    gdb_set_watchpoint,
    gdb_shared_libraries,
    gdb_signal,
    gdb_source,
    gdb_stack_arguments,
    gdb_start_recording,
    gdb_step_and_context,
    gdb_stop_recording,
    gdb_symbols,
    gdb_telescope,
    gdb_thread_apply_all_backtrace,
    gdb_vmmap_structured,
    gdb_write_memory,
    manager,
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
        self.assertIn("gdb_capabilities", names)
        self.assertIn("gdb_recent_events", names)
        self.assertIn("gdb_attach", names)
        self.assertIn("gdb_load_core", names)
        self.assertIn("gdb_eval_expression", names)
        self.assertIn("gdb_disassemble", names)
        self.assertIn("gdb_source", names)
        self.assertIn("gdb_set_watchpoint", names)
        for name in (
            "gdb_detach",
            "gdb_kill",
            "gdb_restart",
            "gdb_signal",
            "gdb_start_recording",
            "gdb_stop_recording",
            "gdb_record_status",
            "gdb_reverse_continue",
            "gdb_reverse_continue_and_context",
            "gdb_reverse_step",
            "gdb_reverse_step_and_context",
            "gdb_reverse_next",
            "gdb_reverse_next_and_context",
            "gdb_reverse_finish",
            "gdb_reverse_finish_and_context",
            "gdb_print",
            "gdb_call_function",
            "gdb_set_variable",
            "gdb_enable_breakpoint",
            "gdb_disable_breakpoint",
            "gdb_breakpoint_condition",
            "gdb_breakpoint_commands",
            "gdb_current_location",
            "gdb_context",
            "gdb_run_and_context",
            "gdb_continue_and_context",
            "gdb_step_and_context",
            "gdb_next_and_context",
            "gdb_disassemble_current_frame",
            "gdb_find_source",
            "gdb_thread_apply_all_backtrace",
            "gdb_stack_arguments",
            "gdb_frame_variables",
            "gdb_write_memory",
            "gdb_search_memory",
            "gdb_read_c_string",
            "gdb_shared_libraries",
            "gdb_info_files",
            "gdb_memory_mappings",
            "gdb_set_remote_paths",
            "gdb_detach_gdbserver",
            "gdb_gdbserver_status",
            "gdb_recent_commands",
            "gdb_session_diagnostics",
            "gdb_close_idle_sessions",
            "gdb_read_register",
            "gdb_register_names",
            "gdb_disassemble_around_pc",
            "gdb_command_reference",
            "gdb_capabilities",
            "gdb_vmmap_structured",
            "gdb_address_info",
            "gdb_telescope",
            "gdb_nearpc",
            "gdb_piebase",
            "gdb_break_rva",
            "gdb_pwn_context",
            "gdb_binary_summary",
            "gdb_register_context",
            "gdb_symbols",
            "gdb_got",
            "gdb_rva_info",
            "gdb_checksec",
            "gdb_elf_info",
        ):
            self.assertIn(name, names)
        for tool in tools:
            with self.subTest(tool=tool.name):
                self.assertTrue(tool.description)
                self.assertEqual(tool.inputSchema.get("type"), "object")
                self.assertEqual(tool.outputSchema.get("type"), "object")
                self.assertIsNotNone(tool.annotations)

    def test_tools_reference_covers_public_mcp_tools(self) -> None:
        tools = asyncio.run(self._tool_names())
        reference = Path(__file__).resolve().parents[1] / "TOOLS.md"
        documented = set(
            re.findall(r"`(gdb_[A-Za-z0-9_]+)`", reference.read_text(encoding="utf-8"))
        )
        self.assertEqual(sorted(tools - documented), [])

    async def _tool_names(self) -> set[str]:
        return {tool.name for tool in await mcp.list_tools()}

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

    def test_breakpoint_tools_reject_malformed_numbers(self) -> None:
        for number in ("", ".", "1.", ".1", "1..2", "a1"):
            with self.subTest(number=number):
                result = asyncio.run(gdb_enable_breakpoint("missing", number))
                self.assertFalse(result["ok"])
                self.assertIn("Breakpoint number", result["error"])

    def test_safe_expression_tools_reject_calls_and_mutations(self) -> None:
        results = [
            asyncio.run(gdb_eval_expression("missing", "puts(1)")),
            asyncio.run(gdb_eval_expression("missing", "value = 1")),
            asyncio.run(gdb_set_watchpoint("missing", "counter++")),
            asyncio.run(gdb_print("missing", "puts(1)")),
            asyncio.run(gdb_set_breakpoint("missing", "main", condition="puts(1)")),
            asyncio.run(gdb_read_memory("missing", "puts(1)", 1)),
            asyncio.run(gdb_read_c_string("missing", "puts(1)")),
            asyncio.run(gdb_search_memory("missing", "0x1000", 1, "puts(1)")),
        ]
        for result in results:
            with self.subTest(result=result):
                self.assertFalse(result["ok"])
        self.assertIn("call functions", results[0]["error"])
        self.assertIn("modify", results[1]["error"])
        self.assertIn("modify", results[2]["error"])
        self.assertIn("call functions", results[3]["error"])
        self.assertIn("call functions", results[4]["error"])
        self.assertIn("call functions", results[5]["error"])
        self.assertIn("call functions", results[6]["error"])
        self.assertIn("call functions", results[7]["error"])

    def test_core_path_rejects_multiline_input(self) -> None:
        result = asyncio.run(gdb_load_core("/tmp/core\nbad", session_id="missing"))
        self.assertFalse(result["ok"])
        self.assertIn("line breaks", result["error"])

    def test_connect_gdbserver_invalid_endpoint_does_not_leak_session(self) -> None:
        asyncio.run(self._test_connect_gdbserver_invalid_endpoint_does_not_leak_session())

    async def _test_connect_gdbserver_invalid_endpoint_does_not_leak_session(self) -> None:
        fake_gdb = Path(__file__).parent / "fixtures" / "fake_gdb.py"
        fake_gdb.chmod(0o755)
        before_ids = {session["session_id"] for session in await manager.list()}
        try:
            result = await gdb_connect_gdbserver(
                "bad endpoint",
                gdb_path=str(fake_gdb),
                timeout=1.0,
            )
            after_ids = {session["session_id"] for session in await manager.list()}
            self.assertFalse(result["ok"])
            self.assertIn("single unquoted", result["error"])
            self.assertEqual(after_ids, before_ids)
        finally:
            for session in await manager.list():
                if session["session_id"] not in before_ids:
                    await manager.close(str(session["session_id"]))

    def test_connect_gdbserver_cancelled_connect_does_not_leak_session(self) -> None:
        asyncio.run(self._test_connect_gdbserver_cancelled_connect_does_not_leak_session())

    async def _test_connect_gdbserver_cancelled_connect_does_not_leak_session(self) -> None:
        fake_gdb = Path(__file__).parent / "fixtures" / "fake_gdb.py"
        fake_gdb.chmod(0o755)
        before_ids = {session["session_id"] for session in await manager.list()}

        async def cancelled_connect(*args: object, **kwargs: object) -> dict[str, object]:
            raise asyncio.CancelledError

        try:
            with patch("gdb_mcp.server.GdbSession.connect_gdbserver", cancelled_connect):
                with self.assertRaises(asyncio.CancelledError):
                    await gdb_connect_gdbserver(
                        "localhost:1234",
                        gdb_path=str(fake_gdb),
                        timeout=1.0,
                    )
            after_ids = {session["session_id"] for session in await manager.list()}
            self.assertEqual(after_ids, before_ids)
        finally:
            for session in await manager.list():
                if session["session_id"] not in before_ids:
                    await manager.close(str(session["session_id"]))

    def test_thread_id_must_be_positive(self) -> None:
        result = asyncio.run(gdb_select_thread("missing", "0"))
        self.assertFalse(result["ok"])
        self.assertIn("positive integer", result["error"])

    def test_register_number_lists_are_bounded(self) -> None:
        negative = asyncio.run(gdb_registers("missing", register_numbers=[-1]))
        too_many = asyncio.run(gdb_register_names("missing", register_numbers=[0] * 513))
        non_integer = asyncio.run(gdb_registers("missing", register_numbers=[True]))

        self.assertFalse(negative["ok"])
        self.assertIn("non-negative integers", negative["error"])
        self.assertFalse(too_many["ok"])
        self.assertIn("at most 512", too_many["error"])
        self.assertFalse(non_integer["ok"])
        self.assertIn("non-negative integers", non_integer["error"])

    def test_elf_file_path_rejects_empty_and_nul(self) -> None:
        for file_path in ("", "abc\0def"):
            with self.subTest(file_path=repr(file_path)):
                result = asyncio.run(gdb_checksec(file_path=file_path))
                self.assertFalse(result["ok"])
                self.assertRegex(result["error"], "empty|unsupported")

    def test_unsafe_dedicated_tools_are_disabled_by_default(self) -> None:
        previous = runtime_config.allow_unsafe_execute
        runtime_config.allow_unsafe_execute = False
        try:
            results = [
                asyncio.run(gdb_call_function("missing", "puts(1)")),
                asyncio.run(gdb_set_variable("missing", "value", "1")),
                asyncio.run(gdb_write_memory("missing", "0x1000", "41")),
                asyncio.run(gdb_breakpoint_commands("missing", "1", ["continue"])),
            ]
        finally:
            runtime_config.allow_unsafe_execute = previous
        for result in results:
            with self.subTest(result=result):
                self.assertFalse(result["ok"])
                self.assertIn("requires --unsafe", result["error"])

    def test_new_tool_commands_are_stable(self) -> None:
        asyncio.run(self._test_new_tool_commands())

    async def _test_new_tool_commands(self) -> None:
        fake_gdb = Path(__file__).parent / "fixtures" / "fake_gdb.py"
        fake_gdb.chmod(0o755)
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "commands.log"
            session = await manager.create(
                gdb_path=str(fake_gdb),
                env={"FAKE_GDB_LOG": str(log_path)},
            )
            try:
                session_id = session.session_id
                self.assertTrue((await gdb_attach(1234, session_id=session_id))["ok"])
                self.assertTrue(
                    (await gdb_load_core("/tmp/core.sample", session_id=session_id))["ok"]
                )
                self.assertTrue(
                    (await gdb_load_core("/tmp/core with spaces", session_id=session_id))[
                        "ok"
                    ]
                )
                self.assertTrue((await gdb_signal(session_id, "0"))["ok"])
                self.assertTrue((await gdb_start_recording(session_id))["ok"])
                self.assertTrue((await gdb_record_status(session_id))["ok"])
                self.assertTrue((await gdb_reverse_continue(session_id))["ok"])
                self.assertTrue(
                    (await gdb_reverse_continue_and_context(session_id))["ok"]
                )
                self.assertTrue((await gdb_reverse_step(session_id))["ok"])
                self.assertTrue((await gdb_reverse_step(session_id, instruction=True))["ok"])
                self.assertTrue((await gdb_reverse_step_and_context(session_id))["ok"])
                self.assertTrue((await gdb_reverse_next(session_id))["ok"])
                self.assertTrue((await gdb_reverse_next(session_id, instruction=True))["ok"])
                self.assertTrue((await gdb_reverse_next_and_context(session_id))["ok"])
                self.assertTrue((await gdb_reverse_finish(session_id))["ok"])
                self.assertTrue((await gdb_reverse_finish_and_context(session_id))["ok"])
                self.assertTrue((await gdb_stop_recording(session_id))["ok"])
                self.assertTrue(
                    (await gdb_eval_expression(session_id, "value + 1"))["ok"]
                )
                self.assertTrue((await gdb_print(session_id, "value + 1"))["ok"])
                self.assertTrue(
                    (await gdb_set_watchpoint(session_id, "value", access="write"))["ok"]
                )
                self.assertTrue((await gdb_enable_breakpoint(session_id, "1"))["ok"])
                self.assertTrue((await gdb_disable_breakpoint(session_id, "1"))["ok"])
                self.assertTrue(
                    (await gdb_breakpoint_condition(session_id, "1", "value == 42"))[
                        "ok"
                    ]
                )
                self.assertTrue(
                    (await gdb_set_breakpoint(session_id, "*0x401000", hardware=True))[
                        "ok"
                    ]
                )
                self.assertTrue(
                    (await gdb_disassemble(session_id, location="main", mixed=True))[
                        "ok"
                    ]
                )
                self.assertTrue(
                    (await gdb_disassemble(
                        session_id,
                        start_address="0x1000",
                        end_address="0x1010",
                        raw_bytes=True,
                    ))["ok"]
                )
                self.assertTrue((await gdb_disassemble_around_pc(session_id))["ok"])
                self.assertTrue((await gdb_current_location(session_id))["ok"])
                self.assertTrue((await gdb_context(session_id))["ok"])
                self.assertTrue(
                    (await gdb_continue_and_context(session_id, timeout=1.0))["ok"]
                )
                self.assertTrue(
                    (await gdb_step_and_context(session_id, timeout=1.0))["ok"]
                )
                self.assertTrue(
                    (await gdb_next_and_context(session_id, timeout=1.0))["ok"]
                )
                self.assertTrue(
                    (await gdb_disassemble_current_frame(session_id, raw_bytes=True))[
                        "ok"
                    ]
                )
                self.assertTrue((await gdb_find_source(session_id, "sample"))["ok"])
                self.assertTrue((await gdb_source(session_id, "sample.c:7"))["ok"])
                self.assertTrue(
                    (await gdb_thread_apply_all_backtrace(session_id, 3))["ok"]
                )
                self.assertTrue((await gdb_stack_arguments(session_id, 3))["ok"])
                self.assertTrue((await gdb_frame_variables(session_id, "all"))["ok"])
                self.assertTrue((await gdb_register_names(session_id))["ok"])
                self.assertTrue((await gdb_read_register(session_id, "pc"))["ok"])
                self.assertTrue(
                    (await gdb_search_memory(session_id, "0x1000", 16, "0x41"))["ok"]
                )
                self.assertTrue(
                    (await gdb_read_c_string(session_id, "0x1000", 16))["ok"]
                )
                self.assertTrue((await gdb_shared_libraries(session_id))["ok"])
                self.assertTrue((await gdb_info_files(session_id))["ok"])
                self.assertTrue((await gdb_memory_mappings(session_id))["ok"])
                self.assertTrue((await gdb_vmmap_structured(session_id))["ok"])
                self.assertTrue(
                    (await gdb_address_info(session_id, "0x401004", read_string=False))[
                        "ok"
                    ]
                )
                self.assertTrue((await gdb_telescope(session_id, "0x7fffffffe000"))["ok"])
                self.assertTrue((await gdb_nearpc(session_id))["ok"])
                self.assertTrue((await gdb_piebase(session_id, offset=0x100))["ok"])
                self.assertTrue((await gdb_rva_info(session_id, offset=0x100))["ok"])
                self.assertTrue((await gdb_register_context(session_id))["ok"])
                self.assertTrue((await gdb_symbols(session_id, query="main"))["ok"])
                self.assertTrue((await gdb_break_rva(session_id, offset=0x100))["ok"])
                self.assertTrue((await gdb_pwn_context(session_id))["ok"])
                self.assertTrue(
                    (await gdb_set_remote_paths(session_id, sysroot="/tmp/sysroot"))[
                        "ok"
                    ]
                )
                self.assertTrue((await gdb_gdbserver_status(session_id))["ok"])
                self.assertTrue((await gdb_recent_commands(session_id))["ok"])
                self.assertTrue((await gdb_session_diagnostics(session_id))["ok"])
                self.assertTrue((await gdb_command_reference())["ok"])
                capabilities = await gdb_capabilities()
                self.assertTrue(capabilities["ok"])
                self.assertIn("binary_analysis", capabilities["workflows"])
                self.assertEqual(capabilities["session_model"]["multi_session"], True)
                previous = runtime_config.allow_unsafe_execute
                runtime_config.allow_unsafe_execute = True
                try:
                    self.assertTrue(
                        (await gdb_call_function(session_id, "puts(1)"))["ok"]
                    )
                    self.assertTrue(
                        (await gdb_set_variable(session_id, "value", "1"))["ok"]
                    )
                    self.assertTrue(
                        (await gdb_write_memory(session_id, "0x1000", "4142"))["ok"]
                    )
                    self.assertTrue(
                        (
                            await gdb_breakpoint_commands(
                                session_id,
                                "1",
                                ["silent", "continue"],
                            )
                        )["ok"]
                    )
                finally:
                    runtime_config.allow_unsafe_execute = previous
                self.assertTrue((await gdb_detach_gdbserver(session_id))["ok"])
                self.assertTrue((await gdb_detach(session_id))["ok"])
                self.assertTrue((await gdb_kill(session_id))["ok"])
            finally:
                await manager.close(session.session_id)

            commands = log_path.read_text(encoding="utf-8")
            self.assertIn("-target-attach 1234", commands)
            self.assertIn('target core /tmp/core.sample', commands)
            self.assertIn("signal 0", commands)
            self.assertIn('-data-evaluate-expression "value + 1"', commands)
            self.assertIn('print value + 1', commands)
            self.assertIn('watch value', commands)
            self.assertIn("-break-enable 1", commands)
            self.assertIn("-break-disable 1", commands)
            self.assertIn("condition 1 value == 42", commands)
            self.assertIn("hbreak *0x401000", commands)
            self.assertIn('disassemble /m main', commands)
            self.assertIn('disassemble /r 0x1000,0x1010', commands)
            self.assertIn("disassemble $pc-32,$pc+96", commands)
            self.assertIn("-stack-info-frame", commands)
            self.assertIn("-stack-list-frames 0 9", commands)
            self.assertIn("-stack-list-variables --simple-values", commands)
            self.assertIn("-exec-continue", commands)
            self.assertIn("-exec-step", commands)
            self.assertIn("-exec-next", commands)
            self.assertIn("disassemble /r $pc", commands)
            self.assertIn("info sources", commands)
            self.assertIn('list sample.c:7', commands)
            self.assertIn("thread apply all backtrace 3", commands)
            self.assertIn("-stack-list-arguments --simple-values 0 2", commands)
            self.assertIn("-stack-list-variables --simple-values", commands)
            self.assertIn("-data-list-register-names", commands)
            self.assertIn('-data-evaluate-expression "$pc"', commands)
            self.assertIn("find 0x1000, +16, 0x41", commands)
            self.assertIn('-data-read-memory-bytes "0x1000" 16', commands)
            self.assertIn("-file-list-shared-libraries", commands)
            self.assertIn("info files", commands)
            self.assertIn("info proc mappings", commands)
            self.assertIn('info symbol 0x401004', commands)
            self.assertIn('-data-read-memory-bytes "0x7fffffffe000" 64', commands)
            self.assertIn("x/12i 0x400fe4", commands)
            self.assertIn('info symbol 0x400100', commands)
            self.assertIn("-data-list-register-values x", commands)
            self.assertIn("info functions main", commands)
            self.assertIn("break *0x400100", commands)
            self.assertIn('-gdb-set sysroot "/tmp/sysroot"', commands)
            self.assertIn("print puts(1)", commands)
            self.assertIn("set var value = 1", commands)
            self.assertIn('-data-write-memory-bytes "0x1000" 4142', commands)
            self.assertIn("commands 1", commands)
            self.assertIn("-target-detach", commands)
            self.assertIn("kill", commands)
            self.assertIn('target core /tmp/core with spaces', commands)
            self.assertIn("target record-full", commands)
            self.assertIn("info record", commands)
            self.assertIn("reverse-continue", commands)
            self.assertIn("reverse-step", commands)
            self.assertIn("reverse-stepi", commands)
            self.assertIn("reverse-next", commands)
            self.assertIn("reverse-nexti", commands)
            self.assertIn("reverse-finish", commands)
            self.assertIn("record stop", commands)

    def test_elf_tools_reject_missing_target(self) -> None:
        checksec = asyncio.run(gdb_checksec())
        elf_info = asyncio.run(gdb_elf_info())
        got = asyncio.run(gdb_got())
        binary_summary = asyncio.run(gdb_binary_summary())
        self.assertFalse(checksec["ok"])
        self.assertFalse(elf_info["ok"])
        self.assertFalse(got["ok"])
        self.assertFalse(binary_summary["ok"])
        self.assertIn("Provide session_id or file_path", checksec["error"])
        self.assertIn("Provide session_id or file_path", elf_info["error"])
        self.assertIn("Provide session_id or file_path", got["error"])
        self.assertIn("Provide session_id or file_path", binary_summary["error"])

    def test_readelf_output_is_bounded(self) -> None:
        asyncio.run(self._test_readelf_output_is_bounded())

    async def _test_readelf_output_is_bounded(self) -> None:
        previous = runtime_config.output_limit_chars
        runtime_config.output_limit_chars = 4_000
        with tempfile.TemporaryDirectory() as tmp:
            fake_readelf = Path(tmp) / "readelf"
            fake_readelf.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "sys.stdout.write('A' * 5000)\n"
                "sys.stderr.write('B' * 2000)\n",
                encoding="utf-8",
            )
            fake_readelf.chmod(0o755)
            try:
                with patch("gdb_mcp.server.shutil.which", return_value=str(fake_readelf)):
                    result = await _run_readelf("/tmp/sample", ["-h"], timeout=1.0)
            finally:
                runtime_config.output_limit_chars = previous

        self.assertTrue(result["ok"])
        self.assertTrue(result["truncated"])
        self.assertTrue(result["stdout_truncated"])
        self.assertTrue(result["stderr_truncated"])
        self.assertLessEqual(len(result["stdout"]), result["output_limit_chars"])
        self.assertLessEqual(len(result["stderr"]), result["output_limit_chars"])
        self.assertIn("truncated", result["stdout"])

    def test_readelf_separates_options_from_file_path(self) -> None:
        asyncio.run(self._test_readelf_separates_options_from_file_path())

    async def _test_readelf_separates_options_from_file_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_readelf = Path(tmp) / "readelf"
            fake_readelf.write_text(
                "#!/usr/bin/env python3\n"
                "import json\n"
                "import sys\n"
                "print(json.dumps(sys.argv[1:]))\n",
                encoding="utf-8",
            )
            fake_readelf.chmod(0o755)
            with patch("gdb_mcp.server.shutil.which", return_value=str(fake_readelf)):
                result = await _run_readelf("-dash-file", ["-h"], timeout=1.0)

        self.assertTrue(result["ok"])
        self.assertEqual(json.loads(result["stdout"]), ["-W", "-h", "--", "-dash-file"])

    def test_context_rejects_invalid_frame_count(self) -> None:
        result = asyncio.run(gdb_context("missing", max_frames=0))
        self.assertFalse(result["ok"])
        self.assertIn("max_frames", result["error"])

    def test_close_idle_sessions(self) -> None:
        asyncio.run(self._test_close_idle_sessions())

    async def _test_close_idle_sessions(self) -> None:
        fake_gdb = Path(__file__).parent / "fixtures" / "fake_gdb.py"
        fake_gdb.chmod(0o755)
        session = await manager.create(gdb_path=str(fake_gdb))
        result = await gdb_close_idle_sessions(max_idle_seconds=0)
        self.assertTrue(result["ok"], result)
        self.assertGreaterEqual(result["closed_count"], 1)
        self.assertIn(session.session_id, str(result["closed"]))


if __name__ == "__main__":
    unittest.main()
