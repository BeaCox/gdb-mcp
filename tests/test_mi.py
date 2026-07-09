import unittest
from pathlib import Path

from gdb_mcp.mi import MIParseError, c_escape, parse_mi_record, quote_cli_command

FIXTURES = Path(__file__).parent / "fixtures"


class MIParserTests(unittest.TestCase):
    def test_parse_result_tuple(self) -> None:
        record = parse_mi_record(
            '3^done,bkpt={number="1",type="breakpoint",addr="0x0000000000401136"}'
        )
        self.assertEqual(record.kind, "result")
        self.assertEqual(record.token, 3)
        self.assertEqual(record.record_class, "done")
        self.assertEqual(record.results["bkpt"]["number"], "1")
        self.assertEqual(record.results["bkpt"]["addr"], "0x0000000000401136")

    def test_parse_stopped_record(self) -> None:
        record = parse_mi_record(
            '*stopped,reason="breakpoint-hit",frame={func="main",file="main.c",line="7"}'
        )
        self.assertEqual(record.kind, "exec")
        self.assertEqual(record.record_class, "stopped")
        self.assertEqual(record.results["reason"], "breakpoint-hit")
        self.assertEqual(record.results["frame"]["func"], "main")

    def test_parse_stream_unescape(self) -> None:
        record = parse_mi_record('~"hello\\nworld"')
        self.assertEqual(record.kind, "stream")
        self.assertEqual(record.stream, "console")
        self.assertEqual(record.text, "hello\nworld")

    def test_parse_prompt_with_trailing_space(self) -> None:
        record = parse_mi_record("(gdb) ")
        self.assertEqual(record.kind, "prompt")

    def test_parse_list_of_results(self) -> None:
        record = parse_mi_record(
            '^done,threads=[{id="1",state="stopped"},{id="2",state="running"}]'
        )
        self.assertEqual(record.results["threads"][0]["id"], "1")
        self.assertEqual(record.results["threads"][1]["state"], "running")

    def test_parse_list_of_named_results_preserves_duplicates(self) -> None:
        record = parse_mi_record(
            '^done,stack=[frame={level="0",func="main"},frame={level="1",func="start"}]'
        )
        self.assertEqual(record.results["stack"][0]["frame"]["level"], "0")
        self.assertEqual(record.results["stack"][1]["frame"]["func"], "start")

    def test_quote_cli_command(self) -> None:
        command = quote_cli_command('print "hi"')
        self.assertEqual(command, '-interpreter-exec console "print \\"hi\\""')

    def test_c_escape(self) -> None:
        self.assertEqual(c_escape('a\\b"c\n'), '"a\\\\b\\"c\\n"')

    def test_parse_realistic_gdb_mi_transcript_fixture(self) -> None:
        records = [
            parse_mi_record(line)
            for line in (FIXTURES / "mi_transcript.txt").read_text(encoding="utf-8").splitlines()
        ]

        self.assertEqual(records[0].kind, "prompt")
        self.assertEqual(records[1].kind, "stream")
        self.assertEqual(records[1].stream, "console")
        self.assertIn("GNU gdb", records[1].text)
        self.assertEqual(records[2].stream, "log")

        thread_group = records[3]
        self.assertEqual(thread_group.kind, "notify")
        self.assertEqual(thread_group.record_class, "thread-group-added")
        self.assertEqual(thread_group.results["id"], "i1")

        error = records[6]
        self.assertEqual(error.kind, "result")
        self.assertEqual(error.record_class, "error")
        self.assertIn('"file"', error.results["msg"])

        stack = records[7]
        self.assertEqual(stack.token, 3)
        self.assertEqual(stack.record_class, "done")
        self.assertEqual(stack.results["stack"][0]["frame"]["func"], "main")
        self.assertEqual(
            stack.results["stack"][1]["frame"]["args"][0]["name"],
            "main",
        )
        self.assertEqual(
            stack.results["stack"][1]["frame"]["from"],
            "/lib/x86_64-linux-gnu/libc.so.6",
        )

        library = records[8]
        self.assertEqual(library.kind, "notify")
        self.assertEqual(library.record_class, "library-loaded")
        self.assertEqual(library.results["ranges"][0]["from"], "0x00007ffff7fcf000")

        stopped = records[9]
        self.assertEqual(stopped.kind, "exec")
        self.assertEqual(stopped.record_class, "stopped")
        self.assertEqual(stopped.results["reason"], "breakpoint-hit")
        self.assertEqual(stopped.results["frame"]["args"][0]["name"], "argc")

        self.assertEqual(records[10].stream, "target")
        self.assertEqual(records[10].text, "target output\n")

    def test_parse_result_list_with_repeated_non_frame_keys(self) -> None:
        record = parse_mi_record(
            '=breakpoint-modified,bkpt={number="1",locations=[location={number="1.1",'
            'addr="0x401136"},location={number="1.2",addr="0x401142"}]}'
        )

        locations = record.results["bkpt"]["locations"]
        self.assertEqual(locations[0]["location"]["number"], "1.1")
        self.assertEqual(locations[1]["location"]["addr"], "0x401142")

    def test_parse_malformed_lines_raise_parse_error(self) -> None:
        malformed = [
            "not-mi-output",
            '~"unterminated',
            '4^done,broken={name="x"',
            "5^done,=bad",
            '6^done,items=[{name="x"},]',
        ]

        for line in malformed:
            with self.subTest(line=line):
                with self.assertRaises(MIParseError):
                    parse_mi_record(line)


if __name__ == "__main__":
    unittest.main()
