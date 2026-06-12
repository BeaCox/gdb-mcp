import unittest

from gdb_mcp.mi import c_escape, parse_mi_record, quote_cli_command


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


if __name__ == "__main__":
    unittest.main()
