import unittest

from gdb_mcp.analysis import (
    address_mapping_info,
    group_registers,
    parse_checksec,
    parse_disassembly,
    parse_gdb_symbols,
    parse_mappings,
    parse_readelf_relocations,
    parse_sections,
    register_rows,
    source_context,
)


class AnalysisTests(unittest.TestCase):
    def test_parse_checksec_handles_real_readelf_gnu_stack_alignment_and_flags_1(self) -> None:
        header = "  Type:                              DYN (Position-Independent Executable file)\n"
        header += "  Machine:                           Advanced Micro Devices X86-64\n"
        header += "  Entry point address:               0x1040\n"
        program_headers = (
            "  Type           Offset   VirtAddr           PhysAddr           "
            "FileSiz  MemSiz   Flg Align\n"
            "  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 "
            "0x000000 0x000000 RW  0x10\n"
            "  GNU_RELRO      0x002dd0 0x0000000000003dd0 0x0000000000003dd0 "
            "0x000230 0x000230 R   0x1\n"
        )
        dynamic = " 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE\n"
        symbols = "    12: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __stack_chk_fail\n"

        sec = parse_checksec(header, program_headers, dynamic, symbols)
        self.assertTrue(sec["pie"])
        self.assertTrue(sec["nx"])
        self.assertTrue(sec["canary"])
        self.assertTrue(sec["bind_now"])
        self.assertEqual(sec["relro"], "Full RELRO")

        exec_stack = program_headers.replace("RW  0x10", "RWE 0x10")
        sec_exec = parse_checksec(header, exec_stack, "", "")
        self.assertFalse(sec_exec["nx"])
        self.assertEqual(sec_exec["relro"], "Partial RELRO")

        synthetic_exec = "  GNU_STACK      0x000000 0x0 0x0 0x0 0x0 RWE\n"
        self.assertFalse(parse_checksec(header, synthetic_exec, "", "")["nx"])

    def test_parse_mappings_and_address_info(self) -> None:
        console = (
            "          Start Addr           End Addr       Size     Offset  Perms  objfile\n"
            "            0x400000           0x402000     0x2000        0x0  r-xp   /tmp/app\n"
            "      0x7ffffffde000     0x7ffffffff000    0x21000        0x0  rw-p   [stack]\n"
        )
        mappings = parse_mappings(console)
        self.assertEqual(len(mappings), 2)
        self.assertEqual(mappings[0]["kind"], "file")
        self.assertEqual(mappings[1]["kind"], "stack")

        info = address_mapping_info(0x401234, mappings)
        assert info is not None
        self.assertEqual(info["module"], "app")
        self.assertEqual(info["offset_in_mapping"], "0x1234")
        self.assertIsNone(address_mapping_info(0x1234, mappings))

    def test_parse_disassembly_sections_relocations_symbols_and_source(self) -> None:
        disasm = parse_disassembly(
            "=> 0x401004 <main+4>: call 0x401030 <puts@plt>\n   0x401009: ret\n",
            current_address=0x401004,
        )
        self.assertEqual(len(disasm), 2)
        self.assertTrue(disasm[0]["current"])
        self.assertEqual(disasm[0]["target"], "0x401030")

        sections = parse_sections(
            "  [ 1] .text             PROGBITS        "
            "0000000000401000 001000 000200 00  AX  0   0 16\n"
        )
        self.assertEqual(sections[0]["name"], ".text")
        self.assertEqual(sections[0]["addr"], "0x401000")

        relocs = parse_readelf_relocations(
            "000000404018  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0\n"
        )
        self.assertEqual(relocs[0]["offset"], "0x404018")
        self.assertEqual(relocs[0]["symbol"], "puts@GLIBC_2.2.5")

        syms = parse_gdb_symbols("File main.c:\n0x401000  int main(int, char **);\n", limit=10)
        self.assertEqual(syms[0]["name"], "main")
        self.assertEqual(syms[0]["file"], "File main.c")

        src = source_context(
            "10\tint x = 1;\n=> 11\treturn x;\n",
            'Line 11 of "/tmp/main.c" starts at address 0x401004.\n',
        )
        self.assertEqual(src["file_path"], "/tmp/main.c")
        self.assertEqual(src["current_line"], 11)
        self.assertEqual(src["vscode_uri"], "vscode://file/tmp/main.c:10")

    def test_register_rows_and_grouping(self) -> None:
        names = {"results": {"register-names": ["rax", "rsp", "rip", "r12", ""]}}
        values = {
            "results": {
                "register-values": [
                    {"number": "0", "value": "0x1"},
                    {"number": "1", "value": "0x7fff"},
                    {"number": "2", "value": "0x401000"},
                    {"number": "3", "value": "0x9"},
                ]
            }
        }
        rows = register_rows(names, values)
        grouped = group_registers(rows)
        self.assertEqual([r["name"] for r in grouped["return"]], ["rax"])
        self.assertEqual([r["name"] for r in grouped["stack"]], ["rsp"])
        self.assertEqual([r["name"] for r in grouped["instruction"]], ["rip"])
        self.assertEqual([r["name"] for r in grouped["general"]], ["r12"])


if __name__ == "__main__":
    unittest.main()
