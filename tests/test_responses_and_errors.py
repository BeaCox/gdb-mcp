import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gdb_mcp.config import ServerConfig
from gdb_mcp.pagination import CursorError, paginate_items
from gdb_mcp.responses import error_response
from gdb_mcp.session import (
    GdbMcpError,
    GdbNotFound,
    PolicyDeniedError,
    SessionLimitError,
    SessionManager,
    SessionNotFound,
)
from gdb_mcp.tools import shared
from gdb_mcp.tools.elf import _run_readelf, collect_elf_bundle
from gdb_mcp.tools.inspection_format import (
    decode_c_string,
    disassembly_options,
    filter_source_matches,
    format_paged_console_payload,
)
from gdb_mcp.tools.shared import _require_read_expression, _require_single_line


class ResponsesAndErrorsTests(unittest.TestCase):
    def test_error_classification_covers_every_category(self) -> None:
        _, meta = paginate_items([1, 2], cursor=None, page_size=1, default_page_size=1,
                                 max_page_size=2, cursor_scope="s", cursor_ttl_seconds=1,
                                 _now=100)
        cursor = meta["next_cursor"]
        cases = [
            (ValueError("bad input"), "invalid_input", False),
            (CursorError("invalid cursor: bad"), "invalid_cursor", False),
            (CursorError("expired cursor: request first page"), "expired_cursor", True),
            (CursorError("stale cursor: snapshot changed"), "stale_cursor", True),
            (SessionNotFound("Unknown GDB session: s1"), "session_not_found", False),
            (SessionLimitError("Session limit reached"), "session_limit_reached", True),
            (PolicyDeniedError("requires --unsafe"), "policy_denied", False),
            (PermissionError("include_raw requires --unsafe"), "policy_denied", False),
            (GdbNotFound("GDB executable not found"), "dependency_not_found", False),
            (TimeoutError("Timed out after 5 seconds"), "timeout", True),
            (GdbMcpError("GDB session is closed"), "session_closed", False),
            (GdbMcpError("GDB command failed"), "gdb_error", False),
            (RuntimeError("unexpected"), "internal_error", False),
        ]
        for exc, expected_code, expected_retryable in cases:
            with self.subTest(exc=type(exc).__name__, expected_code=expected_code):
                payload = error_response(exc)
                self.assertFalse(payload["ok"])
                self.assertEqual(payload["error_code"], expected_code)
                self.assertEqual(payload["retryable"], expected_retryable)
                self.assertEqual(payload["error_type"], type(exc).__name__)
        self.assertTrue(cursor.startswith("gdb1."))

    def test_error_response_redacts_secrets(self) -> None:
        payload = error_response(
            RuntimeError(
                "Failed against https://alice:topsecret@example.com Authorization: Bearer abc"
            )
        )
        self.assertNotIn("topsecret", payload["error"])
        self.assertNotIn("abc", payload["error"])
        self.assertIn("[REDACTED]", payload["error"])

    def test_read_expression_blocks_shift_assignments_and_allows_comparisons(self) -> None:
        for bad in ("x <<= 1", "x >>= 2", "x = 1", "x += 1", "foo()", "a; b"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    _require_read_expression("expression", bad)
        for good in ("x << 2", "x >> 1", "a <= b", "a >= b", "a == b", "a != b", "*((int*)$sp)"):
            with self.subTest(good=good):
                _require_read_expression("expression", good)

        with self.assertRaises(ValueError):
            _require_single_line("arg", "ok\0bad")

    def test_inspection_format_helpers(self) -> None:
        self.assertEqual(disassembly_options(False, False), "")
        self.assertEqual(disassembly_options(True, True), "/mr")
        self.assertEqual(
            filter_source_matches("src/a.c, src/b.c src/a.c src/c.c", "src/", 2),
            ["src/a.c", "src/b.c"],
        )
        self.assertEqual(
            decode_c_string({"ok": True, "results": {"memory": [{"contents": "6869007a"}]}}),
            "hi",
        )
        paged = format_paged_console_payload(
            {"ok": True, "console": "l1\nl2\nl3", "result_class": "done"},
            output="structured",
            cursor=None,
            page_size=2,
            default_page_size=10,
            max_page_size=20,
            cursor_scope="test:console",
        )
        self.assertEqual(paged["lines"], ["l1", "l2"])
        self.assertTrue(paged["pagination"]["has_more"])
        self.assertNotIn("console", paged)

    def test_collect_elf_bundle_and_cancelled_readelf_cleanup(self) -> None:
        async def check() -> None:
            prev_manager = shared._manager
            prev_config = shared._runtime_config
            shared.configure(manager=SessionManager(), runtime_config=ServerConfig())
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    fake_readelf = Path(tmp) / "readelf"
                    fake_readelf.write_text(
                        "#!/usr/bin/env python3\n"
                        "import json, sys\n"
                        "print(json.dumps(sys.argv[1:]))\n",
                        encoding="utf-8",
                    )
                    fake_readelf.chmod(0o755)
                    with patch("gdb_mcp.tools.elf.shutil.which", return_value=str(fake_readelf)):
                        bundle = await collect_elf_bundle("/tmp/sample", timeout=2.0)
                    self.assertEqual(
                        set(bundle),
                        {"header", "sections", "program_headers", "dynamic", "symbols", "notes"},
                    )
                    self.assertEqual(
                        json.loads(bundle["header"]["stdout"]),
                        ["-W", "-h", "--", "/tmp/sample"],
                    )

                    slow_readelf = Path(tmp) / "slow_readelf"
                    pid_file = Path(tmp) / "pid"
                    slow_readelf.write_text(
                        "#!/usr/bin/env python3\n"
                        f"import os, time; open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
                        "time.sleep(30)\n",
                        encoding="utf-8",
                    )
                    slow_readelf.chmod(0o755)
                    with patch("gdb_mcp.tools.elf.shutil.which", return_value=str(slow_readelf)):
                        task = asyncio.create_task(_run_readelf("/tmp/sample", ["-h"], timeout=5.0))
                        for _ in range(50):
                            if pid_file.exists():
                                break
                            await asyncio.sleep(0.02)
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
            finally:
                shared._manager = prev_manager
                shared._runtime_config = prev_config

        asyncio.run(check())


if __name__ == "__main__":
    unittest.main()
