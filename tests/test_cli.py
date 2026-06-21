import sys
import unittest
from unittest.mock import patch

from gdb_mcp import cli


class CliTests(unittest.TestCase):
    def test_backend_flags_are_forwarded_to_spawned_backend(self) -> None:
        captured = {}

        async def fake_run_stdio(backend):
            captured["backend"] = backend

        argv = [
            "gdb-mcp",
            "--unsafe",
            "--max-sessions",
            "12",
            "--output-limit-chars",
            "123456",
            "--backend-arg=--transport",
            "--backend-arg",
            "stdio",
        ]
        with patch.object(sys, "argv", argv), patch.object(cli, "run_stdio", fake_run_stdio):
            cli.main()

        backend = captured["backend"]
        self.assertEqual(backend.command, sys.executable)
        self.assertEqual(
            backend.args,
            [
                "-m",
                "gdb_mcp.server",
                "--transport",
                "stdio",
                "--unsafe",
                "--max-sessions",
                "12",
                "--output-limit-chars",
                "123456",
            ],
        )

    def test_backend_flags_are_not_forwarded_to_http_backend(self) -> None:
        captured = {}

        async def fake_run_stdio(backend):
            captured["backend"] = backend

        argv = [
            "gdb-mcp",
            "--backend-url",
            "http://127.0.0.1:8000/mcp",
            "--unsafe",
            "--max-sessions",
            "12",
            "--output-limit-chars",
            "123456",
        ]
        with patch.object(sys, "argv", argv), patch.object(cli, "run_stdio", fake_run_stdio):
            cli.main()

        backend = captured["backend"]
        self.assertEqual(backend.url, "http://127.0.0.1:8000/mcp")
        self.assertEqual(backend.args, ["-m", "gdb_mcp.server"])

    def test_backend_command_is_split_and_extended(self) -> None:
        captured = {}

        async def fake_run_stdio(backend):
            captured["backend"] = backend

        argv = [
            "gdb-mcp",
            "--backend-command",
            "python -m gdb_mcp.server",
            "--backend-arg=--unsafe",
        ]
        with patch.object(sys, "argv", argv), patch.object(cli, "run_stdio", fake_run_stdio):
            cli.main()

        backend = captured["backend"]
        self.assertEqual(backend.command, "python")
        self.assertEqual(backend.args, ["-m", "gdb_mcp.server", "--unsafe"])


if __name__ == "__main__":
    unittest.main()
