import io
import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from gdb_mcp import __version__, cli, lazy, server

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_version_flags_on_all_entry_points(self) -> None:
        for module_args in (
            ["-m", "gdb_mcp.cli", "--version"],
            ["-m", "gdb_mcp.server", "--version"],
            ["-m", "gdb_mcp.lazy", "--version"],
        ):
            with self.subTest(args=module_args):
                env = os.environ.copy()
                env["PYTHONPATH"] = str(ROOT / "src")
                result = subprocess.run(
                    [sys.executable, *module_args],
                    cwd=ROOT,
                    env=env,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertIn(__version__, result.stdout)

    def test_backend_flags_are_forwarded_to_spawned_backend(self) -> None:
        captured = {}

        async def fake_run_stdio(backend):
            captured["backend"] = backend

        argv = [
            "--unsafe",
            "--max-sessions",
            "12",
            "--output-limit-chars",
            "123456",
            "--backend-arg=--transport",
            "--backend-arg",
            "stdio",
            "--progress",
        ]
        with patch.object(cli, "run_stdio", fake_run_stdio):
            cli.main(argv)

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
                "--progress",
            ],
        )
        self.assertTrue(backend.enable_progress)
        self.assertEqual(backend.env["GDB_MCP_PROGRESS"], "1")

    def test_serve_subcommand_forwards_tools_and_excludes(self) -> None:
        captured = {}

        async def fake_run_stdio(backend):
            captured["backend"] = backend

        with patch.object(cli, "run_stdio", fake_run_stdio):
            cli.main(
                [
                    "serve",
                    "--tool-profile",
                    "core",
                    "--tools",
                    "gdb_symbols,gdb_got",
                    "--exclude-tools",
                    "gdb_source",
                ]
            )

        backend = captured["backend"]
        self.assertEqual(backend.tool_profile, "core")
        self.assertTrue(backend.tool_profile_explicit)
        self.assertEqual(backend.include_tools, ("gdb_symbols", "gdb_got"))
        self.assertEqual(backend.exclude_tools, ("gdb_source",))
        self.assertEqual(backend.env["GDB_MCP_TOOLS"], "gdb_symbols,gdb_got")
        self.assertEqual(backend.env["GDB_MCP_EXCLUDE_TOOLS"], "gdb_source")

    def test_serve_http_and_backend_subcommands_delegate_to_server(self) -> None:
        with patch.object(server, "main") as server_main:
            cli.main(["serve-http", "--port", "9001", "--unsafe", "--tools", "gdb_status"])
        server_main.assert_called_once_with(
            [
                "--transport",
                "streamable-http",
                "--host",
                "127.0.0.1",
                "--port",
                "9001",
                "--unsafe",
                "--tools",
                "gdb_status",
            ]
        )

        with patch.object(server, "main") as server_main:
            cli.main(["backend", "--transport", "stdio", "--unsafe"])
        server_main.assert_called_once_with(["--transport", "stdio", "--unsafe"])

    def test_config_clients_and_doctor_subcommands(self) -> None:
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            cli.main(["config", "cursor", "--installed"])
        payload = json.loads(stdout_buf.getvalue())
        self.assertEqual(
            payload,
            {"mcpServers": {"gdb": {"command": "gdb-mcp", "args": []}}},
        )

        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            cli.main(["config", "agy", "--installed"])
        self.assertEqual(json.loads(stdout_buf.getvalue()), payload)

        stdout_buf = io.StringIO()
        with patch("gdb_mcp.installer.shutil.which", return_value=None), redirect_stdout(
            stdout_buf
        ):
            cli.main(["clients"])
        self.assertIn("claude: not found", stdout_buf.getvalue())
        self.assertIn("codex: not found", stdout_buf.getvalue())

        with patch("gdb_mcp.doctor.run_doctor", return_value=0) as mock_doctor:
            with self.assertRaises(SystemExit) as exc:
                cli.main(["doctor", "--json"])
            self.assertEqual(exc.exception.code, 0)
            mock_doctor.assert_called_once_with(as_json=True)

    def test_legacy_flags_warn_and_reject_mixed_server_or_bare_modifiers(self) -> None:
        stderr_buf = io.StringIO()
        stdout_buf = io.StringIO()
        with redirect_stderr(stderr_buf), redirect_stdout(stdout_buf):
            cli.main(["--print-config", "vscode"])
        self.assertIn("deprecated", stderr_buf.getvalue())
        self.assertIn("servers", stdout_buf.getvalue())

        for bad_argv in (
            ["--install", "--unsafe"],
            ["--print-config", "--max-sessions", "2"],
            ["--direct"],
            ["--scope", "user"],
        ):
            with self.subTest(argv=bad_argv), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as exc:
                    cli.main(bad_argv)
                self.assertEqual(exc.exception.code, 2)

    def test_backend_flags_are_not_forwarded_to_http_backend(self) -> None:
        captured = {}

        async def fake_run_stdio(backend):
            captured["backend"] = backend

        argv = [
            "--backend-url",
            "http://127.0.0.1:8000/mcp",
            "--unsafe",
            "--max-sessions",
            "12",
            "--output-limit-chars",
            "123456",
        ]
        with patch.object(cli, "run_stdio", fake_run_stdio):
            cli.main(argv)

        backend = captured["backend"]
        self.assertEqual(backend.url, "http://127.0.0.1:8000/mcp")
        self.assertEqual(backend.args, ["-m", "gdb_mcp.server"])

    def test_backend_command_is_split_and_extended(self) -> None:
        captured = {}

        async def fake_run_stdio(backend):
            captured["backend"] = backend

        argv = [
            "--backend-command",
            "python -m gdb_mcp.server",
            "--backend-arg=--unsafe",
        ]
        with patch.object(cli, "run_stdio", fake_run_stdio):
            cli.main(argv)

        backend = captured["backend"]
        self.assertEqual(backend.command, "python")
        self.assertEqual(backend.args, ["-m", "gdb_mcp.server", "--unsafe"])

    def test_tool_profile_is_shared_with_lazy_proxy_and_backend(self) -> None:
        captured = {}

        async def fake_run_stdio(backend):
            captured["backend"] = backend

        argv = ["--tool-profile", "advanced:remote-target"]
        with patch.object(cli, "run_stdio", fake_run_stdio):
            cli.main(argv)

        backend = captured["backend"]
        self.assertEqual(backend.tool_profile, "advanced:remote_target")
        self.assertEqual(
            backend.env["GDB_MCP_TOOL_PROFILE"],
            "advanced:remote_target",
        )

    def test_invalid_env_var_exits_with_code_2(self) -> None:
        with (
            patch.dict(os.environ, {"GDB_MCP_MAX_SESSIONS": "abc"}),
            redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as exc:
                cli.main(["serve"])
            self.assertEqual(exc.exception.code, 2)

        with (
            patch.dict(os.environ, {"GDB_MCP_BACKEND_STARTUP_TIMEOUT": "0"}),
            redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit) as exc:
                with patch.object(sys, "argv", ["gdb-mcp"]):
                    lazy.main()
            self.assertEqual(exc.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
