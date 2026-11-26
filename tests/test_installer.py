import json
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from gdb_mcp.installer import (
    MARKETPLACE_NAME,
    PACKAGE_SOURCE,
    PYPI_PACKAGE_NAME,
    RELEASE_TAG,
    CommandFailed,
    _run,
    client_info,
    configuration,
    install,
    parse_targets,
)

ROOT = Path(__file__).resolve().parents[1]


def project_version() -> str:
    match = re.search(
        r'(?m)^version\s*=\s*"(?P<version>[^"]+)"\s*$',
        (ROOT / "pyproject.toml").read_text(encoding="utf-8"),
    )
    if match is None:
        raise AssertionError("pyproject.toml is missing project.version")
    return match.group("version")


class InstallerTests(unittest.TestCase):
    def test_claude_plugin_commands(self) -> None:
        with patch("gdb_mcp.installer.shutil.which", return_value="/bin/claude"):
            info = client_info("claude")
        self.assertEqual(
            info.plugin_install[0],
            ["/bin/claude", "plugin", "marketplace", "add", "BeaCox/gdb-mcp"],
        )
        self.assertIn(f"gdb-mcp@{MARKETPLACE_NAME}", info.plugin_install[1])

    def test_codex_plugin_commands(self) -> None:
        with patch("gdb_mcp.installer.shutil.which", return_value="/bin/codex"):
            info = client_info("codex")
        self.assertEqual(info.plugin_install[0][-2:], ["--ref", RELEASE_TAG])
        self.assertEqual(
            info.plugin_install[1],
            ["/bin/codex", "plugin", "add", "gdb-mcp@beacox"],
        )

    def test_direct_commands_use_beacox_gdb_mcp_source(self) -> None:
        self.assertEqual(PYPI_PACKAGE_NAME, "beacox-gdb-mcp")
        self.assertEqual(PACKAGE_SOURCE, "beacox-gdb-mcp")
        with patch("gdb_mcp.installer.shutil.which", return_value="/bin/claude"):
            info = client_info("claude")
        self.assertEqual(
            info.direct_mcp_install[-4:],
            ["uvx", "--from", "beacox-gdb-mcp", "gdb-mcp"],
        )

    def test_installed_flag_uses_direct_gdb_mcp_binary(self) -> None:
        with patch("gdb_mcp.installer.shutil.which", return_value="/bin/codex"):
            info = client_info("codex", installed=True)
        self.assertEqual(info.direct_mcp_install[-1:], ["gdb-mcp"])
        payload = configuration(installed=True)
        self.assertEqual(
            payload["codex"]["mcp_servers"]["gdb"],
            {"command": "gdb-mcp", "args": []},
        )

    def test_conflicting_gdb_mcp_pypi_source_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "belongs to another project"):
            configuration("gdb-mcp")

    def test_multi_client_configuration_supports_all_clients(self) -> None:
        payload = configuration()
        self.assertEqual(
            set(payload),
            {"claude_code", "codex", "antigravity", "cursor", "vscode", "windsurf"},
        )
        self.assertEqual(
            configuration(client="agy"),
            configuration(client="antigravity"),
        )
        self.assertEqual(
            configuration(client="cursor")["mcpServers"]["gdb"],
            {"command": "uvx", "args": ["--from", "beacox-gdb-mcp", "gdb-mcp"]},
        )
        self.assertEqual(
            configuration(client="vscode")["servers"]["gdb"],
            {
                "type": "stdio",
                "command": "uvx",
                "args": ["--from", "beacox-gdb-mcp", "gdb-mcp"],
            },
        )
        self.assertEqual(
            configuration(client="claude")["mcpServers"]["gdb"]["command"],
            "uvx",
        )
        with self.assertRaises(ValueError):
            configuration(client="unknown")

    def test_codex_install_refreshes_stale_marketplace_ref(self) -> None:
        conflict = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr=(
                "Error: marketplace 'beacox' is already added from a different "
                "source; remove it before adding this source"
            ),
        )
        success = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with (
            patch("gdb_mcp.installer.shutil.which", return_value="/bin/codex"),
            patch("gdb_mcp.installer.subprocess.run") as run,
        ):
            run.side_effect = [conflict, success, success, success]
            install(["codex"])

        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(
            commands,
            [
                [
                    "/bin/codex",
                    "plugin",
                    "marketplace",
                    "add",
                    "BeaCox/gdb-mcp",
                    "--ref",
                    RELEASE_TAG,
                ],
                ["/bin/codex", "plugin", "marketplace", "remove", "beacox"],
                [
                    "/bin/codex",
                    "plugin",
                    "marketplace",
                    "add",
                    "BeaCox/gdb-mcp",
                    "--ref",
                    RELEASE_TAG,
                ],
                ["/bin/codex", "plugin", "add", "gdb-mcp@beacox"],
            ],
        )

    def test_release_version_references_match_project_version(self) -> None:
        version = project_version()
        tag = f"v{version}"
        self.assertEqual(RELEASE_TAG, tag)

        for relative in ("docs/INSTALL.md", "examples/README.md"):
            text = (ROOT / relative).read_text(encoding="utf-8")
            tags = set(re.findall(r"(?:@|--ref\s+)(v[0-9]+\.[0-9]+\.[0-9]+)", text))
            self.assertEqual(tags, {tag}, relative)

        claude_plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
        codex_mcp = json.loads((ROOT / "plugins" / "gdb-mcp" / ".mcp.json").read_text())
        self.assertEqual(
            claude_plugin["mcpServers"]["gdb"]["args"],
            ["--from", f"beacox-gdb-mcp=={version}", "gdb-mcp"],
        )
        self.assertEqual(
            codex_mcp["mcpServers"]["gdb"]["args"],
            ["--from", f"beacox-gdb-mcp=={version}", "gdb-mcp"],
        )

        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        latest = re.search(r"(?m)^## \[(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\]", changelog)
        self.assertIsNotNone(latest)
        self.assertEqual(latest.group("version"), version)

    def test_release_version_sync_script_is_clean(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/sync_release_version.py", "--check"],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_parse_explicit_targets(self) -> None:
        self.assertEqual(
            parse_targets("claude,codex,claude"),
            ["claude", "codex"],
        )
        with self.assertRaises(ValueError):
            parse_targets("unknown")

    def test_parse_auto_targets_reports_missing_clients(self) -> None:
        with patch("gdb_mcp.installer.detect_clients", return_value=[]):
            with self.assertRaisesRegex(RuntimeError, "No supported clients"):
                parse_targets("auto")

    def test_run_allows_existing_config_but_not_ref_conflict(self) -> None:
        already_configured = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="server already configured",
        )
        ref_conflict = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="marketplace already added from a different source",
        )
        with patch("gdb_mcp.installer.subprocess.run", return_value=already_configured):
            _run(["client", "add"], dry_run=False, allow_existing=True)
        with patch("gdb_mcp.installer.subprocess.run", return_value=ref_conflict):
            with self.assertRaises(CommandFailed):
                _run(["client", "add"], dry_run=False, allow_existing=True)

    def test_replace_release_tags_updates_claude_marketplace_at_ref(self) -> None:
        import importlib.util

        script = ROOT / "scripts" / "sync_release_version.py"
        spec = importlib.util.spec_from_file_location("sync_release_version", script)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        sample = (
            "claude plugin marketplace add BeaCox/gdb-mcp@v0.4.0\n"
            "codex plugin marketplace add BeaCox/gdb-mcp --ref v0.4.0\n"
            "uvx --from git+https://github.com/BeaCox/gdb-mcp.git@v0.4.0 gdb-mcp\n"
            "uvx --from beacox-gdb-mcp==0.4.0 gdb-mcp\n"
        )
        updated = module.replace_release_tags(sample, "0.5.0")
        self.assertNotIn("0.4.0", updated)
        self.assertEqual(updated.count("v0.5.0"), 3)
        self.assertIn("beacox-gdb-mcp==0.5.0", updated)


if __name__ == "__main__":
    unittest.main()
