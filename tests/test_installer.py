import json
import unittest
from pathlib import Path
from unittest.mock import patch

from gdb_mcp.installer import (
    MARKETPLACE_NAME,
    PACKAGE_SOURCE,
    RELEASE_TAG,
    client_info,
    configuration,
    parse_targets,
)


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

    def test_direct_commands_use_portable_uvx_source(self) -> None:
        with patch("gdb_mcp.installer.shutil.which", return_value="/bin/claude"):
            info = client_info("claude")
        self.assertTrue(PACKAGE_SOURCE.endswith(f"@{RELEASE_TAG}"))
        self.assertEqual(
            info.direct_mcp_install[-4:],
            ["uvx", "--from", PACKAGE_SOURCE, "gdb-mcp"],
        )

    def test_parse_explicit_targets(self) -> None:
        self.assertEqual(parse_targets("claude,codex,claude"), ["claude", "codex"])
        with self.assertRaises(ValueError):
            parse_targets("unknown")

    def test_configuration_is_json_serializable(self) -> None:
        payload = configuration()
        json.dumps(payload)
        self.assertEqual(
            payload["claude_code"]["mcpServers"]["gdb"]["command"],  # type: ignore[index]
            "uvx",
        )
        self.assertEqual(
            payload["claude_code"]["mcpServers"]["gdb"]["args"][-1],  # type: ignore[index]
            "gdb-mcp",
        )

    def test_marketplace_manifests_point_to_plugin(self) -> None:
        root = Path(__file__).resolve().parents[1]
        claude = json.loads(
            (root / ".claude-plugin" / "marketplace.json").read_text()
        )
        codex = json.loads(
            (root / ".agents" / "plugins" / "marketplace.json").read_text()
        )
        self.assertEqual(claude["name"], "beacox")
        self.assertEqual(claude["plugins"][0]["source"], ".")
        self.assertEqual(codex["name"], "beacox")
        self.assertEqual(
            codex["plugins"][0]["source"]["path"],
            "./plugins/gdb-mcp",
        )


if __name__ == "__main__":
    unittest.main()
