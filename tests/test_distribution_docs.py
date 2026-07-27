import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def project_version() -> str:
    match = re.search(
        r'(?m)^version\s*=\s*"(?P<version>[^"]+)"\s*$',
        (ROOT / "pyproject.toml").read_text(encoding="utf-8"),
    )
    if match is None:
        raise AssertionError("pyproject.toml is missing project.version")
    return match.group("version")


class DistributionDocsTests(unittest.TestCase):
    def test_server_registry_metadata_is_machine_readable(self) -> None:
        version = project_version()
        metadata = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))

        self.assertEqual(metadata["name"], "gdb-mcp")
        self.assertEqual(metadata["version"], version)
        self.assertEqual(metadata["transport"]["type"], "stdio")
        self.assertEqual(metadata["mcpServers"]["gdb"]["command"], "uvx")
        self.assertEqual(metadata["mcpServers"]["gdb"]["args"], ["gdb-mcp"])
        self.assertEqual(metadata["install"]["pypi"]["args"], ["gdb-mcp"])
        self.assertEqual(metadata["install"]["pipx"]["args"], ["install", "gdb-mcp"])
        self.assertIn(
            f"git+https://github.com/BeaCox/gdb-mcp.git@v{version}",
            metadata["install"]["taggedGit"]["args"],
        )
        self.assertIn("gdb://tools/decision-guide", metadata["capabilities"]["resources"])
        self.assertEqual(metadata["capabilities"]["toolProfiles"]["default"], "full")
        self.assertEqual(
            metadata["capabilities"]["toolProfiles"]["snapshots"]["core"]["toolCount"],
            29,
        )
        self.assertEqual(len(metadata["capabilities"]["prompts"]), 4)

    def test_readme_documents_pypi_and_tagged_git_installs(self) -> None:
        version = project_version()
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("uvx gdb-mcp", readme)
        self.assertIn("pipx install gdb-mcp", readme)
        self.assertIn(
            f"uvx --from git+https://github.com/BeaCox/gdb-mcp.git@v{version} gdb-mcp",
            readme,
        )
        self.assertIn("[server.json](server.json)", readme)

    def test_cookbook_workflows_document_security_tradeoffs(self) -> None:
        workflows = (ROOT / "docs" / "WORKFLOWS.md").read_text(encoding="utf-8")
        required_sections = (
            "Local Source Debugging",
            "Stripped Binary Analysis",
            "Core Dump Triage",
            "Remote Gdbserver",
            "Managed Gdbserver",
            "Attach And Detach",
            "Reverse Debugging",
            "Unsafe Mode",
        )
        for section in required_sections:
            with self.subTest(section=section):
                self.assertIn(f"## {section}", workflows)
        self.assertGreaterEqual(workflows.count("Security tradeoff:"), len(required_sections))
        self.assertIn("[SECURITY.md](../SECURITY.md)", workflows)

    def test_security_policy_links_workflow_risks_to_isolation(self) -> None:
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")

        for phrase in (
            "Workflow Tradeoffs",
            "container",
            "VM",
            "dedicated user",
            "Unsafe mode",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, security)
        self.assertIn("[docs/WORKFLOWS.md](docs/WORKFLOWS.md)", security)

    def test_compatibility_matrix_and_packaging_decisions_are_documented(self) -> None:
        compatibility = (ROOT / "docs" / "COMPATIBILITY.md").read_text(encoding="utf-8")

        for phrase in (
            "Python | 3.10, 3.11, 3.12, 3.13",
            "GDB",
            "gdbserver",
            "rr",
            "Nix",
            "Homebrew packaging is not maintained yet",
        ):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, compatibility)

    def test_todo_is_an_actionable_forward_looking_roadmap(self) -> None:
        todo = (ROOT / "TODO.md").read_text(encoding="utf-8")
        active, completed = todo.split("## Completed milestones", maxsplit=1)

        self.assertIn(f"Current released version: `{project_version()}`", todo)
        self.assertIn("## Now — 0.5.0 release and contract stability", active)
        self.assertIn("## Next — 0.6.0 agent effectiveness and maintainability", active)
        self.assertIn("## Later — ecosystem options", active)
        self.assertIn("## Non-goals for the current roadmap", active)
        self.assertGreaterEqual(active.count("- [ ]"), 8)
        self.assertNotIn("- [x]", todo)
        self.assertNotIn("- [ ]", completed)
        self.assertIn("July 2026 baseline", completed)
        self.assertIn("July 2026 protocol and reliability follow-up", completed)


if __name__ == "__main__":
    unittest.main()
