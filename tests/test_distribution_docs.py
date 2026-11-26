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
    def test_official_server_json_follows_mcp_registry_schema(self) -> None:
        version = project_version()
        manifest = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))

        self.assertEqual(
            manifest["$schema"],
            "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
        )
        self.assertEqual(manifest["name"], "io.github.beacox/gdb-mcp")
        self.assertEqual(manifest["version"], version)
        pkg = manifest["packages"][0]
        self.assertEqual(pkg["registryType"], "pypi")
        self.assertEqual(pkg["identifier"], "beacox-gdb-mcp")
        self.assertEqual(pkg["version"], version)
        self.assertEqual(pkg["transport"]["type"], "stdio")

    def test_meta_manifest_is_machine_readable(self) -> None:
        version = project_version()
        metadata = json.loads((ROOT / "gdb-mcp.meta.json").read_text(encoding="utf-8"))

        self.assertEqual(metadata["name"], "gdb-mcp")
        self.assertEqual(metadata["distribution"], "beacox-gdb-mcp")
        self.assertEqual(metadata["version"], version)
        self.assertEqual(metadata["transport"]["type"], "stdio")
        self.assertEqual(metadata["mcpServers"]["gdb"]["command"], "uvx")
        self.assertEqual(
            metadata["mcpServers"]["gdb"]["args"],
            ["--from", f"beacox-gdb-mcp=={version}", "gdb-mcp"],
        )
        self.assertEqual(
            metadata["install"]["uvTool"]["args"],
            ["tool", "install", "beacox-gdb-mcp"],
        )
        self.assertEqual(
            metadata["install"]["pipx"]["args"],
            ["install", "beacox-gdb-mcp"],
        )
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

    def test_readme_uses_beacox_gdb_mcp_and_documents_verification(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")

        self.assertIn("<!-- mcp-name: io.github.beacox/gdb-mcp -->", readme)
        self.assertIn("uv tool install beacox-gdb-mcp", readme)
        self.assertIn("gdb-mcp --version", readme)
        self.assertIn("gdb-mcp doctor", readme)
        self.assertIn("kernel.yama.ptrace_scope=0", readme)
        self.assertIn("kernel.perf_event_paranoid=1", readme)
        self.assertIn("docs/INSTALL.md", readme)
        self.assertIn("docs/TOOLS.md", readme)
        self.assertIn("docs/TRANSPORTS.md", readme)
        self.assertNotIn("uvx gdb-mcp", readme)
        self.assertNotIn("pipx install gdb-mcp", readme)
        self.assertLessEqual(len(readme.splitlines()), 230)

    def test_docs_structure_and_packaging_files_exist(self) -> None:
        version = project_version()
        install_doc = (ROOT / "docs" / "INSTALL.md").read_text(encoding="utf-8")
        transports_doc = (ROOT / "docs" / "TRANSPORTS.md").read_text(encoding="utf-8")
        testing_doc = (ROOT / "docs" / "TESTING.md").read_text(encoding="utf-8")
        index_doc = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")

        self.assertIn("uv tool install beacox-gdb-mcp", install_doc)
        self.assertIn("pipx install beacox-gdb-mcp", install_doc)
        self.assertIn(
            f"uvx --from git+https://github.com/BeaCox/gdb-mcp.git@v{version} gdb-mcp",
            install_doc,
        )
        self.assertIn("--cap-add=SYS_PTRACE", install_doc)
        self.assertIn("nix run github:BeaCox/gdb-mcp", install_doc)
        self.assertIn("Shutdown Semantics", transports_doc)
        self.assertIn("GDB_MCP_PROGRESS", transports_doc)
        self.assertIn("make check", testing_doc)
        self.assertIn("TOOLS.md", index_doc)
        self.assertTrue((ROOT / "Dockerfile").exists())
        self.assertTrue((ROOT / "flake.nix").exists())
        self.assertFalse((ROOT / "TOOLS.md").exists())

    def test_workflows_pin_actions_by_sha_and_unify_release(self) -> None:
        ci_text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        release_text = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        self.assertFalse((ROOT / ".github" / "workflows" / "publish.yml").exists())
        self.assertIn("make check", ci_text)
        for text in (ci_text, release_text):
            uses_refs = re.findall(r"uses:\s*([^\s]+)", text)
            self.assertTrue(uses_refs)
            for ref in uses_refs:
                self.assertRegex(ref, r"@[0-9a-f]{40}$", ref)
        self.assertIn("checksums.txt", release_text)
        self.assertIn("attest-build-provenance", release_text)
        self.assertIn("gh-action-pypi-publish", release_text)

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
        self.assertIn("## Now — 0.6.0 deployment hardening and contract automation", active)
        self.assertIn("## Next — 0.7.0 parser corpus and workflow depth", active)
        self.assertIn("## Later — ecosystem options", active)
        self.assertIn("## Non-goals for the current roadmap", active)
        self.assertGreaterEqual(active.count("- [ ]"), 8)
        self.assertNotIn("- [x]", todo)
        self.assertNotIn("- [ ]", completed)
        self.assertIn("July 2026 baseline", completed)
        self.assertIn("July 2026 protocol and reliability follow-up", completed)


if __name__ == "__main__":
    unittest.main()
