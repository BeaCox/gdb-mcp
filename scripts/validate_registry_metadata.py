"""Validate registry metadata against the actual MCP discovery surface."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

from gdb_mcp import DIST_NAME
from gdb_mcp.lazy import list_proxy_tools
from gdb_mcp.prompts import prompt_index
from gdb_mcp.resources import resource_index
from gdb_mcp.tool_profiles import ADVANCED_TOOL_GROUPS, CORE_TOOL_PROFILE

ROOT = Path(__file__).resolve().parents[1]


def _digest(names: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest()


def validate_official_registry(server_manifest: dict[str, Any], expected_version: str) -> list[str]:
    errors: list[str] = []
    if server_manifest.get("$schema") != (
        "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
    ):
        errors.append("server.json $schema must point to official MCP Registry schema")
    if server_manifest.get("name") != "io.github.beacox/gdb-mcp":
        errors.append("server.json name must be io.github.beacox/gdb-mcp")
    if server_manifest.get("version") != expected_version:
        errors.append("server.json version does not match gdb-mcp.meta.json")
    packages = server_manifest.get("packages") or []
    if not packages or not isinstance(packages, list):
        errors.append("server.json must define packages")
    else:
        pkg = packages[0]
        if pkg.get("registryType") != "pypi":
            errors.append("server.json packages[0].registryType must be pypi")
        if pkg.get("identifier") != DIST_NAME:
            errors.append(f"server.json packages[0].identifier must be {DIST_NAME}")
        if pkg.get("version") != expected_version:
            errors.append("server.json packages[0].version does not match server.json version")
        if pkg.get("transport", {}).get("type") != "stdio":
            errors.append("server.json packages[0].transport.type must be stdio")
    return errors


async def validate(
    metadata: dict[str, Any],
    server_manifest: dict[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    if metadata.get("distribution") != DIST_NAME:
        errors.append(f"gdb-mcp.meta.json distribution must be {DIST_NAME}")

    advertised = metadata["capabilities"]
    profile_metadata = advertised["toolProfiles"]

    if profile_metadata["default"] != "full":
        errors.append("toolProfiles.default must remain full for compatibility")
    if profile_metadata["coreTools"] != CORE_TOOL_PROFILE:
        errors.append("toolProfiles.coreTools does not match the core profile")

    profile_names = [
        "core",
        *(f"advanced:{name}" for name in ADVANCED_TOOL_GROUPS),
        "full",
    ]
    for profile_name in profile_names:
        tools = await list_proxy_tools(profile_name)
        names = [tool.name for tool in tools]
        snapshot = profile_metadata["snapshots"].get(profile_name)
        if snapshot is None:
            errors.append(f"missing registry snapshot for {profile_name}")
            continue
        if snapshot.get("toolCount") != len(names):
            errors.append(f"registry tool count mismatch for {profile_name}")
        if snapshot.get("sha256") != _digest(names):
            errors.append(f"registry tool digest mismatch for {profile_name}")

    expected_resources = [item["uri"] for item in resource_index()]
    if advertised["resources"] != expected_resources:
        errors.append("registry resources do not match MCP resources/list")
    expected_prompts = [item["name"] for item in prompt_index()]
    if advertised["prompts"] != expected_prompts:
        errors.append("registry prompts do not match MCP prompts/list")
    if metadata["security"]["unsafeTools"] != ADVANCED_TOOL_GROUPS["unsafe"]["tools"]:
        errors.append("registry unsafeTools do not match the unsafe profile")

    if server_manifest is not None:
        errors.extend(validate_official_registry(server_manifest, str(metadata.get("version"))))

    return errors


def main() -> int:
    metadata = json.loads((ROOT / "gdb-mcp.meta.json").read_text(encoding="utf-8"))
    server_manifest = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    errors = asyncio.run(validate(metadata, server_manifest))
    if errors:
        for error in errors:
            print(f"error: {error}")
        return 1
    print("server.json and gdb-mcp.meta.json match tools, resources, prompts, and safety profiles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
