"""Validate registry metadata against the actual MCP discovery surface."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

from gdb_mcp.lazy import list_proxy_tools
from gdb_mcp.prompts import prompt_index
from gdb_mcp.resources import resource_index
from gdb_mcp.tool_profiles import ADVANCED_TOOL_GROUPS, CORE_TOOL_PROFILE

ROOT = Path(__file__).resolve().parents[1]


def _digest(names: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest()


async def validate(metadata: dict) -> list[str]:
    errors: list[str] = []
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
    return errors


def main() -> int:
    metadata = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    errors = asyncio.run(validate(metadata))
    if errors:
        for error in errors:
            print(f"error: {error}")
        return 1
    print("server.json matches tools, resources, prompts, and safety profiles")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
