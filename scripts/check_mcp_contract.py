#!/usr/bin/env python3
"""Snapshot and diff the public gdb-mcp MCP compatibility contract."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from gdb_mcp.contract import build_contract_snapshot, diff_contract
from gdb_mcp.lazy import list_proxy_resources, list_proxy_tools
from gdb_mcp.prompts import prompt_index
from gdb_mcp.tool_profiles import ADVANCED_TOOL_GROUPS

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = ROOT / "tests" / "fixtures" / "mcp_contract.json"


async def collect_current_contract() -> dict[str, Any]:
    """Collect capabilities, per-profile tool schemas, resources, and prompts."""

    profile_names = [
        "core",
        *(f"advanced:{name}" for name in sorted(ADVANCED_TOOL_GROUPS)),
        "full",
    ]
    profiles: dict[str, list[dict[str, Any]]] = {}
    for name in profile_names:
        tools = await list_proxy_tools(name)
        profiles[name] = [
            tool.model_dump(mode="json", by_alias=True, exclude_none=True)
            for tool in tools
        ]
    capabilities = {
        "experimental": {},
        "prompts": {"listChanged": False},
        "resources": {"subscribe": False, "listChanged": False},
        "tools": {"listChanged": False},
    }
    return build_contract_snapshot(
        capabilities=capabilities,
        profiles=profiles,
        resources=list_proxy_resources(),
        prompts=prompt_index(),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline",
        type=Path,
        default=DEFAULT_BASELINE,
        help="Path to a baseline MCP contract JSON snapshot.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write the current contract snapshot to --baseline.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Compare the live contract against --baseline and fail on breaking diffs.",
    )
    parser.add_argument(
        "--diff",
        nargs=2,
        metavar=("BASELINE", "CURRENT"),
        type=Path,
        help="Diff two saved contract JSON snapshots without importing the MCP server.",
    )
    args = parser.parse_args()

    if args.diff is not None:
        baseline = json.loads(args.diff[0].read_text(encoding="utf-8"))
        current = json.loads(args.diff[1].read_text(encoding="utf-8"))
        diff = diff_contract(baseline, current)
        print(diff.format_report())
        return 0 if diff.ok else 1

    current = asyncio.run(collect_current_contract())
    if args.write:
        args.baseline.parent.mkdir(parents=True, exist_ok=True)
        args.baseline.write_text(
            json.dumps(current, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"Wrote MCP contract snapshot to {args.baseline}")
        return 0

    if args.check:
        if not args.baseline.exists():
            print(f"error: baseline snapshot not found: {args.baseline}", file=sys.stderr)
            return 2
        baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
        diff = diff_contract(baseline, current)
        print(diff.format_report())
        return 0 if diff.ok else 1

    print(json.dumps(current, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
