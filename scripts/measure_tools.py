#!/usr/bin/env python3
"""Measure `tools/list` schema bytes and estimated tokens per discovery profile."""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

from gdb_mcp.contract import normalize_tool_contract
from gdb_mcp.lazy import list_proxy_tools
from gdb_mcp.response_budget import CONSERVATIVE_BYTES_PER_TOKEN, measure_response
from gdb_mcp.tool_profiles import ADVANCED_TOOL_GROUPS


async def collect_measurements(
    *,
    profiles: list[str] | None = None,
    per_tool_profile: str | None = None,
) -> dict[str, Any]:
    target_profiles = profiles or [
        "core",
        *(f"advanced:{group}" for group in sorted(ADVANCED_TOOL_GROUPS)),
        "full",
    ]
    rows: list[dict[str, Any]] = []
    for name in target_profiles:
        tools = await list_proxy_tools(name)
        payload = {
            "tools": [
                normalize_tool_contract(
                    tool.model_dump(mode="json", by_alias=True, exclude_none=True)
                )
                for tool in tools
            ]
        }
        measured = measure_response(payload)
        rows.append(
            {
                "profile": name,
                "tool_count": len(tools),
                "bytes": measured.bytes,
                "estimated_tokens": measured.estimated_tokens,
            }
        )

    per_tool: list[dict[str, Any]] = []
    if per_tool_profile is not None:
        tools = await list_proxy_tools(per_tool_profile)
        for tool in tools:
            normalized = normalize_tool_contract(
                tool.model_dump(mode="json", by_alias=True, exclude_none=True)
            )
            measured = measure_response(normalized)
            per_tool.append(
                {
                    "name": tool.name,
                    "bytes": measured.bytes,
                    "estimated_tokens": measured.estimated_tokens,
                }
            )
        per_tool.sort(key=lambda item: item["bytes"], reverse=True)

    return {
        "bytes_per_token": CONSERVATIVE_BYTES_PER_TOKEN,
        "profiles": rows,
        "per_tool": per_tool,
    }


def _format_table(report: dict[str, Any], *, top: int | None = None) -> str:
    lines = [
        f"Schema measurement (1 token per {report['bytes_per_token']} UTF-8 JSON bytes)",
        "",
        "Profile                     Tools    Bytes   Est. Tokens",
        "--------------------------------------------------------",
    ]
    for row in report["profiles"]:
        lines.append(
            f"{row['profile']:<27} {row['tool_count']:>5} "
            f"{row['bytes']:>8} {row['estimated_tokens']:>13}"
        )
    if report["per_tool"]:
        lines.extend(
            [
                "",
                "Tool                                Bytes   Est. Tokens",
                "-------------------------------------------------------",
            ]
        )
        items = report["per_tool"][:top] if top is not None else report["per_tool"]
        for item in items:
            lines.append(
                f"{item['name']:<35} {item['bytes']:>5} {item['estimated_tokens']:>13}"
            )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        action="append",
        default=None,
        help="Measure specific profile(s); may be repeated",
    )
    parser.add_argument(
        "--per-tool",
        action="store_true",
        help="Include per-tool byte and token breakdown",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=None,
        help="Limit per-tool table to top N heaviest tools",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON report")
    args = parser.parse_args()

    per_tool_profile = (args.profile[-1] if args.profile else "full") if args.per_tool else None
    report = asyncio.run(
        collect_measurements(
            profiles=args.profile,
            per_tool_profile=per_tool_profile,
        )
    )
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(_format_table(report, top=args.top))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
