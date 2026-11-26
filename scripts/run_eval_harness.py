#!/usr/bin/env python3
"""Run deterministic gdb-mcp scenario baselines and enforce response/leak budgets."""

from __future__ import annotations

import argparse
import asyncio
import json

from gdb_mcp.eval_harness import compare_profiles, run_all_scenarios


def _format_profile_comparison(data: dict) -> str:
    lines = [
        "Profile  Tools  Schema(B/tok)    Scenarios(B/tok)  Total(B/tok)",
        "-------------------------------------------------------------------",
    ]
    for row in data["profiles"]:
        schema = f"{row['schema_bytes']}/{row['schema_tokens']}"
        scen = f"{row['scenario_bytes']}/{row['scenario_tokens']}"
        total = f"{row['total_bytes']}/{row['total_estimated_tokens']}"
        lines.append(
            f"{row['profile']:<8} {row['tool_count']:>5}  "
            f"{schema:<16} {scen:<17} {total}"
        )
    if len(data["profiles"]) >= 2:
        full_row, core_row = data["profiles"][0], data["profiles"][1]
        if full_row["total_estimated_tokens"] > 0:
            saved_schema = 100.0 * (
                1 - core_row["schema_tokens"] / full_row["schema_tokens"]
            )
            saved_total = 100.0 * (
                1 - core_row["total_estimated_tokens"] / full_row["total_estimated_tokens"]
            )
            lines.append("")
            lines.append(
                f"Schema savings ({core_row['profile']} vs {full_row['profile']}): "
                f"{saved_schema:.1f}% | Total savings: {saved_total:.1f}%"
            )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print JSON evaluation report.")
    parser.add_argument(
        "--compare-profiles",
        action="store_true",
        help="Compare full vs core upfront schema + scenario token cost.",
    )
    args = parser.parse_args()

    if args.compare_profiles:
        comparison = asyncio.run(compare_profiles())
        if args.json:
            print(json.dumps(comparison, indent=2))
        else:
            print(_format_profile_comparison(comparison))
        return 0 if comparison["ok"] else 1

    report = asyncio.run(run_all_scenarios())
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.format_table())
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
