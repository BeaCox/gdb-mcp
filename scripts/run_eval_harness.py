#!/usr/bin/env python3
"""Run deterministic gdb-mcp scenario baselines and enforce response/leak budgets."""

from __future__ import annotations

import argparse
import asyncio
import json

from gdb_mcp.eval_harness import run_all_scenarios


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Print JSON evaluation report.")
    args = parser.parse_args()

    report = asyncio.run(run_all_scenarios())
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.format_table())
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
