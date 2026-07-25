"""Check representative tool responses against byte and token budgets."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

from gdb_mcp.response_budget import CONSERVATIVE_BYTES_PER_TOKEN, measure_response
from gdb_mcp.server import (
    _run_readelf,
    gdb_context,
    gdb_read_memory,
    gdb_symbols,
    gdb_thread_apply_all_backtrace,
    manager,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUDGETS = ROOT / "tests" / "fixtures" / "response_budgets.json"
FAKE_GDB = ROOT / "tests" / "fixtures" / "fake_gdb.py"


async def collect_payloads() -> dict[str, dict[str, Any]]:
    """Generate deterministic, near-limit responses through the real tool handlers."""

    FAKE_GDB.chmod(0o755)
    session = await manager.create(
        gdb_path=str(FAKE_GDB),
        env={"FAKE_GDB_LARGE_OUTPUT": "1"},
    )
    try:
        payloads = {
            "context": await gdb_context(
                session.session_id,
                max_frames=10,
                output="structured",
            ),
            "backtrace_all": await gdb_thread_apply_all_backtrace(
                session.session_id,
                max_frames=50,
                output="structured",
                page_size=200,
            ),
            "symbols": await gdb_symbols(
                session.session_id,
                query="main",
                limit=200,
                output="structured",
                page_size=200,
            ),
            "memory": await gdb_read_memory(
                session.session_id,
                "$sp",
                4_096,
                output="structured",
                page_size=4_096,
            ),
        }

        with tempfile.TemporaryDirectory() as tmp:
            fake_readelf = Path(tmp) / "readelf"
            fake_readelf.write_text(
                "#!/usr/bin/env python3\n"
                "for index in range(200):\n"
                "    print(f'{index:04x} section line with deterministic bounded output')\n",
                encoding="utf-8",
            )
            fake_readelf.chmod(0o755)
            with patch("gdb_mcp.tools.binary.shutil.which", return_value=str(fake_readelf)):
                payloads["readelf"] = await _run_readelf(
                    "/tmp/sample",
                    ["-S"],
                    timeout=2.0,
                    output="raw",
                    page_size=200,
                )
        return payloads
    finally:
        await manager.close(session.session_id)


def check_payloads(
    payloads: dict[str, dict[str, Any]],
    budgets: dict[str, dict[str, int]],
) -> tuple[list[dict[str, Any]], list[str]]:
    report: list[dict[str, Any]] = []
    failures: list[str] = []
    for name, limits in budgets.items():
        payload = payloads.get(name)
        if payload is None:
            failures.append(f"{name}: fixture response was not generated")
            continue
        if not payload.get("ok"):
            failures.append(f"{name}: tool response failed: {payload.get('error')}")
            continue
        measured = measure_response(payload)
        row = {
            "name": name,
            "bytes": measured.bytes,
            "estimated_tokens": measured.estimated_tokens,
            "max_bytes": limits["max_bytes"],
            "max_estimated_tokens": limits["max_estimated_tokens"],
        }
        report.append(row)
        if measured.bytes > limits["max_bytes"]:
            failures.append(
                f"{name}: {measured.bytes} bytes exceeds {limits['max_bytes']}"
            )
        if measured.estimated_tokens > limits["max_estimated_tokens"]:
            failures.append(
                f"{name}: estimated {measured.estimated_tokens} tokens exceeds "
                f"{limits['max_estimated_tokens']}"
            )
    report.sort(key=lambda item: item["bytes"], reverse=True)
    return report, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--budgets", type=Path, default=DEFAULT_BUDGETS)
    parser.add_argument("--json", action="store_true", help="Print the report as JSON")
    args = parser.parse_args()

    config = json.loads(args.budgets.read_text(encoding="utf-8"))
    payloads = asyncio.run(collect_payloads())
    report, failures = check_payloads(payloads, config["cases"])

    if args.json:
        print(json.dumps({"responses": report, "failures": failures}, indent=2))
    else:
        print(
            "response budget estimate: "
            f"1 token per {CONSERVATIVE_BYTES_PER_TOKEN} serialized UTF-8 bytes"
        )
        for row in report:
            print(
                f"{row['name']}: {row['bytes']} bytes, "
                f"~{row['estimated_tokens']} tokens "
                f"(limits {row['max_bytes']} / {row['max_estimated_tokens']})"
            )
        for failure in failures:
            print(f"error: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
