#!/usr/bin/env python3
"""Small rr stub used by contract tests."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from fake_gdb import main as fake_gdb_main


def _trace_dir(args: list[str]) -> str | None:
    for index, arg in enumerate(args):
        if arg.startswith("--output-trace-dir="):
            return arg.split("=", 1)[1]
        if arg == "--output-trace-dir" and index + 1 < len(args):
            return args[index + 1]
    return None


def main() -> None:
    args = sys.argv[1:]
    if log_path := os.environ.get("FAKE_RR_LOG"):
        Path(log_path).write_text("\n".join(args), encoding="utf-8")
    if args[:1] == ["record"]:
        if delay := os.environ.get("FAKE_RR_DELAY"):
            time.sleep(float(delay))
        if os.environ.get("FAKE_RR_FAIL_PERF"):
            print("Permission denied to use 'perf_event_open'")
            print("rr needs /proc/sys/kernel/perf_event_paranoid <= 1, but it is 4.")
            raise SystemExit(1)
        trace_dir = _trace_dir(args)
        if trace_dir is None:
            raise SystemExit("missing --output-trace-dir")
        path = Path(trace_dir)
        path.mkdir(parents=True, exist_ok=True)
        (path / "version").write_text("fake rr trace\n", encoding="utf-8")
        print(f"rr: Saving execution to trace directory `{trace_dir}'.")
        print("fake target output")
        return

    if args[:1] == ["replay"]:
        fake_gdb_main()
        return

    raise SystemExit("fake rr only supports record and replay")


if __name__ == "__main__":
    main()
