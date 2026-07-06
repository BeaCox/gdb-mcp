#!/usr/bin/env python3
"""Check that the lazy MCP proxy starts quickly without touching the backend."""

from __future__ import annotations

import argparse
import asyncio
import os
import shlex
import sys
import time
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

BACKEND_SENTINEL = "/definitely/missing/gdb-mcp-backend"


def _default_command() -> list[str]:
    return [sys.executable, "-m", "gdb_mcp.lazy"]


def _source_tree_env(root: Path) -> dict[str, str]:
    env = os.environ.copy()
    src = root / "src"
    pythonpath = str(src)
    if existing := env.get("PYTHONPATH"):
        pythonpath = os.pathsep.join([pythonpath, existing])
    env["PYTHONPATH"] = pythonpath
    return env


async def _measure(command: list[str], *, root: Path) -> tuple[float, float, int]:
    params = StdioServerParameters(
        command=command[0],
        args=command[1:],
        env=_source_tree_env(root),
        cwd=root,
    )
    started = time.perf_counter()
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            initialized = time.perf_counter()
            tools = await session.list_tools()
            listed = time.perf_counter()
    return initialized - started, listed - started, len(tools.tools)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--command",
        help=(
            "Command used to start gdb-mcp. Defaults to the current Python "
            "interpreter running gdb_mcp.lazy."
        ),
    )
    parser.add_argument(
        "--budget",
        type=float,
        default=2.0,
        help="Maximum allowed initialize plus tools/list time in seconds.",
    )
    parser.add_argument(
        "--initialize-budget",
        type=float,
        default=1.0,
        help="Maximum allowed initialize time in seconds.",
    )
    parser.add_argument(
        "--no-backend-sentinel",
        action="store_true",
        help="Do not append a missing backend command to prove tools/list stays lazy.",
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    command = shlex.split(args.command) if args.command else _default_command()
    if not command:
        print("error: command must not be empty", file=sys.stderr)
        return 2
    if not args.no_backend_sentinel:
        command.extend(["--backend-command", BACKEND_SENTINEL])

    try:
        initialize_time, total_time, tool_count = asyncio.run(
            _measure(command, root=args.root.resolve())
        )
    except Exception as exc:
        print(f"lazy startup check failed: {exc}", file=sys.stderr)
        return 1

    print(f"initialize: {initialize_time:.3f}s")
    print(f"initialize+tools/list: {total_time:.3f}s")
    print(f"tools: {tool_count}")
    if initialize_time > args.initialize_budget:
        print(
            f"error: initialize exceeded {args.initialize_budget:.3f}s budget",
            file=sys.stderr,
        )
        return 1
    if total_time > args.budget:
        print(f"error: tools/list exceeded {args.budget:.3f}s budget", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
