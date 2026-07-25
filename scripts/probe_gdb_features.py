"""Write a CI-friendly GDB build and feature report."""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from gdb_mcp.compatibility import probe_gdb_features


def _version(command: str | None) -> str | None:
    if command is None:
        return None
    result = subprocess.run(
        [command, "--version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return next((line.strip() for line in result.stdout.splitlines() if line.strip()), None)


def _gdb_configuration(gdb_path: str | None) -> list[str]:
    if gdb_path is None:
        return []
    result = subprocess.run(
        [gdb_path, "-q", "-nx", "-batch", "-ex", "show configuration"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return [line.rstrip() for line in result.stdout.splitlines() if line.strip()]


async def build_report() -> dict[str, Any]:
    gdb_path = shutil.which("gdb")
    dependencies = {}
    for name in ("gdb", "gdbserver", "rr", "cc", "c++", "readelf"):
        path = shutil.which(name)
        dependencies[name] = {
            "available": path is not None,
            "path": path,
            "version": _version(path),
        }
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "dependencies": dependencies,
        "gdb_configuration": _gdb_configuration(gdb_path),
        "gdb_features": await probe_gdb_features(gdb_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    encoded = json.dumps(asyncio.run(build_report()), indent=2) + "\n"
    if args.output is None:
        print(encoded, end="")
    else:
        args.output.write_text(encoded, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
