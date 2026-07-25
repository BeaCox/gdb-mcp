"""Install a built wheel in isolation and validate its lazy MCP entry point."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from gdb_mcp import __version__

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_WHEEL_ASSETS = {
    "gdb_mcp/__init__.py",
    "gdb_mcp/cli.py",
    "gdb_mcp/lazy.py",
    "gdb_mcp/server.py",
    "gdb_mcp/py.typed",
}


def _run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    print(result.stdout, end="")
    if result.returncode != 0:
        raise RuntimeError(f"command failed with {result.returncode}: {command}")


def _validate_wheel_assets(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    missing = sorted(REQUIRED_WHEEL_ASSETS - names)
    if missing:
        raise RuntimeError(f"wheel is missing package assets: {', '.join(missing)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheels", type=Path, nargs="+")
    args = parser.parse_args()
    matches = [
        wheel
        for wheel in args.wheels
        if wheel.name.startswith(f"gdb_mcp-{__version__}-")
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one wheel for version {__version__}, found: "
            + ", ".join(str(wheel) for wheel in matches)
        )
    wheel = matches[0].resolve()
    _validate_wheel_assets(wheel)

    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is required for the clean-install check")

    with tempfile.TemporaryDirectory() as tmp:
        environment = Path(tmp) / "venv"
        _run([uv, "venv", "--python", sys.executable, str(environment)])
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        executable = environment / ("Scripts/gdb-mcp.exe" if os.name == "nt" else "bin/gdb-mcp")
        _run([uv, "pip", "install", "--python", str(python), str(wheel)])

        clean_env = os.environ.copy()
        clean_env.pop("PYTHONPATH", None)
        _run(
            [
                str(python),
                "-c",
                "import gdb_mcp, mcp; print(gdb_mcp.__version__)",
            ],
            env=clean_env,
        )
        _run(
            [
                sys.executable,
                str(ROOT / "scripts" / "check_lazy_startup.py"),
                "--command",
                str(executable),
                "--isolated",
                "--budget",
                "5",
                "--initialize-budget",
                "3",
            ],
            env=clean_env,
        )
    print(f"clean wheel installation passed: {wheel.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
