"""Runtime probes for GDB features that cannot be inferred from a version."""

from __future__ import annotations

import asyncio
from typing import Any

FEATURE_PROBES: dict[str, tuple[str, ...]] = {
    "mi2": ("--interpreter=mi2", "-ex", "show version"),
    "python": ("-ex", "python print('gdb-mcp-python-ok')"),
    "record_full": ("-ex", "help record full"),
    "reverse_execution": ("-ex", "help reverse-continue"),
    "gcore": ("-ex", "help gcore"),
    "target_extended_remote": ("-ex", "help target extended-remote"),
    "debuginfod": ("-ex", "show debuginfod enabled"),
}


async def _run_probe(gdb_path: str, args: tuple[str, ...]) -> tuple[int, str]:
    process = await asyncio.create_subprocess_exec(
        gdb_path,
        "-q",
        "-nx",
        "-batch",
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=5.0)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return 124, "probe timed out after 5 seconds"
    return process.returncode or 0, stdout.decode(errors="replace").strip()


async def probe_gdb_features(gdb_path: str | None) -> dict[str, dict[str, Any]]:
    """Probe supported GDB commands and return actionable feature gates."""

    if gdb_path is None:
        return {
            name: {
                "supported": False,
                "reason": "GDB executable is not available on PATH",
            }
            for name in FEATURE_PROBES
        }

    results = await asyncio.gather(
        *(_run_probe(gdb_path, args) for args in FEATURE_PROBES.values())
    )
    features: dict[str, dict[str, Any]] = {}
    for (name, _), (returncode, output) in zip(
        FEATURE_PROBES.items(), results, strict=True
    ):
        supported = returncode == 0
        first_line = next((line.strip() for line in output.splitlines() if line.strip()), "")
        features[name] = {
            "supported": supported,
            "reason": (
                None
                if supported
                else first_line or f"GDB probe exited with status {returncode}"
            ),
        }
    return features
