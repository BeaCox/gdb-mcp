"""Runtime environment self-check for `gdb-mcp doctor`."""

from __future__ import annotations

import asyncio
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import DIST_NAME, __version__
from .compatibility import probe_gdb_features

_CAP_SYS_PTRACE_BIT = 19
_PTRACE_SCOPE_PATH = Path("/proc/sys/kernel/yama/ptrace_scope")
_PERF_PARANOID_PATH = Path("/proc/sys/kernel/perf_event_paranoid")
_PROC_STATUS_PATH = Path("/proc/self/status")
_PROC_CGROUP_PATH = Path("/proc/1/cgroup")
_CONTAINER_MARKER_PATHS = (Path("/.dockerenv"), Path("/run/.containerenv"))


def _executable_version(path: str | None) -> str | None:
    if path is None:
        return None
    try:
        result = subprocess.run(
            [path, "--version"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=2.0,
        )
    except Exception:
        return None
    return next((line.strip() for line in result.stdout.splitlines() if line.strip()), None)


def _read_int_sysctl(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _detect_container(
    *,
    marker_paths: tuple[Path, ...] = _CONTAINER_MARKER_PATHS,
    cgroup_path: Path = _PROC_CGROUP_PATH,
) -> bool:
    if any(marker.exists() for marker in marker_paths):
        return True
    try:
        cgroup_text = cgroup_path.read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        return False
    return any(
        token in cgroup_text
        for token in ("docker", "containerd", "kubepods", "podman", "lxc")
    )


def _has_cap_sys_ptrace(proc_status_path: Path = _PROC_STATUS_PATH) -> bool | None:
    try:
        status_text = proc_status_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in status_text.splitlines():
        if line.startswith("CapEff:"):
            hex_mask = line.split(":", 1)[1].strip()
            try:
                cap_eff = int(hex_mask, 16)
            except ValueError:
                return None
            return bool(cap_eff & (1 << _CAP_SYS_PTRACE_BIT))
    return None


def _detect_client_registrations(home_dir: Path) -> dict[str, dict[str, Any]]:
    checks: dict[str, tuple[Path, tuple[str, ...]]] = {
        "claude": (home_dir / ".claude.json", ("gdb-mcp", "beacox-gdb-mcp", '"gdb"')),
        "codex": (
            home_dir / ".codex" / "config.toml",
            ("gdb-mcp", "beacox-gdb-mcp", "mcp_servers.gdb"),
        ),
        "gemini": (home_dir / ".gemini" / "settings.json", ("gdb-mcp", "beacox-gdb-mcp", '"gdb"')),
    }
    clients: dict[str, dict[str, Any]] = {}
    for name, (config_path, markers) in checks.items():
        exe_path = shutil.which(name)
        registered = False
        if config_path.exists():
            try:
                content = config_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                content = ""
            registered = any(marker in content for marker in markers)
        clients[name] = {
            "cli_available": exe_path is not None,
            "cli_path": exe_path,
            "registered": registered,
            "config_path": str(config_path),
        }
    return clients


async def collect_doctor_report(
    *,
    ptrace_scope_path: Path = _PTRACE_SCOPE_PATH,
    perf_paranoid_path: Path = _PERF_PARANOID_PATH,
    proc_status_path: Path = _PROC_STATUS_PATH,
    cgroup_path: Path = _PROC_CGROUP_PATH,
    container_marker_paths: tuple[Path, ...] = _CONTAINER_MARKER_PATHS,
    home_dir: Path | None = None,
) -> dict[str, Any]:
    """Collect structured diagnostics for the local `gdb-mcp` environment."""

    resolved_home = home_dir or Path.home()
    checks: list[dict[str, Any]] = []

    is_linux = sys.platform.startswith("linux")
    runtime_check: dict[str, Any] = {
        "name": "runtime",
        "status": "ok" if is_linux else "warn",
        "detail": (
            f"{DIST_NAME} {__version__}, Python {platform.python_version()}, "
            f"{platform.platform()}"
        ),
    }
    if not is_linux:
        runtime_check["fix"] = (
            "Local attach, core-dump, and gdbserver workflows require Linux."
        )
    checks.append(runtime_check)

    gdb_path = shutil.which("gdb")
    gdbserver_path = shutil.which("gdbserver")
    rr_path = shutil.which("rr")
    gdb_version = _executable_version(gdb_path)
    gdbserver_version = _executable_version(gdbserver_path)
    rr_version = _executable_version(rr_path)
    gdb_features = await probe_gdb_features(gdb_path)

    if gdb_path is None:
        checks.append(
            {
                "name": "gdb",
                "status": "fail",
                "detail": "gdb executable not found on PATH",
                "fix": "sudo apt-get update && sudo apt-get install -y gdb",
            }
        )
    elif not gdb_features.get("mi2", {}).get("supported"):
        checks.append(
            {
                "name": "gdb",
                "status": "fail",
                "detail": f"{gdb_path} ({gdb_version or 'unknown version'}) lacks MI2 support",
                "features": gdb_features,
                "fix": "Install a GDB build with --interpreter=mi2 support.",
            }
        )
    elif not gdb_features.get("python", {}).get("supported"):
        checks.append(
            {
                "name": "gdb",
                "status": "warn",
                "detail": f"{gdb_path} ({gdb_version or 'unknown version'}) lacks Python support",
                "features": gdb_features,
                "fix": "Install a GDB build compiled with Python support if needed.",
            }
        )
    else:
        checks.append(
            {
                "name": "gdb",
                "status": "ok",
                "detail": f"{gdb_path} ({gdb_version or 'unknown version'})",
                "features": gdb_features,
            }
        )

    if gdbserver_path is not None:
        checks.append(
            {
                "name": "gdbserver",
                "status": "ok",
                "detail": f"{gdbserver_path} ({gdbserver_version or 'unknown version'})",
            }
        )
    else:
        checks.append(
            {
                "name": "gdbserver",
                "status": "info",
                "detail": "gdbserver not found on PATH (optional for remote/managed targets)",
                "fix": "sudo apt-get install -y gdbserver",
            }
        )

    if rr_path is not None:
        checks.append(
            {
                "name": "rr",
                "status": "ok",
                "detail": f"{rr_path} ({rr_version or 'unknown version'})",
            }
        )
    else:
        checks.append(
            {
                "name": "rr",
                "status": "info",
                "detail": "rr not found on PATH (optional for time-travel debugging)",
                "fix": "sudo apt-get install -y rr",
            }
        )

    ptrace_scope = _read_int_sysctl(ptrace_scope_path)
    if ptrace_scope is None:
        checks.append(
            {
                "name": "ptrace_scope",
                "status": "info",
                "detail": f"{ptrace_scope_path} not present or unreadable",
            }
        )
    elif ptrace_scope == 0:
        checks.append(
            {
                "name": "ptrace_scope",
                "status": "ok",
                "detail": f"kernel.yama.ptrace_scope = {ptrace_scope} (gdb_attach allowed)",
            }
        )
    else:
        checks.append(
            {
                "name": "ptrace_scope",
                "status": "warn",
                "detail": (
                    f"kernel.yama.ptrace_scope = {ptrace_scope} "
                    "(gdb_attach to non-child processes is restricted)"
                ),
                "fix": (
                    "sudo sysctl kernel.yama.ptrace_scope=0  "
                    "# or persist in /etc/sysctl.d/10-ptrace.conf"
                ),
            }
        )

    perf_paranoid = _read_int_sysctl(perf_paranoid_path)
    if perf_paranoid is None:
        checks.append(
            {
                "name": "perf_event_paranoid",
                "status": "info",
                "detail": f"{perf_paranoid_path} not present or unreadable",
            }
        )
    elif perf_paranoid <= 1:
        checks.append(
            {
                "name": "perf_event_paranoid",
                "status": "ok",
                "detail": f"kernel.perf_event_paranoid = {perf_paranoid} (rr recording allowed)",
            }
        )
    else:
        checks.append(
            {
                "name": "perf_event_paranoid",
                "status": "warn" if rr_path is not None else "info",
                "detail": (
                    f"kernel.perf_event_paranoid = {perf_paranoid} "
                    "(rr requires <= 1 for perf_event_open)"
                ),
                "fix": "sudo sysctl kernel.perf_event_paranoid=1",
            }
        )

    in_container = _detect_container(
        marker_paths=container_marker_paths,
        cgroup_path=cgroup_path,
    )
    cap_ptrace = _has_cap_sys_ptrace(proc_status_path)
    if in_container and cap_ptrace is False:
        checks.append(
            {
                "name": "container",
                "status": "warn",
                "detail": "Running in a container without CAP_SYS_PTRACE",
                "fix": (
                    "docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined ... "
                    "(add --pid=host to attach to host processes)"
                ),
            }
        )
    elif in_container:
        checks.append(
            {
                "name": "container",
                "status": "ok",
                "detail": "Running in a container with CAP_SYS_PTRACE available",
            }
        )
    else:
        checks.append(
            {
                "name": "container",
                "status": "ok",
                "detail": "Not running inside a container",
            }
        )

    clients = _detect_client_registrations(resolved_home)
    registered_clients = [name for name, info in clients.items() if info["registered"]]
    if registered_clients:
        checks.append(
            {
                "name": "clients",
                "status": "ok",
                "detail": f"Registered in: {', '.join(registered_clients)}",
                "clients": clients,
            }
        )
    else:
        checks.append(
            {
                "name": "clients",
                "status": "info",
                "detail": "No client MCP registration detected yet",
                "clients": clients,
                "fix": "claude mcp add --scope user gdb -- gdb-mcp  # or codex / gemini",
            }
        )

    summary = {
        status: sum(1 for item in checks if item["status"] == status)
        for status in ("ok", "warn", "info", "fail")
    }
    return {
        "ok": summary["fail"] == 0,
        "distribution": DIST_NAME,
        "version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "checks": checks,
        "summary": summary,
    }


def format_doctor_report(report: dict[str, Any]) -> str:
    """Format a doctor report as a human-readable multi-line checklist."""

    lines = [
        f"gdb-mcp doctor ({report['distribution']} {report['version']})",
        "",
    ]
    for check in report["checks"]:
        badge = check["status"].upper()
        lines.append(f"[{badge:<4}] {check['name']}: {check['detail']}")
        if fix := check.get("fix"):
            lines.append(f"       fix: {fix}")
    summary = report["summary"]
    lines.append("")
    lines.append(
        "Summary: "
        f"{summary['ok']} ok, {summary['warn']} warn, "
        f"{summary['info']} info, {summary['fail']} fail"
    )
    return "\n".join(lines)


def run_doctor(*, as_json: bool = False) -> int:
    """Execute doctor checks, print output, and return an exit code."""

    report = asyncio.run(collect_doctor_report())
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print(format_doctor_report(report))
    return 0 if report["ok"] else 1
