"""Deterministic scenario-based evaluation harness for agent debugging workflows."""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .analysis import parse_mappings
from .mi import c_escape
from .response_budget import measure_response
from .responses import error_response, session_response
from .session import SessionManager

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FAKE_GDB = ROOT / "tests" / "fixtures" / "fake_gdb.py"


@dataclass(frozen=True)
class ScenarioSpec:
    name: str
    description: str
    max_bytes: int
    max_estimated_tokens: int


@dataclass
class ScenarioResult:
    name: str
    completed: bool
    tool_calls: int
    serialized_bytes: int
    estimated_tokens: int
    elapsed_seconds: float
    leaked_sessions: int
    within_budget: bool
    failures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "completed": self.completed,
            "tool_calls": self.tool_calls,
            "serialized_bytes": self.serialized_bytes,
            "estimated_tokens": self.estimated_tokens,
            "elapsed_seconds": round(self.elapsed_seconds, 6),
            "leaked_sessions": self.leaked_sessions,
            "within_budget": self.within_budget,
            "failures": list(self.failures),
        }


@dataclass(frozen=True)
class EvalReport:
    scenarios: list[ScenarioResult]

    @property
    def ok(self) -> bool:
        return all(
            item.completed
            and item.within_budget
            and item.leaked_sessions == 0
            and not item.failures
            for item in self.scenarios
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "scenario_count": len(self.scenarios),
            "scenarios": [item.to_dict() for item in self.scenarios],
        }

    def format_table(self) -> str:
        lines = [
            "Scenario                     OK    Calls   Bytes   Tokens   Leaks   Time(s)",
            "---------------------------------------------------------------------------",
        ]
        for item in self.scenarios:
            ok_flag = item.completed and item.within_budget and not item.failures
            status = "PASS" if ok_flag else "FAIL"
            lines.append(
                f"{item.name:<28} {status:<5} {item.tool_calls:>5} "
                f"{item.serialized_bytes:>7} {item.estimated_tokens:>8} "
                f"{item.leaked_sessions:>7} {item.elapsed_seconds:>8.3f}"
            )
            for failure in item.failures:
                lines.append(f"  error: {failure}")
        return "\n".join(lines)


SCENARIOS: tuple[ScenarioSpec, ...] = (
    ScenarioSpec(
        name="local_source_triage",
        description="Create session, set breakpoint, run/interrupt, inspect frame/locals, close.",
        max_bytes=16_000,
        max_estimated_tokens=5_400,
    ),
    ScenarioSpec(
        name="stripped_binary_analysis",
        description="Inspect mappings, near-PC disassembly, and memory slots on stripped target.",
        max_bytes=16_000,
        max_estimated_tokens=5_400,
    ),
    ScenarioSpec(
        name="core_dump_triage",
        description="Load a core dump and collect bounded thread/stack context.",
        max_bytes=12_000,
        max_estimated_tokens=4_000,
    ),
    ScenarioSpec(
        name="remote_debug_info_setup",
        description="Configure remote sysroot, solib-search-path, substitute-path, and debug dirs.",
        max_bytes=10_000,
        max_estimated_tokens=3_400,
    ),
    ScenarioSpec(
        name="unavailable_dependency",
        description="Verify missing GDB executable returns dependency_not_found with zero leaks.",
        max_bytes=2_000,
        max_estimated_tokens=700,
    ),
)


class _CallRecorder:
    def __init__(self, output_limit_chars: int) -> None:
        self.output_limit_chars = output_limit_chars
        self.calls: list[dict[str, Any]] = []

    def record(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(payload)
        return payload

    async def execute(
        self,
        session: Any,
        command: str,
        *,
        timeout: float = 5.0,
        wait_for_stop: bool = False,
    ) -> dict[str, Any]:
        result = await session.execute(
            command,
            timeout=timeout,
            wait_for_stop=wait_for_stop,
        )
        return self.record(result.to_dict(self.output_limit_chars))

    def totals(self) -> tuple[int, int, int]:
        total_bytes = 0
        total_tokens = 0
        for payload in self.calls:
            measured = measure_response(payload)
            total_bytes += measured.bytes
            total_tokens += measured.estimated_tokens
        return len(self.calls), total_bytes, total_tokens


async def _scenario_local_source_triage(
    manager: SessionManager,
    fake_gdb: Path,
    rec: _CallRecorder,
) -> list[str]:
    failures: list[str] = []
    session = await manager.create(
        gdb_path=str(fake_gdb),
        env={"FAKE_GDB_LARGE_OUTPUT": "1"},
    )
    rec.record(session_response(session))
    try:
        brk = await rec.execute(session, "break main")
        run = await rec.execute(session, "-exec-run")
        interrupt_res = await session.interrupt(timeout=2.0)
        intr = rec.record(interrupt_res.to_dict(manager.output_limit_chars))
        frame = await rec.execute(session, "-stack-info-frame")
        bt = await rec.execute(session, "-stack-list-frames 0 4")
        locs = await rec.execute(session, "-stack-list-variables --simple-values")
        for name, item in (
            ("break", brk),
            ("run", run),
            ("interrupt", intr),
            ("frame", frame),
            ("backtrace", bt),
            ("locals", locs),
        ):
            if not item.get("ok"):
                failures.append(f"{name} failed: {item.get('error')}")
    finally:
        rec.record(await manager.close(session.session_id))
    return failures


async def _scenario_stripped_binary_analysis(
    manager: SessionManager,
    fake_gdb: Path,
    rec: _CallRecorder,
) -> list[str]:
    failures: list[str] = []
    session = await manager.create(gdb_path=str(fake_gdb))
    rec.record(session_response(session))
    try:
        maps = await rec.execute(session, "info proc mappings")
        parsed_maps = parse_mappings(str(maps.get("console") or ""))
        if not parsed_maps:
            failures.append("expected parsed mappings")
        disasm = await rec.execute(session, "x/12i $pc")
        mem = await rec.execute(session, '-data-read-memory-bytes "$sp" 16')
        sym = await rec.execute(session, "info symbol 0x401004")
        for name, item in (
            ("mappings", maps),
            ("disasm", disasm),
            ("memory", mem),
            ("symbol", sym),
        ):
            if not item.get("ok"):
                failures.append(f"{name} failed: {item.get('error')}")
    finally:
        rec.record(await manager.close(session.session_id))
    return failures


async def _scenario_core_dump_triage(
    manager: SessionManager,
    fake_gdb: Path,
    rec: _CallRecorder,
) -> list[str]:
    failures: list[str] = []
    session = await manager.create(
        gdb_path=str(fake_gdb),
        env={"FAKE_GDB_LARGE_OUTPUT": "1"},
    )
    rec.record(session_response(session))
    try:
        core = await rec.execute(session, "target core /tmp/sample.core")
        frame = await rec.execute(session, "-stack-info-frame")
        bt = await rec.execute(session, "-stack-list-frames 0 4")
        for name, item in (("core", core), ("frame", frame), ("backtrace", bt)):
            if not item.get("ok"):
                failures.append(f"{name} failed: {item.get('error')}")
    finally:
        rec.record(await manager.close(session.session_id))
    return failures


async def _scenario_remote_debug_info_setup(
    manager: SessionManager,
    fake_gdb: Path,
    rec: _CallRecorder,
) -> list[str]:
    failures: list[str] = []
    session = await manager.create(gdb_path=str(fake_gdb))
    rec.record(session_response(session))
    try:
        for name, cmd in (
            ("sysroot", f"-gdb-set sysroot {c_escape('/srv/sysroot')}"),
            ("solib", f"-gdb-set solib-search-path {c_escape('/srv/sysroot/lib')}"),
            (
                "substitute",
                f"-gdb-set substitute-path {c_escape('/build/src')} {c_escape('/workspace/src')}",
            ),
            ("debugdir", f"-gdb-set debug-file-directory {c_escape('/usr/lib/debug')}"),
        ):
            res = await rec.execute(session, cmd)
            if not res.get("ok"):
                failures.append(f"{name} failed: {res.get('error')}")
    finally:
        rec.record(await manager.close(session.session_id))
    return failures


async def _scenario_unavailable_dependency(
    manager: SessionManager,
    _fake_gdb: Path,
    rec: _CallRecorder,
) -> list[str]:
    failures: list[str] = []
    try:
        await manager.create(gdb_path="/definitely/missing/gdb-binary-for-eval")
        failures.append("expected GdbNotFound error")
    except Exception as exc:
        payload = rec.record(error_response(exc))
        if payload.get("error_code") != "dependency_not_found":
            failures.append(f"unexpected error_code: {payload.get('error_code')}")
    return failures


_RUNNERS: dict[
    str,
    Callable[[SessionManager, Path, _CallRecorder], Awaitable[list[str]]],
] = {
    "local_source_triage": _scenario_local_source_triage,
    "stripped_binary_analysis": _scenario_stripped_binary_analysis,
    "core_dump_triage": _scenario_core_dump_triage,
    "remote_debug_info_setup": _scenario_remote_debug_info_setup,
    "unavailable_dependency": _scenario_unavailable_dependency,
}


async def run_all_scenarios(
    *,
    fake_gdb_path: Path | None = None,
    scenarios: tuple[ScenarioSpec, ...] = SCENARIOS,
) -> EvalReport:
    """Execute deterministic baseline scenarios and collect budget/leak metrics."""

    fake_gdb = (fake_gdb_path or DEFAULT_FAKE_GDB).resolve()
    fake_gdb.chmod(0o755)
    results: list[ScenarioResult] = []

    for spec in scenarios:
        manager = SessionManager(max_sessions=4, output_limit_chars=50_000)
        recorder = _CallRecorder(manager.output_limit_chars)
        started = time.perf_counter()
        failures: list[str] = []
        completed = False
        try:
            runner = _RUNNERS[spec.name]
            failures = await runner(manager, fake_gdb, recorder)
            completed = len(failures) == 0
        except Exception as exc:
            failures = [f"unhandled exception: {type(exc).__name__}: {exc}"]
        finally:
            remaining = len(await manager.list())
            await manager.close_all()

        elapsed = time.perf_counter() - started
        tool_calls, total_bytes, total_tokens = recorder.totals()
        within_budget = (
            total_bytes <= spec.max_bytes and total_tokens <= spec.max_estimated_tokens
        )
        if not within_budget:
            failures.append(
                f"budget exceeded: {total_bytes}B/{total_tokens}tok "
                f"(limit {spec.max_bytes}B/{spec.max_estimated_tokens}tok)"
            )
        if remaining != 0:
            failures.append(f"leaked {remaining} live session(s)")

        results.append(
            ScenarioResult(
                name=spec.name,
                completed=completed,
                tool_calls=tool_calls,
                serialized_bytes=total_bytes,
                estimated_tokens=total_tokens,
                elapsed_seconds=elapsed,
                leaked_sessions=remaining,
                within_budget=within_budget,
                failures=failures,
            )
        )

    return EvalReport(scenarios=results)
