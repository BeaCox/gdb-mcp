"""GDB session lifecycle and asynchronous MI command routing."""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .mi import MIParseError, MIRecord, c_escape, parse_mi_record, quote_cli_command


class GdbMcpError(RuntimeError):
    """Base error for this package."""


class GdbNotFound(GdbMcpError):
    """Raised when GDB cannot be found."""


class SessionNotFound(GdbMcpError):
    """Raised when a session ID is unknown."""


def _wall_time() -> float:
    return time.time()


def _monotonic() -> float:
    return time.monotonic()


def _remaining(deadline: float) -> float:
    return max(0.001, deadline - _monotonic())


def _mi_arguments(args: list[str]) -> str:
    return " ".join(c_escape(arg) for arg in args)


def _mi_word(name: str, value: str) -> str:
    if not value:
        raise ValueError(f"{name} must not be empty")
    if any(char.isspace() for char in value) or '"' in value:
        raise ValueError(f"{name} must be a single unquoted GDB/MI argument")
    return value


_GDBSERVER_PORT_RE = re.compile(r"\bListening on port (?P<port>[0-9]+)\b", re.IGNORECASE)
_HEX_VALUE_RE = re.compile(r"0x[0-9a-fA-F]+")


def gdbserver_target_endpoint(listen: str, banner: str) -> str:
    """Return the endpoint GDB should connect to for a locally launched gdbserver."""

    host: str | None = None
    port = listen
    if ":" in listen:
        host, port = listen.rsplit(":", 1)
        if host in {"", "0.0.0.0", "::", "[::]"}:
            host = "localhost"
        elif host.startswith("[") and host.endswith("]"):
            host = host[1:-1]

    match = _GDBSERVER_PORT_RE.search(banner)
    if match is not None:
        port = match.group("port")

    if host:
        return f"{host}:{port}"
    if port.isdigit():
        return f"localhost:{port}"
    return listen.lstrip(":")


def _truncate_text(value: str, limit: int) -> tuple[str, bool]:
    if len(value) <= limit:
        return value, False
    suffix = f"\n... truncated {len(value) - limit} characters"
    keep = max(0, limit - len(suffix))
    return value[:keep] + suffix, True


def _truncate_value(value: Any, budget: int) -> tuple[Any, bool]:
    """Bound nested MI data while preserving its JSON-compatible shape."""

    if budget <= 0:
        if isinstance(value, str):
            return "", bool(value)
        if isinstance(value, list):
            return [], bool(value)
        if isinstance(value, dict):
            return {}, bool(value)
        return value, False
    if isinstance(value, str):
        return _truncate_text(value, budget)
    if isinstance(value, list):
        output: list[Any] = []
        remaining = budget
        truncated = False
        for item in value:
            if remaining <= 0:
                truncated = True
                break
            bounded, item_truncated = _truncate_value(item, remaining)
            output.append(bounded)
            remaining -= len(repr(bounded))
            truncated = truncated or item_truncated
        truncated = truncated or len(output) < len(value)
        return output, truncated
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        remaining = budget
        truncated = False
        for key, item in value.items():
            if remaining <= 0:
                truncated = True
                break
            bounded, item_truncated = _truncate_value(item, remaining)
            output[key] = bounded
            remaining -= len(key) + len(repr(bounded))
            truncated = truncated or item_truncated
        truncated = truncated or len(output) < len(value)
        return output, truncated
    return value, False


def _compact_hex_values(value: Any) -> Any:
    """Shorten full-string hexadecimal values in nested MI payloads."""

    if isinstance(value, str):
        if _HEX_VALUE_RE.fullmatch(value):
            return hex(int(value, 16))
        return value
    if isinstance(value, list):
        return [_compact_hex_values(item) for item in value]
    if isinstance(value, dict):
        return {key: _compact_hex_values(item) for key, item in value.items()}
    return value


@dataclass
class CommandResult:
    command: str
    records: list[MIRecord]
    result_record: MIRecord | None = None
    stopped_record: MIRecord | None = None
    timed_out: bool = False
    interrupted: bool = False
    error: str | None = None

    def to_dict(self, output_limit_chars: int = 100_000) -> dict[str, Any]:
        console = "".join(
            record.text or ""
            for record in self.records
            if record.kind == "stream" and record.stream == "console"
        ).strip()
        target = "".join(
            record.text or ""
            for record in self.records
            if record.kind == "stream" and record.stream == "target"
        ).strip()
        log = "".join(
            record.text or ""
            for record in self.records
            if record.kind == "stream" and record.stream == "log"
        ).strip()

        section_limit = max(1_000, output_limit_chars // 4)
        console, console_truncated = _truncate_text(console, section_limit)
        target, target_truncated = _truncate_text(target, section_limit)
        log, log_truncated = _truncate_text(log, section_limit)
        results, results_truncated = _truncate_value(
            self.result_record.results if self.result_record else {},
            max(1_000, output_limit_chars // 2),
        )
        stopped, stopped_truncated = _truncate_value(
            self.stopped_record.results if self.stopped_record else None,
            max(1_000, output_limit_chars // 4),
        )

        async_records = [
            record.to_dict()
            for record in self.records
            if record.kind in {"exec", "status", "notify"}
        ]
        async_records, async_truncated = _truncate_value(
            async_records, max(1_000, output_limit_chars // 3)
        )
        raw = [record.raw for record in self.records if record.kind != "prompt"]
        raw, raw_truncated = _truncate_value(
            raw, max(1_000, output_limit_chars // 3)
        )

        result_class = self.result_record.record_class if self.result_record else None
        ok = (
            not self.timed_out
            and self.error is None
            and result_class not in {"error", None}
        )
        truncated = any(
            (
                console_truncated,
                target_truncated,
                log_truncated,
                results_truncated,
                stopped_truncated,
                async_truncated,
                raw_truncated,
            )
        )
        return _compact_hex_values({
            "ok": ok,
            "command": self.command,
            "result_class": result_class,
            "results": results,
            "stopped": stopped,
            "console": console,
            "target": target,
            "log": log,
            "async": async_records,
            "raw": raw,
            "timed_out": self.timed_out,
            "interrupted": self.interrupted,
            "error": self.error,
            "truncated": truncated,
            "output_limit_chars": output_limit_chars,
        })


@dataclass
class _PendingCommand:
    token: int
    display_command: str
    wait_for_stop: bool
    future: asyncio.Future[CommandResult]
    history_entry: dict[str, Any]
    records: list[MIRecord] = field(default_factory=list)
    result_record: MIRecord | None = None
    stopped_record: MIRecord | None = None
    saw_running: bool = False

    def result(self) -> CommandResult:
        return CommandResult(
            command=self.display_command,
            records=self.records,
            result_record=self.result_record,
            stopped_record=self.stopped_record,
        )


@dataclass
class GdbSession:
    gdb_path: str = "gdb"
    program: str | None = None
    args: list[str] = field(default_factory=list)
    cwd: str | None = None
    env: dict[str, str] | None = None
    output_limit_chars: int = 100_000
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=_wall_time)
    process: asyncio.subprocess.Process | None = None
    gdbserver_process: asyncio.subprocess.Process | None = None
    gdbserver_drain_task: asyncio.Task[None] | None = None
    gdbserver_endpoint: str | None = None
    last_stop: dict[str, Any] | None = None
    state: str = "created"
    last_activity_at: float = field(default_factory=_wall_time)
    _token: int = 1
    _command_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _write_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _reader_task: asyncio.Task[None] | None = None
    _startup_prompt: asyncio.Event = field(default_factory=asyncio.Event)
    _reader_error: Exception | None = None
    _pending: dict[int, _PendingCommand] = field(default_factory=dict)
    _recent_records: deque[MIRecord] = field(
        default_factory=lambda: deque(maxlen=500),
    )
    _recent_commands: deque[dict[str, Any]] = field(
        default_factory=lambda: deque(maxlen=200),
    )

    async def start(self, startup_timeout: float = 10.0) -> dict[str, Any]:
        if self.process is not None and self.process.returncode is None:
            return self.describe()
        resolved_gdb = shutil.which(self.gdb_path)
        if resolved_gdb is None:
            raise GdbNotFound(f"GDB executable not found: {self.gdb_path}")

        command = [
            resolved_gdb,
            "--interpreter=mi2",
            "--nx",
            "--nh",
            "-q",
        ]
        if self.program:
            command.append(self.program)

        env = os.environ.copy()
        if self.env:
            env.update(self.env)

        self.state = "starting"
        self._startup_prompt.clear()
        self._reader_error = None
        try:
            self.process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                cwd=self.cwd,
                env=env,
            )
            self._reader_task = asyncio.create_task(
                self._reader_loop(),
                name=f"gdb-reader-{self.session_id}",
            )
            await asyncio.wait_for(self._startup_prompt.wait(), timeout=startup_timeout)
            if self._reader_error is not None:
                raise GdbMcpError(f"GDB failed during startup: {self._reader_error}")

            await self._require_success("-gdb-set pagination off", timeout=3.0)
            await self._require_success("-gdb-set confirm off", timeout=3.0)
            await self._require_success("-gdb-set breakpoint pending on", timeout=3.0)
            if self.args:
                await self._require_success(
                    f"-exec-arguments {_mi_arguments(self.args)}",
                    timeout=3.0,
                )
            self.state = "ready"
            return self.describe()
        except BaseException:
            await self.close()
            raise

    async def connect_gdbserver(
        self,
        endpoint: str,
        *,
        extended: bool = True,
        timeout: float = 15.0,
        sysroot: str | None = None,
        solib_search_path: str | None = None,
    ) -> dict[str, Any]:
        await self.ensure_started()
        if sysroot:
            result = await self.execute(
                f"-gdb-set sysroot {c_escape(sysroot)}",
                timeout=timeout,
            )
            if not result.to_dict(self.output_limit_chars)["ok"]:
                return result.to_dict(self.output_limit_chars)
        if solib_search_path:
            result = await self.execute(
                f"-gdb-set solib-search-path {c_escape(solib_search_path)}",
                timeout=timeout,
            )
            if not result.to_dict(self.output_limit_chars)["ok"]:
                return result.to_dict(self.output_limit_chars)
        mode = "extended-remote" if extended else "remote"
        result = await self.execute(
            f"-target-select {mode} {_mi_word('endpoint', endpoint)}",
            timeout=timeout,
        )
        if result.result_record and result.result_record.record_class != "error":
            self.gdbserver_endpoint = endpoint
            self.state = "stopped"
        return result.to_dict(self.output_limit_chars)

    async def execute(
        self,
        command: str,
        *,
        timeout: float = 15.0,
        wait_for_stop: bool = False,
        auto_interrupt: bool = False,
    ) -> CommandResult:
        await self.ensure_started()
        actual = command if command.strip().startswith("-") else quote_cli_command(command)

        async with self._command_lock:
            result = await self._send_command(
                actual,
                display_command=command,
                timeout=timeout,
                wait_for_stop=wait_for_stop,
            )
            if result.timed_out and auto_interrupt and self.is_alive():
                interrupt_result = await self.interrupt(timeout=5.0)
                result.interrupted = (
                    interrupt_result.result_record is not None
                    and interrupt_result.result_record.record_class != "error"
                )
                result.records.extend(interrupt_result.records)
                if interrupt_result.stopped_record is not None:
                    result.stopped_record = interrupt_result.stopped_record
            return result

    async def interrupt(self, timeout: float = 5.0) -> CommandResult:
        """Interrupt GDB without waiting for the long-running command lock."""

        await self.ensure_started()
        return await self._send_command(
            "-exec-interrupt",
            display_command="-exec-interrupt",
            timeout=timeout,
            wait_for_stop=True,
        )

    async def close(self) -> None:
        self.state = "closing"
        process = self.process
        if process is not None and process.returncode is None:
            try:
                await self._send_command(
                    "-gdb-exit",
                    display_command="-gdb-exit",
                    timeout=1.0,
                    wait_for_stop=False,
                )
            except Exception:
                pass
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()

        if self._reader_task is not None:
            if not self._reader_task.done():
                self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
            self._reader_task = None

        if self.gdbserver_drain_task is not None:
            self.gdbserver_drain_task.cancel()
        if self.gdbserver_process is not None and self.gdbserver_process.returncode is None:
            self.gdbserver_process.terminate()
            try:
                await asyncio.wait_for(self.gdbserver_process.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                self.gdbserver_process.kill()
                await self.gdbserver_process.wait()
        if self.gdbserver_drain_task is not None:
            try:
                await self.gdbserver_drain_task
            except asyncio.CancelledError:
                pass
            self.gdbserver_drain_task = None

        self._fail_pending(GdbMcpError("GDB session closed"))
        self.state = "closed"

    def is_alive(self) -> bool:
        return self.process is not None and self.process.returncode is None

    def describe(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "gdb_path": self.gdb_path,
            "program": self.program,
            "args": self.args,
            "cwd": self.cwd or os.getcwd(),
            "alive": self.is_alive(),
            "state": self.state,
            "gdb_pid": self.process.pid if self.process else None,
            "gdbserver_pid": self.gdbserver_process.pid if self.gdbserver_process else None,
            "gdbserver_endpoint": self.gdbserver_endpoint,
            "last_stop": self.last_stop,
            "created_at": self.created_at,
            "last_activity_at": self.last_activity_at,
        }

    def recent_records(self, limit: int = 100) -> list[dict[str, Any]]:
        records = list(self._recent_records)
        return [record.to_dict() for record in records[-max(0, limit) :]]

    def recent_commands(self, limit: int = 100) -> list[dict[str, Any]]:
        commands = list(self._recent_commands)
        return commands[-max(0, limit) :]

    async def ensure_started(self) -> None:
        if self.process is None:
            await self.start()
        elif self.process.returncode is not None:
            raise GdbMcpError(f"GDB exited with code {self.process.returncode}")

    async def _require_success(self, command: str, timeout: float) -> None:
        result = await self.execute(command, timeout=timeout)
        payload = result.to_dict(self.output_limit_chars)
        if not payload["ok"]:
            raise GdbMcpError(
                f"GDB initialization command failed: {command}: "
                f"{payload['error'] or payload['results']}"
            )

    async def _send_command(
        self,
        command: str,
        *,
        display_command: str,
        timeout: float,
        wait_for_stop: bool,
    ) -> CommandResult:
        process = self.process
        if process is None or process.returncode is not None:
            code = process.returncode if process is not None else None
            return CommandResult(
                command=display_command,
                records=[],
                error=f"GDB is not running (exit code: {code})",
            )
        if process.stdin is None:
            return CommandResult(
                command=display_command,
                records=[],
                error="GDB stdin is not available",
            )

        token = self._token
        self._token += 1
        future: asyncio.Future[CommandResult] = asyncio.get_running_loop().create_future()
        started_at = _wall_time()
        pending = _PendingCommand(
            token=token,
            display_command=display_command,
            wait_for_stop=wait_for_stop,
            future=future,
            history_entry={
                "token": token,
                "command": display_command,
                "mi_command": command,
                "wait_for_stop": wait_for_stop,
                "started_at": started_at,
                "timeout": timeout,
                "status": "running",
            },
        )
        self._pending[token] = pending
        self.last_activity_at = started_at
        self._recent_commands.append(pending.history_entry)

        try:
            async with self._write_lock:
                process.stdin.write(f"{token}{command}\n".encode())
                await process.stdin.drain()
            return await asyncio.wait_for(asyncio.shield(future), timeout=timeout)
        except asyncio.TimeoutError:
            self._pending.pop(token, None)
            future.cancel()
            self._finish_command_history(
                pending,
                status="timeout",
                error=f"Timed out after {timeout} seconds",
                timed_out=True,
            )
            return CommandResult(
                display_command,
                pending.records,
                result_record=pending.result_record,
                stopped_record=pending.stopped_record,
                timed_out=True,
                error=f"Timed out after {timeout} seconds",
            )
        except (BrokenPipeError, ConnectionResetError) as exc:
            self._pending.pop(token, None)
            self._finish_command_history(pending, status="error", error=str(exc))
            return CommandResult(display_command, pending.records, error=str(exc))

    async def _reader_loop(self) -> None:
        assert self.process is not None
        assert self.process.stdout is not None
        try:
            while True:
                raw = await self.process.stdout.readline()
                if raw == b"":
                    raise GdbMcpError("GDB stdout closed")
                line = raw.decode(errors="replace").rstrip("\r\n")
                try:
                    record = parse_mi_record(line)
                except MIParseError:
                    record = MIRecord(
                        kind="stream",
                        raw=line,
                        stream="log",
                        text=line + "\n",
                    )
                self.last_activity_at = _wall_time()
                self._route_record(record)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._reader_error = exc
            self._startup_prompt.set()
            self._fail_pending(exc)
            if self.state not in {"closing", "closed"}:
                self.state = "exited"

    def _route_record(self, record: MIRecord) -> None:
        if record.kind == "prompt":
            self._startup_prompt.set()
            for pending in list(self._pending.values()):
                if (
                    pending.wait_for_stop
                    and pending.result_record is not None
                    and not pending.saw_running
                ):
                    self._finish_pending(pending)
            return

        self._recent_records.append(record)
        if record.kind == "result":
            pending = self._pending.get(record.token or -1)
            if pending is None:
                return
            pending.records.append(record)
            pending.result_record = record
            if record.record_class == "running":
                pending.saw_running = True
                self.state = "running"
            if (
                not pending.wait_for_stop
                or record.record_class in {"error", "exit"}
                or pending.stopped_record is not None
            ):
                self._finish_pending(pending)
            return

        for pending in self._pending.values():
            pending.records.append(record)

        if record.kind == "exec" and record.record_class == "running":
            self.state = "running"
            for pending in self._pending.values():
                pending.saw_running = True
            return

        if record.kind == "exec" and record.record_class == "stopped":
            self.state = "stopped"
            self.last_stop = record.results or {}
            for pending in list(self._pending.values()):
                if pending.wait_for_stop:
                    pending.stopped_record = record
                    if pending.result_record is not None:
                        self._finish_pending(pending)

    def _finish_pending(self, pending: _PendingCommand) -> None:
        self._pending.pop(pending.token, None)
        if not pending.future.done():
            result = pending.result()
            self._finish_command_history(
                pending,
                status="error"
                if result.error is not None
                or (
                    result.result_record is not None
                    and result.result_record.record_class == "error"
                )
                else "done",
                error=result.error,
            )
            pending.future.set_result(result)

    def _fail_pending(self, exc: Exception) -> None:
        pending_commands = list(self._pending.values())
        self._pending.clear()
        for pending in pending_commands:
            if not pending.future.done():
                self._finish_command_history(pending, status="error", error=str(exc))
                pending.future.set_result(
                    CommandResult(
                        pending.display_command,
                        pending.records,
                        result_record=pending.result_record,
                        stopped_record=pending.stopped_record,
                        error=str(exc),
                    )
                )

    def _finish_command_history(
        self,
        pending: _PendingCommand,
        *,
        status: str,
        error: str | None = None,
        timed_out: bool = False,
    ) -> None:
        if pending.history_entry.get("finished_at") is not None:
            return
        finished_at = _wall_time()
        started_at = float(pending.history_entry["started_at"])
        pending.history_entry.update(
            {
                "status": status,
                "finished_at": finished_at,
                "duration_seconds": max(0.0, finished_at - started_at),
                "result_class": (
                    pending.result_record.record_class
                    if pending.result_record is not None
                    else None
                ),
                "stopped": pending.stopped_record is not None,
                "timed_out": timed_out,
                "error": error,
                "record_count": len(pending.records),
            }
        )


class SessionManager:
    def __init__(self, *, max_sessions: int = 8, output_limit_chars: int = 100_000) -> None:
        self._sessions: dict[str, GdbSession] = {}
        self._lock = asyncio.Lock()
        self._creating = 0
        self.max_sessions = max_sessions
        self.output_limit_chars = output_limit_chars

    async def create(
        self,
        *,
        gdb_path: str = "gdb",
        program: str | None = None,
        args: list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        startup_timeout: float = 10.0,
    ) -> GdbSession:
        async with self._lock:
            live_count = sum(session.is_alive() for session in self._sessions.values())
            if (
                self.max_sessions > 0
                and live_count + self._creating >= self.max_sessions
            ):
                raise GdbMcpError(
                    f"Session limit reached ({self.max_sessions}); close a session first"
                )
            self._creating += 1

        session = GdbSession(
            gdb_path=gdb_path,
            program=program,
            args=args or [],
            cwd=cwd,
            env=env,
            output_limit_chars=self.output_limit_chars,
        )
        try:
            await session.start(startup_timeout=startup_timeout)
        except BaseException:
            await session.close()
            async with self._lock:
                self._creating -= 1
            raise
        async with self._lock:
            self._creating -= 1
            self._sessions[session.session_id] = session
        return session

    async def add(self, session: GdbSession) -> None:
        async with self._lock:
            self._sessions[session.session_id] = session

    async def get(self, session_id: str) -> GdbSession:
        async with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise SessionNotFound(f"Unknown GDB session: {session_id}")
        return session

    async def list(self) -> list[dict[str, Any]]:
        async with self._lock:
            sessions = list(self._sessions.values())
        return [session.describe() for session in sessions]

    async def close(self, session_id: str) -> dict[str, Any]:
        async with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            raise SessionNotFound(f"Unknown GDB session: {session_id}")
        await session.close()
        return {"closed": True, "session_id": session_id}

    async def close_all(self) -> None:
        async with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        await asyncio.gather(
            *(session.close() for session in sessions),
            return_exceptions=True,
        )


async def launch_gdbserver(
    *,
    program: str,
    listen: str,
    args: list[str] | None = None,
    cwd: str | None = None,
    gdbserver_path: str = "gdbserver",
    startup_timeout: float = 5.0,
) -> tuple[asyncio.subprocess.Process, str, asyncio.Task[None] | None]:
    resolved = shutil.which(gdbserver_path)
    if resolved is None:
        raise GdbMcpError(f"gdbserver executable not found: {gdbserver_path}")

    process = await asyncio.create_subprocess_exec(
        resolved,
        listen,
        program,
        *(args or []),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=cwd,
    )

    output: list[str] = []
    deadline = _monotonic() + startup_timeout
    try:
        while _monotonic() < deadline:
            if process.returncode is not None:
                raise GdbMcpError(
                    f"gdbserver exited early with code {process.returncode}: "
                    + "".join(output).strip()
                )
            if process.stdout is None:
                raise GdbMcpError("gdbserver stdout is not available")
            raw = await asyncio.wait_for(
                process.stdout.readline(),
                timeout=_remaining(deadline),
            )
            if raw == b"":
                raise GdbMcpError(
                    "gdbserver closed stdout during startup: " + "".join(output).strip()
                )
            text = raw.decode(errors="replace")
            output.append(text)
            lower = text.lower()
            if "listening" in lower or "remote debugging" in lower:
                return process, "".join(output), _start_stdout_drain(process)
        raise GdbMcpError(
            f"gdbserver did not become ready within {startup_timeout} seconds: "
            + "".join(output).strip()
        )
    except BaseException:
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
        raise


def _start_stdout_drain(
    process: asyncio.subprocess.Process,
) -> asyncio.Task[None] | None:
    if process.stdout is None:
        return None
    return asyncio.create_task(
        _drain_stdout(process.stdout),
        name=f"gdbserver-drain-{process.pid}",
    )


async def _drain_stdout(stream: asyncio.StreamReader) -> None:
    while True:
        chunk = await stream.read(4096)
        if not chunk:
            return
