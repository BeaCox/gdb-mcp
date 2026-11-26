"""GDB session lifecycle and asynchronous MI command routing."""

# Public debugger APIs intentionally expose numeric timeouts.
# ruff: noqa: ASYNC109

from __future__ import annotations

import asyncio
import os
import re
import shutil
import time
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from anyio import CancelScope

from .mi import MIParseError, MIRecord, c_escape, parse_mi_record, quote_cli_command
from .observability import logger
from .process import (
    subprocess_group_kwargs,
    terminate_process_group,
    terminate_process_group_sync,
)

GDB_STREAM_LIMIT_BYTES = 4 * 1024 * 1024
MAX_GDB_LINE_BYTES = 16 * 1024 * 1024


class GdbMcpError(RuntimeError):
    """Base error for this package."""


class GdbNotFound(GdbMcpError):
    """Raised when GDB cannot be found."""


class SessionNotFound(GdbMcpError):
    """Raised when a session ID is unknown."""


class PolicyDeniedError(GdbMcpError):
    """Raised when an operation is disallowed by server safety policy."""


class SessionLimitError(GdbMcpError):
    """Raised when the live session limit has been reached."""


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
        if ":" in host and not (host.startswith("[") and host.endswith("]")):
            host = f"[{host}]"
        return f"{host}:{port}"
    if port.isdigit():
        return f"localhost:{port}"
    return listen.lstrip(":")


def _mi_target_endpoint(endpoint: str) -> str:
    """Return a validated MI argument for a remote target endpoint."""

    return _mi_word("endpoint", endpoint)


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


def _record_error_message(record: MIRecord | None) -> str | None:
    if record is None or record.record_class != "error":
        return None
    results = record.results or {}
    message = results.get("msg")
    if isinstance(message, str) and message:
        return message
    if results:
        return repr(results)
    return "GDB command failed"


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
    gdb_args: list[str] = field(default_factory=list)
    program: str | None = None
    args: list[str] = field(default_factory=list)
    cwd: str | None = None
    env: dict[str, str] | None = None
    output_limit_chars: int = 100_000
    rr_trace_dir: str | None = None
    max_recent_records: int = 500
    max_recent_commands: int = 200
    clock: Callable[[], float] = _wall_time
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=_wall_time)
    process: asyncio.subprocess.Process | None = None
    gdb_pgid: int | None = None
    gdbserver_process: asyncio.subprocess.Process | None = None
    gdbserver_pgid: int | None = None
    gdbserver_drain_task: asyncio.Task[None] | None = None
    gdbserver_endpoint: str | None = None
    last_stop: dict[str, Any] | None = None
    applied_profiles: list[dict[str, Any]] = field(default_factory=list)
    pagination_version: int = 0
    state: str = "created"
    last_activity_at: float = field(default_factory=_wall_time)
    _token: int = 1
    _command_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _write_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _close_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _closing: bool = False
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

    def __post_init__(self) -> None:
        self._recent_records = deque(maxlen=max(1, self.max_recent_records))
        self._recent_commands = deque(maxlen=max(1, self.max_recent_commands))

    async def start(self, startup_timeout: float = 10.0) -> dict[str, Any]:
        if self.state in {"closing", "closed"} or self._closing:
            raise GdbMcpError(f"GDB session is {self.state}")
        if self.process is not None and self.process.returncode is None:
            return self.describe()
        resolved_gdb = shutil.which(self.gdb_path)
        if resolved_gdb is None:
            raise GdbNotFound(f"GDB executable not found: {self.gdb_path}")

        command = [
            resolved_gdb,
            *self.gdb_args,
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
                limit=GDB_STREAM_LIMIT_BYTES,
                **subprocess_group_kwargs(),
            )
            self.gdb_pgid = self.process.pid
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
            f"-target-select {mode} {_mi_target_endpoint(endpoint)}",
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
        async with self._close_lock:
            if self.state == "closed":
                return
            self._closing = True
            self.state = "closing"
            had_pending = bool(self._pending)
            self._fail_pending(GdbMcpError("GDB session is closing"))

            process = self.process
            if process is not None and process.returncode is None:
                if not had_pending:
                    try:
                        await self._send_command(
                            "-gdb-exit",
                            display_command="-gdb-exit",
                            timeout=1.0,
                            wait_for_stop=False,
                            allow_closing=True,
                        )
                    except Exception:
                        pass
                if process.returncode is None:
                    await terminate_process_group(process, self.gdb_pgid, timeout=2.0)

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
                await terminate_process_group(
                    self.gdbserver_process,
                    self.gdbserver_pgid,
                    timeout=2.0,
                )
            if self.gdbserver_drain_task is not None:
                try:
                    await self.gdbserver_drain_task
                except asyncio.CancelledError:
                    pass
                self.gdbserver_drain_task = None

            self._fail_pending(GdbMcpError("GDB session closed"))
            self.state = "closed"
            self._closing = False

    def is_alive(self) -> bool:
        return self.process is not None and self.process.returncode is None

    def is_busy(self) -> bool:
        return bool(self._pending) or self.state == "running"

    def describe(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "gdb_path": self.gdb_path,
            "program": self.program,
            "args": self.args,
            "cwd": self.cwd or os.getcwd(),
            "rr_trace_dir": self.rr_trace_dir,
            "alive": self.is_alive(),
            "state": self.state,
            "gdb_pid": self.process.pid if self.process else None,
            "gdbserver_pid": self.gdbserver_process.pid if self.gdbserver_process else None,
            "gdbserver_endpoint": self.gdbserver_endpoint,
            "last_stop": self.last_stop,
            "applied_profiles": self.applied_profiles,
            "pagination_version": self.pagination_version,
            "created_at": self.created_at,
            "last_activity_at": self.last_activity_at,
        }

    def recent_records(self, limit: int = 100) -> list[dict[str, Any]]:
        records = list(self._recent_records)
        return [record.to_dict() for record in records[-max(0, limit) :]]

    def recent_commands(self, limit: int = 100) -> list[dict[str, Any]]:
        commands = list(self._recent_commands)
        return commands[-max(0, limit) :]

    def record_profile(self, name: str, configuration: dict[str, Any]) -> None:
        """Record an initialization profile after all of its commands succeed."""

        self.applied_profiles.append(
            {
                "name": name,
                "configuration": configuration,
                "applied_at": self.clock(),
            }
        )

    def invalidate_pagination(self) -> None:
        """Invalidate cursors for output tied to mutable inferior state."""

        self.pagination_version += 1

    async def ensure_started(self) -> None:
        if self.state == "closed":
            raise GdbMcpError("GDB session is closed")
        if self.state == "closing" or self._closing:
            raise GdbMcpError("GDB session is closing")
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
        allow_closing: bool = False,
    ) -> CommandResult:
        if not allow_closing and (self._closing or self.state in {"closing", "closed"}):
            return CommandResult(
                command=display_command,
                records=[],
                error=f"GDB session is {self.state}",
            )
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
        started_at = self.clock()
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

        sent = False
        try:
            async with self._write_lock:
                process.stdin.write(f"{token}{command}\n".encode())
                sent = True
                await process.stdin.drain()
            return await asyncio.wait_for(asyncio.shield(future), timeout=timeout)
        except asyncio.CancelledError:
            self._pending.pop(token, None)
            future.cancel()
            self._finish_command_history(
                pending,
                status="cancelled",
                error="Command task cancelled",
            )
            logger.emit(
                "info",
                "command.cancelled",
                session_id=self.session_id,
                token=token,
                command_family=_command_family(display_command),
            )
            if (
                wait_for_stop
                and display_command != "-exec-interrupt"
                and (sent or pending.saw_running)
                and self.is_alive()
            ):
                try:
                    with CancelScope(shield=True):
                        await self.interrupt(timeout=1.0)
                except Exception:
                    pass
            raise
        except asyncio.TimeoutError:
            self._pending.pop(token, None)
            future.cancel()
            self._finish_command_history(
                pending,
                status="timeout",
                error=f"Timed out after {timeout} seconds",
                timed_out=True,
            )
            logger.emit(
                "warning",
                "command.timeout",
                session_id=self.session_id,
                token=token,
                command_family=_command_family(display_command),
                timeout_seconds=timeout,
            )
            return CommandResult(
                display_command,
                pending.records,
                result_record=pending.result_record,
                stopped_record=pending.stopped_record,
                timed_out=True,
                error=f"Timed out after {timeout} seconds",
            )
        except (BrokenPipeError, ConnectionResetError, OSError) as exc:
            self._pending.pop(token, None)
            future.cancel()
            self._finish_command_history(pending, status="error", error=str(exc))
            logger.emit(
                "error",
                "command.transport_error",
                session_id=self.session_id,
                token=token,
                command_family=_command_family(display_command),
                error_type=type(exc).__name__,
            )
            return CommandResult(display_command, pending.records, error=str(exc))

    async def _readline_bounded(self, stream: asyncio.StreamReader) -> tuple[bytes, bool]:
        preview = bytearray()
        preview_limit = min(max(1_024, self.output_limit_chars), 65_536)
        total_bytes = 0
        truncated = False
        while True:
            try:
                chunk = await stream.readuntil(b"\n")
            except asyncio.IncompleteReadError as exc:
                if not truncated:
                    return exc.partial, False
                if len(preview) < preview_limit and exc.partial:
                    preview.extend(exc.partial[: preview_limit - len(preview)])
                return bytes(preview), True
            except asyncio.LimitOverrunError as exc:
                truncated = True
                consume = exc.consumed if exc.consumed > 0 else 65_536
                piece = await stream.readexactly(consume)
                total_bytes += len(piece)
                if len(preview) < preview_limit:
                    preview.extend(piece[: preview_limit - len(preview)])
                if total_bytes > MAX_GDB_LINE_BYTES:
                    logger.emit(
                        "error",
                        "session.line_exceeded_max",
                        session_id=self.session_id,
                        bytes_read=total_bytes,
                    )
                    raise GdbMcpError("GDB output line exceeded maximum allowed size") from exc
                continue

            if not truncated:
                return chunk, False
            total_bytes += len(chunk)
            if len(preview) < preview_limit:
                preview.extend(chunk[: preview_limit - len(preview)])
            logger.emit(
                "warning",
                "session.line_truncated",
                session_id=self.session_id,
                bytes_read=total_bytes,
                preview_bytes=len(preview),
            )
            return bytes(preview), True

    async def _reader_loop(self) -> None:
        assert self.process is not None
        assert self.process.stdout is not None
        try:
            while True:
                raw, line_truncated = await self._readline_bounded(self.process.stdout)
                if raw == b"" and not line_truncated:
                    raise GdbMcpError("GDB stdout closed")
                line = raw.decode(errors="replace").rstrip("\r\n")
                if line_truncated:
                    record = MIRecord(
                        kind="stream",
                        raw=line,
                        stream="log",
                        text=f"{line}\n... truncated oversized GDB/MI output line\n",
                    )
                else:
                    try:
                        record = parse_mi_record(line)
                    except MIParseError:
                        record = MIRecord(
                            kind="stream",
                            raw=line,
                            stream="log",
                            text=line + "\n",
                        )
                self.last_activity_at = self.clock()
                self._route_record(record)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._reader_error = exc
            self._startup_prompt.set()
            self._fail_pending(exc)
            if self.state not in {"closing", "closed"}:
                self.state = "exited"
            logger.emit(
                "warning",
                "session.reader_stopped",
                session_id=self.session_id,
                state=self.state,
                error_type=type(exc).__name__,
            )

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
            self.invalidate_pagination()
            for pending in self._pending.values():
                pending.saw_running = True
            return

        if record.kind == "exec" and record.record_class == "stopped":
            self.state = "stopped"
            self.last_stop = record.results or {}
            self.invalidate_pagination()
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
                error=result.error or _record_error_message(result.result_record),
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
        finished_at = self.clock()
        started_at = float(pending.history_entry["started_at"])
        duration = max(0.0, finished_at - started_at)
        pending.history_entry.update(
            {
                "status": status,
                "finished_at": finished_at,
                "duration_seconds": duration,
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
        logger.emit(
            "debug",
            "command.finished",
            session_id=self.session_id,
            token=pending.token,
            command_family=_command_family(pending.display_command),
            status=status,
            duration_seconds=duration,
            timed_out=timed_out,
        )


def _command_family(command: str) -> str:
    parts = command.strip().split(maxsplit=1)
    return parts[0] if parts else ""


class SessionManager:
    def __init__(
        self,
        *,
        max_sessions: int = 8,
        output_limit_chars: int = 100_000,
        idle_session_ttl_seconds: float | None = None,
        max_recent_records: int = 500,
        max_recent_commands: int = 200,
        clock: Callable[[], float] = _wall_time,
    ) -> None:
        self._sessions: dict[str, GdbSession] = {}
        self._lock = asyncio.Lock()
        self._creating = 0
        self._reaper_task: asyncio.Task[None] | None = None
        self.max_sessions = max_sessions
        self.output_limit_chars = output_limit_chars
        self.idle_session_ttl_seconds = idle_session_ttl_seconds
        self.max_recent_records = max_recent_records
        self.max_recent_commands = max_recent_commands
        self._clock = clock

    async def prune_dead(self) -> list[str]:
        """Remove and clean up sessions whose GDB process has already exited."""

        async with self._lock:
            dead_ids = [
                session_id
                for session_id, session in self._sessions.items()
                if not session.is_alive() and session.state not in {"created", "starting"}
            ]
            dead_sessions = [self._sessions.pop(session_id) for session_id in dead_ids]
        if dead_sessions:
            await asyncio.gather(
                *(session.close() for session in dead_sessions),
                return_exceptions=True,
            )
            for session_id in dead_ids:
                logger.emit("info", "session.pruned_dead", session_id=session_id)
        return dead_ids

    async def prune_idle(
        self,
        max_idle_seconds: float | None = None,
    ) -> list[dict[str, Any]]:
        """Close non-busy live sessions that have been idle for at least TTL seconds."""

        await self.prune_dead()
        ttl = self.idle_session_ttl_seconds if max_idle_seconds is None else max_idle_seconds
        if ttl is None or ttl < 0:
            return []

        now = self._clock()
        candidates: list[tuple[str, GdbSession, dict[str, Any], float]] = []
        async with self._lock:
            for session_id, session in list(self._sessions.items()):
                if session.is_busy():
                    continue
                idle = max(0.0, now - float(session.last_activity_at))
                if idle < ttl:
                    continue
                self._sessions.pop(session_id, None)
                candidates.append((session_id, session, session.describe(), idle))

        closed: list[dict[str, Any]] = []
        for session_id, session, description, idle in candidates:
            try:
                await session.close()
                closed.append(
                    {
                        "session": description,
                        "result": {"closed": True, "session_id": session_id},
                        "idle_seconds": idle,
                    }
                )
                logger.emit(
                    "info",
                    "session.expired_idle",
                    session_id=session_id,
                    idle_seconds=idle,
                )
            except Exception as exc:
                closed.append(
                    {
                        "session": description,
                        "error": str(exc),
                        "idle_seconds": idle,
                    }
                )
        return closed

    def start_reaper(self, interval_seconds: float | None = None) -> None:
        """Start automatic idle-session cleanup when an idle TTL is configured."""

        ttl = self.idle_session_ttl_seconds
        if ttl is None or ttl <= 0:
            return
        if self._reaper_task is not None and not self._reaper_task.done():
            return
        interval = (
            interval_seconds
            if interval_seconds is not None
            else min(max(1.0, ttl / 4.0), 60.0)
        )
        self._reaper_task = asyncio.create_task(
            self._reaper_loop(interval),
            name="gdb-session-reaper",
        )

    async def stop_reaper(self) -> None:
        task = self._reaper_task
        self._reaper_task = None
        if task is None:
            return
        if not task.done():
            task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def _reaper_loop(self, interval_seconds: float) -> None:
        while True:
            await asyncio.sleep(interval_seconds)
            try:
                await self.prune_idle()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.emit(
                    "warning",
                    "session.reaper_error",
                    error_type=type(exc).__name__,
                )

    async def create(
        self,
        *,
        gdb_path: str = "gdb",
        gdb_args: list[str] | None = None,
        program: str | None = None,
        args: list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        rr_trace_dir: str | None = None,
        startup_timeout: float = 10.0,
    ) -> GdbSession:
        await self.prune_dead()
        if self.idle_session_ttl_seconds is not None and self.idle_session_ttl_seconds > 0:
            await self.prune_idle()

        async with self._lock:
            live_count = sum(session.is_alive() for session in self._sessions.values())
            if (
                self.max_sessions > 0
                and live_count + self._creating >= self.max_sessions
            ):
                raise SessionLimitError(
                    f"Session limit reached ({self.max_sessions}); close a session first"
                )
            self._creating += 1

        now = self._clock()
        session = GdbSession(
            gdb_path=gdb_path,
            gdb_args=gdb_args or [],
            program=program,
            args=args or [],
            cwd=cwd,
            env=env,
            output_limit_chars=self.output_limit_chars,
            rr_trace_dir=rr_trace_dir,
            max_recent_records=self.max_recent_records,
            max_recent_commands=self.max_recent_commands,
            clock=self._clock,
            created_at=now,
            last_activity_at=now,
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
        logger.emit(
            "info",
            "session.created",
            session_id=session.session_id,
            has_program=bool(program),
        )
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
        logger.emit("info", "session.closed", session_id=session_id)
        return {"closed": True, "session_id": session_id}

    async def close_all(self) -> None:
        await self.stop_reaper()
        async with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        await asyncio.gather(
            *(session.close() for session in sessions),
            return_exceptions=True,
        )

    def terminate_all_sync(self) -> None:
        """Best-effort synchronous cleanup of all spawned debugger process groups."""

        sessions = list(self._sessions.values())
        for session in sessions:
            if session.process is not None and session.process.returncode is None:
                terminate_process_group_sync(session.gdb_pgid, session.process.pid)
            if (
                session.gdbserver_process is not None
                and session.gdbserver_process.returncode is None
            ):
                terminate_process_group_sync(
                    session.gdbserver_pgid,
                    session.gdbserver_process.pid,
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
        **subprocess_group_kwargs(),
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
            await terminate_process_group(process, process.pid, timeout=2.0)
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
