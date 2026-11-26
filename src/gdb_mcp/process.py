"""Process-group and Linux parent-death-signal helpers for child subprocesses."""

from __future__ import annotations

import asyncio
import ctypes
import os
import signal
import sys
from collections.abc import Callable
from typing import Any

_PR_SET_PDEATHSIG = 1
_LIBC_NAME = "libc.so.6"


def _load_libc() -> ctypes.CDLL | None:
    if not sys.platform.startswith("linux"):
        return None
    try:
        return ctypes.CDLL(_LIBC_NAME, use_errno=True)
    except OSError:
        return None


def set_pdeathsig(sig: int, *, expected_ppid: int | None = None) -> bool:
    """Ask Linux to deliver ``sig`` to this process if its parent dies.

    Returns ``True`` when the prctl succeeded, or ``False`` on non-Linux hosts
    or when ``prctl`` is unavailable. If ``expected_ppid`` is provided and the
    parent has already exited (``os.getppid() != expected_ppid``), delivers
    ``sig`` to self immediately so no race window leaks an orphan.
    """

    libc = _load_libc()
    if libc is None:
        return False
    prctl = getattr(libc, "prctl", None)
    if prctl is None:
        return False
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int
    if prctl(_PR_SET_PDEATHSIG, sig, 0, 0, 0) != 0:
        return False
    if expected_ppid is not None and os.getppid() != expected_ppid:
        os.kill(os.getpid(), sig)
    return True


def make_child_preexec(sig: int = signal.SIGKILL) -> Callable[[], None] | None:
    """Return a preexec_fn that binds a Linux child to its parent's lifetime."""

    if not sys.platform.startswith("linux"):
        return None
    libc = _load_libc()
    if libc is None:
        return None
    prctl = getattr(libc, "prctl", None)
    if prctl is None:
        return None
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int
    parent_pid = os.getpid()

    def _preexec() -> None:
        prctl(_PR_SET_PDEATHSIG, sig, 0, 0, 0)
        if os.getppid() != parent_pid:
            os._exit(1)

    return _preexec


def _signal_process_or_group(
    sig: int,
    *,
    process: asyncio.subprocess.Process | None = None,
    pgid: int | None = None,
    pid: int | None = None,
) -> None:
    target_pgid = pgid if pgid is not None else pid
    if target_pgid is not None and hasattr(os, "killpg"):
        try:
            os.killpg(target_pgid, sig)
            return
        except (ProcessLookupError, PermissionError, OSError):
            pass
    if process is not None and process.returncode is None:
        try:
            if sig == signal.SIGTERM:
                process.terminate()
            else:
                process.kill()
            return
        except ProcessLookupError:
            return
    if pid is not None:
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            pass


async def terminate_process_group(
    process: asyncio.subprocess.Process | None,
    pgid: int | None = None,
    *,
    timeout: float = 2.0,
) -> None:
    """Terminate a child process and its process group, escalating to SIGKILL."""

    if process is None:
        return
    if process.returncode is not None:
        if pgid is not None:
            _signal_process_or_group(signal.SIGTERM, pgid=pgid)
        return

    _signal_process_or_group(
        signal.SIGTERM,
        process=process,
        pgid=pgid or process.pid,
        pid=process.pid,
    )
    try:
        await asyncio.wait_for(process.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        _signal_process_or_group(
            signal.SIGKILL,
            process=process,
            pgid=pgid or process.pid,
            pid=process.pid,
        )
        await process.wait()


def terminate_process_group_sync(pgid: int | None, pid: int | None) -> None:
    """Best-effort synchronous process-group termination for exit/signal hooks."""

    if pgid is None and pid is None:
        return
    _signal_process_or_group(signal.SIGTERM, pgid=pgid, pid=pid)
    _signal_process_or_group(signal.SIGKILL, pgid=pgid, pid=pid)


def subprocess_group_kwargs() -> dict[str, Any]:
    """Return keyword arguments to isolate spawned debugger subprocesses."""

    kwargs: dict[str, Any] = {"start_new_session": True}
    preexec = make_child_preexec(signal.SIGKILL)
    if preexec is not None:
        kwargs["preexec_fn"] = preexec
    return kwargs
