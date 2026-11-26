import asyncio
import json
import os
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
FAKE_GDB = ROOT / "tests" / "fixtures" / "fake_gdb.py"


def _source_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(SRC), *(item for item in [env.get("PYTHONPATH")] if item)]
    )
    return env


def _pid_running(pid: int) -> bool:
    stat_path = Path(f"/proc/{pid}/stat")
    if not stat_path.exists():
        return False
    try:
        content = stat_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    rparen = content.rfind(")")
    if rparen == -1:
        return False
    fields = content[rparen + 2 :].split()
    state = fields[0] if fields else ""
    return state not in {"Z", "X"}


def _parent_pid(pid: int) -> int | None:
    status_path = Path(f"/proc/{pid}/status")
    try:
        for line in status_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("PPid:"):
                return int(line.split(":", 1)[1].strip())
    except (OSError, ValueError):
        return None
    return None


async def _wait_for_pids_exit(pids: list[int], timeout: float = 4.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(not _pid_running(pid) for pid in pids):
            return
        await asyncio.sleep(0.05)
    still_alive = [pid for pid in pids if _pid_running(pid)]
    raise AssertionError(f"Orphaned process(es) still running: {still_alive}")


async def _start_proxy_and_session() -> tuple[asyncio.subprocess.Process, int, int]:
    FAKE_GDB.chmod(0o755)
    proxy = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "gdb_mcp.cli",
        "serve",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=ROOT,
        env=_source_env(),
    )
    assert proxy.stdin is not None and proxy.stdout is not None

    async def send(msg: dict) -> None:
        proxy.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        await proxy.stdin.drain()

    async def recv() -> dict:
        raw = await asyncio.wait_for(proxy.stdout.readline(), timeout=10.0)
        assert raw, "proxy closed stdout unexpectedly"
        return json.loads(raw)

    await send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    init_resp = await recv()
    assert init_resp["id"] == 1
    await send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    await send(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "gdb_create_session",
                "arguments": {"gdb_path": str(FAKE_GDB)},
            },
        }
    )
    created_resp = await recv()
    payload = created_resp["result"]["structuredContent"]
    assert payload["ok"], payload
    gdb_pid = int(payload["session"]["gdb_pid"])
    backend_pid = _parent_pid(gdb_pid)
    assert backend_pid is not None and backend_pid > 0
    return proxy, backend_pid, gdb_pid


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux /proc lifecycle test")
class ProcessLifecycleTests(unittest.TestCase):
    def test_sigkill_proxy_cleans_up_backend_and_gdb_without_orphans(self) -> None:
        async def check() -> None:
            proxy, backend_pid, gdb_pid = await _start_proxy_and_session()
            self.assertTrue(_pid_running(backend_pid))
            self.assertTrue(_pid_running(gdb_pid))
            proxy.kill()
            await asyncio.wait_for(proxy.wait(), timeout=5.0)
            await _wait_for_pids_exit([gdb_pid, backend_pid])

        asyncio.run(check())

    def test_sigterm_proxy_cleans_up_backend_and_gdb(self) -> None:
        async def check() -> None:
            proxy, backend_pid, gdb_pid = await _start_proxy_and_session()
            proxy.terminate()
            await asyncio.wait_for(proxy.wait(), timeout=5.0)
            await _wait_for_pids_exit([gdb_pid, backend_pid])

        asyncio.run(check())

    def test_stdin_eof_cleans_up_backend_and_gdb(self) -> None:
        async def check() -> None:
            proxy, backend_pid, gdb_pid = await _start_proxy_and_session()
            assert proxy.stdin is not None
            proxy.stdin.close()
            await asyncio.wait_for(proxy.wait(), timeout=5.0)
            await _wait_for_pids_exit([gdb_pid, backend_pid])

        asyncio.run(check())


if __name__ == "__main__":
    unittest.main()
