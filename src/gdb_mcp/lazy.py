"""Lazy MCP proxy for gdb-mcp.

The proxy exposes the same tool schema as the full server, but delays starting
the real backend until the first tool call. This keeps MCP client startup cheap
while preserving normal multi-session behavior in the backend SessionManager.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shlex
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from collections.abc import Awaitable, Callable
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.types import CallToolResult, Tool

from . import __version__
from .prompts import prompt_index, render_prompt
from .resources import RESOURCE_MIME_TYPE, read_reference_resource, resource_index

INSTRUCTIONS = (
    "This is a lazy proxy for gdb-mcp. It exposes gdb-mcp tools immediately, "
    "but starts or connects to the real backend only when a tool is called. "
    "Reuse existing live sessions for follow-up debugging requests; call "
    "gdb_list_sessions before creating a new session when the user refers to "
    "previous debugger state."
)


async def list_proxy_tools() -> list[Tool]:
    """Return the full gdb-mcp tool schema without running an MCP transport."""

    from .server import mcp

    return await mcp.list_tools()


def list_proxy_resources() -> list[dict[str, Any]]:
    """Return the backend's static resource metadata without starting it."""

    return [
        {
            "uri": resource["uri"],
            "name": resource["name"],
            "title": resource["title"],
            "description": resource["description"],
            "mimeType": RESOURCE_MIME_TYPE,
        }
        for resource in resource_index()
    ]


def read_proxy_resource(uri: str) -> dict[str, Any]:
    """Return one static resource in the MCP ``resources/read`` result shape."""

    if not isinstance(uri, str) or not uri:
        raise ValueError("resources/read requires a resource URI")

    try:
        content = read_reference_resource(uri)
    except KeyError as exc:
        raise ValueError(f"Unknown resource: {uri}") from exc

    return {
        "contents": [
            {
                "uri": uri,
                "mimeType": RESOURCE_MIME_TYPE,
                "text": json.dumps(content, indent=2),
            }
        ]
    }


def _split_env_command(value: str) -> tuple[str, list[str]]:
    parts = shlex.split(value)
    if not parts:
        raise ValueError("backend command must not be empty")
    return parts[0], parts[1:]


@dataclass
class LazyBackend:
    """Manages one lazily-created MCP client connection to the real backend."""

    command: str | None = None
    args: list[str] | None = None
    env: dict[str, str] | None = None
    cwd: str | None = None
    url: str | None = None
    startup_timeout: float = 30.0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _stack: AsyncExitStack | None = None
    _session: ClientSession | None = None

    @classmethod
    def from_env(cls) -> LazyBackend:
        url = os.getenv("GDB_MCP_BACKEND_URL")
        command_env = os.getenv("GDB_MCP_BACKEND_COMMAND")
        args_env = os.getenv("GDB_MCP_BACKEND_ARGS")
        cwd = os.getenv("GDB_MCP_BACKEND_CWD")
        timeout = float(os.getenv("GDB_MCP_BACKEND_STARTUP_TIMEOUT", "30"))

        command: str | None = None
        args: list[str] | None = None
        if command_env:
            command, args = _split_env_command(command_env)
        else:
            command = sys.executable
            args = ["-m", "gdb_mcp.server"]

        if args_env:
            args = [*(args or []), *shlex.split(args_env)]

        return cls(
            command=command,
            args=args,
            env=_backend_subprocess_env(),
            cwd=cwd,
            url=url,
            startup_timeout=timeout,
        )

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None,
        progress_callback: (
            Callable[[float, float | None, str | None], Awaitable[None]] | None
        ) = None,
    ) -> CallToolResult:
        session = await self._ensure_session()
        return await session.call_tool(
            name,
            arguments or {},
            progress_callback=progress_callback,
        )

    async def close(self) -> None:
        async with self._lock:
            if self._stack is not None:
                await self._stack.aclose()
            self._stack = None
            self._session = None

    async def _ensure_session(self) -> ClientSession:
        if self._session is not None:
            return self._session

        async with self._lock:
            if self._session is not None:
                return self._session

            stack = AsyncExitStack()
            try:
                if self.url:
                    read, write, _ = await stack.enter_async_context(
                        streamablehttp_client(self.url, timeout=self.startup_timeout)
                    )
                else:
                    if not self.command:
                        raise ValueError("backend command is required when no backend URL is set")
                    params = StdioServerParameters(
                        command=self.command,
                        args=self.args or [],
                        env=self.env,
                        cwd=self.cwd,
                    )
                    read, write = await stack.enter_async_context(stdio_client(params))

                session = await stack.enter_async_context(ClientSession(read, write))
                await asyncio.wait_for(
                    session.initialize(),
                    timeout=self.startup_timeout,
                )
            except BaseException:
                await stack.aclose()
                raise

            self._stack = stack
            self._session = session
            return session


@asynccontextmanager
async def _stdio_lifespan(backend: LazyBackend):
    try:
        yield
    finally:
        await backend.close()


async def run_stdio(backend: LazyBackend | None = None) -> None:
    backend = backend or LazyBackend.from_env()
    async with _stdio_lifespan(backend):
        await _run_raw_stdio_proxy(backend)


async def _run_raw_stdio_proxy(backend: LazyBackend) -> None:
    output_lock = asyncio.Lock()

    async def write_message(message: dict[str, Any]) -> None:
        encoded = json.dumps(message, separators=(",", ":")).encode("utf-8")
        async with output_lock:
            sys.stdout.buffer.write(encoded + b"\n")
            sys.stdout.buffer.flush()

    async def emit_progress(
        token: str | int,
        progress: float,
        total: float | None,
        message: str | None,
    ) -> None:
        params: dict[str, Any] = {"progressToken": token, "progress": progress}
        if total is not None:
            params["total"] = total
        if message is not None:
            params["message"] = message
        await write_message(
            {"jsonrpc": "2.0", "method": "notifications/progress", "params": params}
        )

    while True:
        line = await asyncio.to_thread(sys.stdin.buffer.readline)
        if not line:
            return
        line = line.strip()
        if not line:
            continue
        response = await _dispatch_jsonrpc(backend, line, emit_progress=emit_progress)
        if response is None:
            continue
        await write_message(response)


async def _dispatch_jsonrpc(
    backend: LazyBackend,
    raw_request: bytes,
    emit_progress: (
        Callable[[str | int, float, float | None, str | None], Awaitable[None]] | None
    ) = None,
) -> dict[str, Any] | None:
    try:
        request = json.loads(raw_request)
        if not isinstance(request, dict):
            raise ValueError("request must be a JSON object")
        method = request.get("method")
        request_id = request.get("id")
        params = request.get("params") or {}
        if not isinstance(params, dict):
            raise ValueError("params must be a JSON object")

        if method == "initialize":
            result = {
                "protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": {
                    "experimental": {},
                    "prompts": {"listChanged": False},
                    "resources": {"subscribe": False, "listChanged": False},
                    "tools": {"listChanged": False},
                },
                "serverInfo": {"name": "gdb-mcp", "version": __version__},
                "instructions": INSTRUCTIONS,
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            tools = await list_proxy_tools()
            result = {
                "tools": [
                    tool.model_dump(mode="json", by_alias=True, exclude_none=True)
                    for tool in tools
                ]
            }
        elif method == "tools/call":
            name = params.get("name")
            if not isinstance(name, str) or not name:
                raise ValueError("tools/call requires a tool name")
            arguments = params.get("arguments")
            if arguments is not None and not isinstance(arguments, dict):
                raise ValueError("tools/call arguments must be an object")
            progress_callback = None
            meta = params.get("_meta")
            if isinstance(meta, dict) and isinstance(meta.get("progressToken"), (str, int)):
                if emit_progress is not None:
                    outer_token = meta["progressToken"]

                    async def progress_callback(
                        progress: float,
                        total: float | None,
                        message: str | None,
                    ) -> None:
                        await emit_progress(outer_token, progress, total, message)

            result_obj = await backend.call_tool(
                name,
                arguments or {},
                progress_callback=progress_callback,
            )
            result = result_obj.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
        elif method == "resources/list":
            result = {"resources": list_proxy_resources()}
        elif method == "resources/read":
            result = read_proxy_resource(params.get("uri"))
        elif method == "resources/templates/list":
            result = {"resourceTemplates": []}
        elif method == "prompts/list":
            result = {"prompts": prompt_index()}
        elif method == "prompts/get":
            name = params.get("name")
            if not isinstance(name, str) or not name:
                raise ValueError("prompts/get requires a prompt name")
            arguments = params.get("arguments")
            if arguments is not None and not isinstance(arguments, dict):
                raise ValueError("prompts/get arguments must be an object")
            result = render_prompt(name, arguments)
        elif isinstance(method, str) and method.startswith("notifications/"):
            return None
        else:
            if request_id is None:
                return None
            return _jsonrpc_error(request_id, -32601, f"Method not found: {method}")

        if request_id is None:
            return None
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except Exception as exc:
        request_id = None
        try:
            parsed = json.loads(raw_request)
            if isinstance(parsed, dict):
                request_id = parsed.get("id")
        except Exception:
            pass
        if request_id is None:
            return None
        return _jsonrpc_error(request_id, -32000, str(exc))


def _jsonrpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _backend_subprocess_env() -> dict[str, str] | None:
    env = {
        name: value
        for name in (
            "GDB_MCP_ALLOW_UNSAFE",
            "GDB_MCP_MAX_SESSIONS",
            "GDB_MCP_OUTPUT_LIMIT_CHARS",
            "PYTHONPATH",
        )
        if (value := os.getenv(name)) is not None
    }
    return env or None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lazy stdio proxy for gdb-mcp")
    parser.add_argument(
        "--backend-url",
        default=os.getenv("GDB_MCP_BACKEND_URL"),
        help="Connect to an existing Streamable HTTP backend instead of spawning one",
    )
    parser.add_argument(
        "--backend-command",
        default=os.getenv("GDB_MCP_BACKEND_COMMAND"),
        help=(
            "Command used to spawn a stdio backend; defaults to this Python "
            "running gdb_mcp.server"
        ),
    )
    parser.add_argument(
        "--backend-arg",
        action="append",
        default=None,
        help="Argument for the spawned backend command; may be repeated",
    )
    parser.add_argument(
        "--backend-cwd",
        default=os.getenv("GDB_MCP_BACKEND_CWD"),
        help="Working directory for the spawned stdio backend",
    )
    parser.add_argument(
        "--startup-timeout",
        type=float,
        default=float(os.getenv("GDB_MCP_BACKEND_STARTUP_TIMEOUT", "30")),
        help="Backend startup/connect timeout in seconds",
    )
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    if args.backend_command:
        command, command_args = _split_env_command(args.backend_command)
    else:
        command = sys.executable
        command_args = ["-m", "gdb_mcp.server"]
    if args.backend_arg:
        command_args.extend(args.backend_arg)

    backend = LazyBackend(
        command=command,
        args=command_args,
        env=_backend_subprocess_env(),
        cwd=args.backend_cwd,
        url=args.backend_url,
        startup_timeout=args.startup_timeout,
    )
    asyncio.run(run_stdio(backend))


if __name__ == "__main__":
    main()
