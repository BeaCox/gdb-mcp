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
import signal
import sys
from collections.abc import Awaitable, Callable, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult, Tool

from . import __version__
from .config import _env_bool, _env_positive_float
from .observability import logger, parse_log_level
from .prompts import prompt_index, render_prompt
from .resources import RESOURCE_MIME_TYPE, read_reference_resource, resource_index
from .tool_profiles import parse_tool_selection

INSTRUCTIONS = (
    "This is a lazy proxy for gdb-mcp. It exposes gdb-mcp tools immediately, "
    "but starts or connects to the real backend only when a tool is called. "
    "Reuse existing live sessions for follow-up debugging requests; call "
    "gdb_list_sessions before creating a new session when the user refers to "
    "previous debugger state."
)


async def list_proxy_tools(
    profile_value: str | None = None,
    *,
    include_tools: str | Sequence[str] | None = None,
    exclude_tools: str | Sequence[str] | None = None,
    profile_explicit: bool | None = None,
) -> list[Tool]:
    """Return the filtered gdb-mcp tool schema without running an MCP transport."""

    from .server import mcp

    tools = await mcp.list_tools()
    selection = parse_tool_selection(
        profile_value,
        include_tools=include_tools,
        exclude_tools=exclude_tools,
        profile_explicit=profile_explicit,
    )
    return selection.filter_tools(tools)


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
    tool_profile: str = "full"
    tool_profile_explicit: bool = False
    include_tools: tuple[str, ...] = ()
    exclude_tools: tuple[str, ...] = ()
    enable_progress: bool = False
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _stack: AsyncExitStack | None = None
    _session: ClientSession | None = None
    _owner_task: asyncio.Task[None] | None = None
    _stop_event: asyncio.Event | None = None

    @classmethod
    def from_env(cls) -> LazyBackend:
        url = os.getenv("GDB_MCP_BACKEND_URL")
        command_env = os.getenv("GDB_MCP_BACKEND_COMMAND")
        args_env = os.getenv("GDB_MCP_BACKEND_ARGS")
        cwd = os.getenv("GDB_MCP_BACKEND_CWD")
        timeout = _env_positive_float("GDB_MCP_BACKEND_STARTUP_TIMEOUT", 30.0)
        raw_profile = os.getenv("GDB_MCP_TOOL_PROFILE")
        selection = parse_tool_selection(
            raw_profile,
            include_tools=os.getenv("GDB_MCP_TOOLS"),
            exclude_tools=os.getenv("GDB_MCP_EXCLUDE_TOOLS"),
            profile_explicit=bool(raw_profile and raw_profile.strip()),
        )
        enable_progress = _env_bool("GDB_MCP_PROGRESS", False)

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
            tool_profile=selection.profile.canonical_name,
            tool_profile_explicit=selection.profile_explicit,
            include_tools=selection.include_tools,
            exclude_tools=selection.exclude_tools,
            enable_progress=enable_progress,
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
        try:
            return await session.call_tool(
                name,
                arguments or {},
                progress_callback=progress_callback,
            )
        except (
            BrokenPipeError,
            ConnectionResetError,
            EOFError,
            OSError,
            anyio.ClosedResourceError,
            anyio.BrokenResourceError,
        ) as exc:
            logger.emit(
                "warning",
                "proxy.backend_disconnected",
                tool=name,
                error_type=type(exc).__name__,
            )
            await self.close()
            raise

    async def close(self) -> None:
        async with self._lock:
            owner_task = self._owner_task
            stop_event = self._stop_event
            self._owner_task = None
            self._stop_event = None
            self._stack = None
            self._session = None
        if stop_event is not None:
            stop_event.set()
        if owner_task is not None:
            await owner_task

    async def _run_backend_owner(
        self,
        ready: asyncio.Future[ClientSession],
        stop_event: asyncio.Event,
    ) -> None:
        stack = AsyncExitStack()
        self._stack = stack
        try:
            if self.url:
                import httpx2

                http_client = await stack.enter_async_context(
                    httpx2.AsyncClient(timeout=self.startup_timeout)
                )
                read, write = await stack.enter_async_context(
                    streamable_http_client(self.url, http_client=http_client)
                )
            else:
                if not self.command:
                    raise ValueError("backend command is required when no backend URL is set")
                child_env = dict(self.env or {})
                child_env["GDB_MCP_PARENT_PID"] = str(os.getpid())
                params = StdioServerParameters(
                    command=self.command,
                    args=self.args or [],
                    env=child_env,
                    cwd=self.cwd,
                )
                read, write = await stack.enter_async_context(stdio_client(params))

            session = await stack.enter_async_context(ClientSession(read, write))
            await asyncio.wait_for(
                session.initialize(),
                timeout=self.startup_timeout,
            )
            if not ready.done():
                ready.set_result(session)
            await stop_event.wait()
        except BaseException as exc:
            if not ready.done():
                ready.set_exception(exc)
            raise
        finally:
            self._session = None
            self._stack = None
            await stack.aclose()

    async def _ensure_session(self) -> ClientSession:
        if self._session is not None:
            return self._session

        async with self._lock:
            if self._session is not None:
                return self._session

            loop = asyncio.get_running_loop()
            ready: asyncio.Future[ClientSession] = loop.create_future()
            stop_event = asyncio.Event()
            owner_task = asyncio.create_task(self._run_backend_owner(ready, stop_event))
            try:
                session = await ready
            except BaseException:
                stop_event.set()
                try:
                    await owner_task
                except BaseException:
                    pass
                raise

            self._stop_event = stop_event
            self._owner_task = owner_task
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
    loop = asyncio.get_running_loop()
    proxy_task: asyncio.Task[None] | None = None

    def _on_sigterm() -> None:
        if proxy_task is not None and not proxy_task.done():
            proxy_task.cancel()

    sigterm_installed = False
    if hasattr(signal, "SIGTERM"):
        try:
            loop.add_signal_handler(signal.SIGTERM, _on_sigterm)
            sigterm_installed = True
        except (NotImplementedError, RuntimeError):
            pass

    try:
        async with _stdio_lifespan(backend):
            proxy_task = asyncio.create_task(_run_raw_stdio_proxy(backend))
            try:
                await proxy_task
            except asyncio.CancelledError:
                pass
    finally:
        if sigterm_installed:
            loop.remove_signal_handler(signal.SIGTERM)


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

    in_flight: dict[Any, asyncio.Task[None]] = {}
    anonymous_tasks: set[asyncio.Task[None]] = set()

    async def handle_request(raw_line: bytes, req_id: str | int | None) -> None:
        try:
            response = await _dispatch_jsonrpc(
                backend,
                raw_line,
                emit_progress=emit_progress,
            )
            if response is not None:
                await write_message(response)
        except asyncio.CancelledError:
            raise
        finally:
            current = asyncio.current_task()
            if req_id is not None and in_flight.get(req_id) is current:
                in_flight.pop(req_id, None)
            if current is not None:
                anonymous_tasks.discard(current)

    loop = asyncio.get_running_loop()
    stdin_reader: asyncio.StreamReader | None = None
    stdin_transport: asyncio.ReadTransport | None = None
    try:
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        stdin_transport, _ = await loop.connect_read_pipe(
            lambda: protocol,
            sys.stdin.buffer,
        )
        stdin_reader = reader
    except (OSError, NotImplementedError, ValueError):
        stdin_reader = None
        stdin_transport = None

    try:
        while True:
            if stdin_reader is not None:
                line = await stdin_reader.readline()
            else:
                line = await asyncio.to_thread(sys.stdin.buffer.readline)
            if not line:
                return
            line = line.strip()
            if not line:
                continue

            req_id: str | int | None = None
            try:
                parsed = json.loads(line)
            except Exception:
                parsed = None

            if isinstance(parsed, dict):
                if parsed.get("method") == "notifications/cancelled":
                    params = parsed.get("params")
                    if isinstance(params, dict):
                        target_id = params.get("requestId")
                        if (
                            isinstance(target_id, (str, int))
                            and (target_task := in_flight.get(target_id)) is not None
                        ):
                            target_task.cancel()
                    continue
                candidate_id = parsed.get("id")
                if isinstance(candidate_id, (str, int)):
                    req_id = candidate_id

            task = asyncio.create_task(handle_request(line, req_id))
            if req_id is not None:
                in_flight[req_id] = task
            else:
                anonymous_tasks.add(task)
    finally:
        if stdin_transport is not None:
            stdin_transport.close()
        pending = list(in_flight.values()) + list(anonymous_tasks)
        for task in pending:
            if not task.done():
                task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)


async def _dispatch_jsonrpc(
    backend: LazyBackend,
    raw_request: bytes,
    emit_progress: (
        Callable[[str | int, float, float | None, str | None], Awaitable[None]] | None
    ) = None,
) -> dict[str, Any] | None:
    try:
        tool_profile = getattr(backend, "tool_profile", "full")
        tool_profile_explicit = getattr(backend, "tool_profile_explicit", True)
        include_tools = getattr(backend, "include_tools", ())
        exclude_tools = getattr(backend, "exclude_tools", ())
        enable_progress = bool(getattr(backend, "enable_progress", False))
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
            tools = await list_proxy_tools(
                tool_profile,
                include_tools=include_tools,
                exclude_tools=exclude_tools,
                profile_explicit=tool_profile_explicit,
            )
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
            visible_tools = await list_proxy_tools(
                tool_profile,
                include_tools=include_tools,
                exclude_tools=exclude_tools,
                profile_explicit=tool_profile_explicit,
            )
            visible_names = {tool.name for tool in visible_tools}
            if name not in visible_names:
                raise ValueError(
                    f"Tool {name!r} is not available in current tool selection"
                )
            progress_callback = None
            meta = params.get("_meta")
            if (
                enable_progress
                and isinstance(meta, dict)
                and isinstance(meta.get("progressToken"), (str, int))
            ):
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
            "GDB_MCP_TOOL_PROFILE",
            "GDB_MCP_TOOLS",
            "GDB_MCP_EXCLUDE_TOOLS",
            "GDB_MCP_IDLE_SESSION_TTL_SECONDS",
            "GDB_MCP_MAX_RECENT_RECORDS",
            "GDB_MCP_MAX_RECENT_COMMANDS",
            "GDB_MCP_LOG_LEVEL",
            "GDB_MCP_PROGRESS",
            "PYTHONPATH",
        )
        if (value := os.getenv(name)) is not None
    }
    return env or None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lazy stdio proxy for gdb-mcp")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
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
        default=None,
        help="Backend startup/connect timeout in seconds",
    )
    parser.add_argument(
        "--tool-profile",
        default=None,
        help=(
            "Discovered tools: full (default), core, or "
            "advanced:<group>[,<group>]"
        ),
    )
    parser.add_argument(
        "--tools",
        action="append",
        default=None,
        help="Explicitly expose only (or add to profile) comma-separated tool names",
    )
    parser.add_argument(
        "--exclude-tools",
        action="append",
        default=None,
        help="Comma-separated tool names to exclude after profile and --tools",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        default=None,
        help="Forward MCP notifications/progress on stdio (disabled by default)",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        help="Operational stderr log level: off (default), error, warning, info, debug",
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    try:
        raw_env_profile = os.getenv("GDB_MCP_TOOL_PROFILE")
        profile_value = args.tool_profile if args.tool_profile is not None else raw_env_profile
        profile_explicit = (args.tool_profile is not None) or bool(
            raw_env_profile and raw_env_profile.strip()
        )
        include_tools = (
            args.tools if args.tools is not None else os.getenv("GDB_MCP_TOOLS")
        )
        exclude_tools = (
            args.exclude_tools
            if args.exclude_tools is not None
            else os.getenv("GDB_MCP_EXCLUDE_TOOLS")
        )
        selection = parse_tool_selection(
            profile_value,
            include_tools=include_tools,
            exclude_tools=exclude_tools,
            profile_explicit=profile_explicit,
        )
        startup_timeout = (
            args.startup_timeout
            if args.startup_timeout is not None
            else _env_positive_float("GDB_MCP_BACKEND_STARTUP_TIMEOUT", 30.0)
        )
        if startup_timeout <= 0:
            raise ValueError("--startup-timeout must be > 0")
        enable_progress = (
            args.progress
            if args.progress is not None
            else _env_bool("GDB_MCP_PROGRESS", False)
        )
        if args.log_level is not None:
            logger.set_level(parse_log_level(args.log_level))
    except ValueError as exc:
        parser.error(str(exc))
    if args.backend_command:
        command, command_args = _split_env_command(args.backend_command)
    else:
        command = sys.executable
        command_args = ["-m", "gdb_mcp.server"]
    if args.backend_arg:
        command_args.extend(args.backend_arg)

    backend_env = _backend_subprocess_env() or {}
    backend_env["GDB_MCP_TOOL_PROFILE"] = selection.profile.canonical_name
    if selection.include_tools:
        backend_env["GDB_MCP_TOOLS"] = ",".join(selection.include_tools)
    if selection.exclude_tools:
        backend_env["GDB_MCP_EXCLUDE_TOOLS"] = ",".join(selection.exclude_tools)
    if enable_progress:
        backend_env["GDB_MCP_PROGRESS"] = "1"
    backend = LazyBackend(
        command=command,
        args=command_args,
        env=backend_env,
        cwd=args.backend_cwd,
        url=args.backend_url,
        startup_timeout=startup_timeout,
        tool_profile=selection.profile.canonical_name,
        tool_profile_explicit=selection.profile_explicit,
        include_tools=selection.include_tools,
        exclude_tools=selection.exclude_tools,
        enable_progress=enable_progress,
    )
    asyncio.run(run_stdio(backend))


if __name__ == "__main__":
    main()
