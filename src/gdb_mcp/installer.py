"""Installation helpers for supported MCP clients and plugin marketplaces."""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import Literal

ClientName = Literal["claude", "codex"]

MARKETPLACE_SOURCE = "BeaCox/gdb-mcp"
MARKETPLACE_NAME = "beacox"
PLUGIN_NAME = "gdb-mcp"
MCP_SERVER_NAME = "gdb"
RELEASE_TAG = "v0.3.1"
PACKAGE_SOURCE = f"git+https://github.com/BeaCox/gdb-mcp.git@{RELEASE_TAG}"


@dataclass(frozen=True)
class ClientInfo:
    name: ClientName
    command: str
    available: bool
    plugin_install: list[list[str]]
    plugin_uninstall: list[list[str]]
    direct_mcp_install: list[str]
    direct_mcp_uninstall: list[str]


def _uvx_server_command(package_source: str = PACKAGE_SOURCE) -> list[str]:
    return ["uvx", "--from", package_source, "gdb-mcp"]


def client_info(
    name: ClientName,
    *,
    scope: str = "user",
    package_source: str = PACKAGE_SOURCE,
) -> ClientInfo:
    server_command = _uvx_server_command(package_source)
    if name == "claude":
        command = shutil.which("claude") or "claude"
        return ClientInfo(
            name=name,
            command=command,
            available=shutil.which("claude") is not None,
            plugin_install=[
                [command, "plugin", "marketplace", "add", MARKETPLACE_SOURCE],
                [
                    command,
                    "plugin",
                    "install",
                    f"{PLUGIN_NAME}@{MARKETPLACE_NAME}",
                    "--scope",
                    scope,
                ],
            ],
            plugin_uninstall=[
                [
                    command,
                    "plugin",
                    "uninstall",
                    f"{PLUGIN_NAME}@{MARKETPLACE_NAME}",
                    "--scope",
                    scope,
                ]
            ],
            direct_mcp_install=[
                command,
                "mcp",
                "add",
                "--scope",
                scope,
                MCP_SERVER_NAME,
                "--",
                *server_command,
            ],
            direct_mcp_uninstall=[
                command,
                "mcp",
                "remove",
                "--scope",
                scope,
                MCP_SERVER_NAME,
            ],
        )
    if name == "codex":
        command = shutil.which("codex") or "codex"
        return ClientInfo(
            name=name,
            command=command,
            available=shutil.which("codex") is not None,
            plugin_install=[
                [
                    command,
                    "plugin",
                    "marketplace",
                    "add",
                    MARKETPLACE_SOURCE,
                    "--ref",
                    RELEASE_TAG,
                ],
                [command, "plugin", "add", f"{PLUGIN_NAME}@{MARKETPLACE_NAME}"],
            ],
            plugin_uninstall=[
                [command, "plugin", "remove", f"{PLUGIN_NAME}@{MARKETPLACE_NAME}"]
            ],
            direct_mcp_install=[
                command,
                "mcp",
                "add",
                MCP_SERVER_NAME,
                "--",
                *server_command,
            ],
            direct_mcp_uninstall=[
                command,
                "mcp",
                "remove",
                MCP_SERVER_NAME,
            ],
        )
    raise ValueError(f"Unsupported client: {name}")


def detect_clients() -> list[ClientName]:
    return [
        name
        for name in ("claude", "codex")
        if client_info(name).available
    ]


def parse_targets(value: str | None) -> list[ClientName]:
    if value is None or not value.strip() or value.strip() == "auto":
        detected = detect_clients()
        if not detected:
            raise RuntimeError("No supported clients found. Install Claude Code or Codex first.")
        return detected

    targets: list[ClientName] = []
    for raw in value.split(","):
        name = raw.strip().lower()
        if name not in {"claude", "codex"}:
            raise ValueError(f"Unsupported client {name!r}; choose claude, codex, or auto")
        if name not in targets:
            targets.append(name)  # type: ignore[arg-type]
    return targets


def _format_command(command: list[str]) -> str:
    return shlex.join(command)


def _run(
    command: list[str],
    *,
    dry_run: bool,
    allow_existing: bool = False,
) -> None:
    print(f"$ {_format_command(command)}")
    if dry_run:
        return
    result = subprocess.run(command, check=False, text=True, capture_output=True)
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip())
    if result.returncode == 0:
        return
    combined = f"{result.stdout}\n{result.stderr}".lower()
    if allow_existing and any(
        marker in combined
        for marker in ("already exists", "already added", "already configured")
    ):
        return
    raise RuntimeError(
        f"Command failed with exit code {result.returncode}: {_format_command(command)}"
    )


def install(
    targets: list[ClientName],
    *,
    scope: str = "user",
    direct: bool = False,
    dry_run: bool = False,
    package_source: str = PACKAGE_SOURCE,
) -> None:
    for target in targets:
        info = client_info(target, scope=scope, package_source=package_source)
        if not info.available and not dry_run:
            raise RuntimeError(f"{target} executable was not found")
        print(f"Installing gdb-mcp for {target}...")
        if direct:
            _run(info.direct_mcp_install, dry_run=dry_run)
            continue
        for index, command in enumerate(info.plugin_install):
            _run(command, dry_run=dry_run, allow_existing=index == 0)


def uninstall(
    targets: list[ClientName],
    *,
    scope: str = "user",
    direct: bool = False,
    dry_run: bool = False,
) -> None:
    for target in targets:
        info = client_info(target, scope=scope)
        if not info.available and not dry_run:
            raise RuntimeError(f"{target} executable was not found")
        print(f"Uninstalling gdb-mcp from {target}...")
        if direct:
            _run(info.direct_mcp_uninstall, dry_run=dry_run)
            continue
        for command in info.plugin_uninstall:
            _run(command, dry_run=dry_run)


def configuration(package_source: str = PACKAGE_SOURCE) -> dict[str, object]:
    server = {
        "command": "uvx",
        "args": ["--from", package_source, "gdb-mcp"],
    }
    return {
        "claude_code": {
            "mcpServers": {
                MCP_SERVER_NAME: server,
            }
        },
        "codex": {
            "mcp_servers": {
                MCP_SERVER_NAME: server,
            }
        },
    }


def print_configuration(package_source: str = PACKAGE_SOURCE) -> None:
    print(json.dumps(configuration(package_source), indent=2))


def list_clients() -> None:
    for name in ("claude", "codex"):
        info = client_info(name)
        status = "available" if info.available else "not found"
        print(f"{name}: {status}")
