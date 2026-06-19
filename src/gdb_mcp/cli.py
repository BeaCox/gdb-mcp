"""User-facing command-line entry point for gdb-mcp."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from .lazy import LazyBackend, _split_env_command, run_stdio


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Lazy stdio MCP proxy and installer for gdb-mcp"
    )
    lifecycle = parser.add_mutually_exclusive_group()
    lifecycle.add_argument(
        "--install",
        nargs="?",
        const="auto",
        metavar="CLIENTS",
        help="Install for detected clients or a comma-separated list",
    )
    lifecycle.add_argument(
        "--uninstall",
        nargs="?",
        const="auto",
        metavar="CLIENTS",
        help="Uninstall from detected clients or a comma-separated list",
    )
    parser.add_argument(
        "--direct",
        action="store_true",
        help="Configure MCP directly instead of installing marketplace plugins",
    )
    parser.add_argument(
        "--scope",
        choices=["user", "project", "local"],
        default="user",
        help="Client configuration scope where supported",
    )
    parser.add_argument(
        "--source",
        default=None,
        help="Override the Python package source used by direct installs",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print installation commands without running them",
    )
    parser.add_argument(
        "--list-clients",
        action="store_true",
        help="List supported clients and whether they are installed",
    )
    parser.add_argument(
        "--config",
        "--print-config",
        dest="print_config",
        action="store_true",
        help="Print portable MCP client configuration and exit",
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
        default=float(os.getenv("GDB_MCP_BACKEND_STARTUP_TIMEOUT", "30")),
        help="Backend startup/connect timeout in seconds",
    )
    parser.add_argument(
        "--unsafe",
        action="store_true",
        help="Enable unrestricted backend gdb_execute commands",
    )
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=None,
        help="Maximum live backend GDB sessions; 0 means unlimited",
    )
    parser.add_argument(
        "--output-limit-chars",
        type=int,
        default=None,
        help="Approximate backend output limit per tool result",
    )
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    from .installer import (
        PACKAGE_SOURCE,
        install,
        list_clients,
        parse_targets,
        print_configuration,
        uninstall,
    )

    package_source = args.source or PACKAGE_SOURCE
    if args.list_clients:
        list_clients()
        return
    if args.print_config:
        print_configuration(package_source)
        return
    if args.install is not None:
        install(
            parse_targets(args.install),
            scope=args.scope,
            direct=args.direct,
            dry_run=args.dry_run,
            package_source=package_source,
        )
        return
    if args.uninstall is not None:
        uninstall(
            parse_targets(args.uninstall),
            scope=args.scope,
            direct=args.direct,
            dry_run=args.dry_run,
        )
        return

    if args.backend_command:
        command, command_args = _split_env_command(args.backend_command)
    else:
        command = sys.executable
        command_args = ["-m", "gdb_mcp.server"]
    if args.backend_arg:
        command_args.extend(args.backend_arg)
    if not args.backend_url:
        if args.unsafe:
            command_args.append("--unsafe")
        if args.max_sessions is not None:
            command_args.extend(["--max-sessions", str(args.max_sessions)])
        if args.output_limit_chars is not None:
            command_args.extend(["--output-limit-chars", str(args.output_limit_chars)])

    backend = LazyBackend(
        command=command,
        args=command_args,
        cwd=args.backend_cwd,
        url=args.backend_url,
        startup_timeout=args.startup_timeout,
    )
    asyncio.run(run_stdio(backend))


if __name__ == "__main__":
    main()
