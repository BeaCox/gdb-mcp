"""User-facing command-line entry point for gdb-mcp."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections.abc import Sequence

from . import __version__
from .config import _env_positive_float
from .lazy import LazyBackend, _backend_subprocess_env, _split_env_command, run_stdio
from .observability import logger, parse_log_level
from .tool_profiles import parse_tool_selection

_SUBCOMMANDS = (
    "serve",
    "serve-http",
    "backend",
    "install",
    "uninstall",
    "config",
    "clients",
    "doctor",
)


def _add_proxy_options(parser: argparse.ArgumentParser) -> None:
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
        "--idle-session-ttl",
        type=float,
        default=None,
        help="Optional idle session TTL in seconds for the spawned backend",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        help="Operational stderr log level: off (default), error, warning, info, debug",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        default=None,
        help="Forward MCP notifications/progress on stdio (disabled by default)",
    )


def _add_backend_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--unsafe", action="store_true", help="Enable unrestricted gdb_execute")
    parser.add_argument(
        "--max-sessions",
        type=int,
        default=None,
        help="Maximum live GDB sessions; 0 means unlimited",
    )
    parser.add_argument(
        "--output-limit-chars",
        type=int,
        default=None,
        help="Approximate output limit per tool result",
    )
    parser.add_argument(
        "--tool-profile",
        default=None,
        help="Discovered tools: full (default), core, or advanced:<group>[,<group>]",
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
        "--idle-session-ttl",
        type=float,
        default=None,
        help="Optional idle session TTL in seconds (disabled by default)",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        help="Operational stderr log level: off (default), error, warning, info, debug",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        default=None,
        help="Enable MCP notifications/progress (disabled by default)",
    )


def _build_subcommand_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gdb-mcp",
        description="Lazy stdio MCP proxy, installer, and diagnostics for gdb-mcp",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="subcommand", metavar="COMMAND")

    serve_parser = subparsers.add_parser(
        "serve",
        help="Run the lazy stdio MCP proxy (default)",
    )
    _add_proxy_options(serve_parser)

    http_parser = subparsers.add_parser(
        "serve-http",
        help="Run the standalone Streamable HTTP or SSE backend server",
    )
    http_parser.add_argument(
        "--transport",
        choices=["streamable-http", "sse"],
        default="streamable-http",
        help="HTTP MCP transport (default: streamable-http)",
    )
    http_parser.add_argument("--host", default="127.0.0.1", help="HTTP bind host")
    http_parser.add_argument("--port", type=int, default=8000, help="HTTP bind port")
    http_parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Acknowledge a protected non-loopback HTTP deployment",
    )
    http_parser.add_argument(
        "--allow-unsafe-over-http",
        action="store_true",
        help="Allow unsafe tools on an authenticated non-loopback HTTP deployment",
    )
    http_parser.add_argument("--http-auth-token", default=None)
    http_parser.add_argument("--http-auth-issuer-url", default=None)
    http_parser.add_argument("--http-auth-resource-url", default=None)
    http_parser.add_argument("--http-allowed-host", action="append", default=None)
    http_parser.add_argument("--http-allowed-origin", action="append", default=None)
    _add_backend_common_options(http_parser)

    subparsers.add_parser("backend")  # hidden internal backend entry point

    install_parser = subparsers.add_parser(
        "install",
        help="Install gdb-mcp for detected or named MCP clients",
    )
    install_parser.add_argument(
        "clients",
        nargs="?",
        default="auto",
        help="Client list (claude,codex) or 'auto' (default)",
    )
    install_parser.add_argument(
        "--direct",
        action="store_true",
        help="Configure MCP directly instead of installing marketplace plugins",
    )
    install_parser.add_argument(
        "--scope",
        choices=["user", "project", "local"],
        default="user",
        help="Client configuration scope where supported",
    )
    install_parser.add_argument(
        "--source",
        default=None,
        help="Override the Python package source used by direct installs",
    )
    install_parser.add_argument(
        "--installed",
        action="store_true",
        help="Register a locally installed `gdb-mcp` command instead of `uvx`",
    )
    install_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print installation commands without running them",
    )

    uninstall_parser = subparsers.add_parser(
        "uninstall",
        help="Uninstall gdb-mcp from detected or named MCP clients",
    )
    uninstall_parser.add_argument(
        "clients",
        nargs="?",
        default="auto",
        help="Client list (claude,codex) or 'auto' (default)",
    )
    uninstall_parser.add_argument(
        "--direct",
        action="store_true",
        help="Remove direct MCP registration instead of marketplace plugins",
    )
    uninstall_parser.add_argument(
        "--scope",
        choices=["user", "project", "local"],
        default="user",
        help="Client configuration scope where supported",
    )
    uninstall_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print uninstall commands without running them",
    )

    config_parser = subparsers.add_parser(
        "config",
        help="Print portable MCP client configuration JSON",
    )
    config_parser.add_argument(
        "client",
        nargs="?",
        default=None,
        help="Optional client name: claude, codex, antigravity (agy), cursor, vscode, windsurf",
    )
    config_parser.add_argument(
        "--source",
        default=None,
        help="Override the Python package source used in generated config",
    )
    config_parser.add_argument(
        "--installed",
        action="store_true",
        help="Emit a direct `gdb-mcp` command instead of `uvx`",
    )

    subparsers.add_parser("clients", help="List supported clients and availability")

    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Check GDB, gdbserver, rr, kernel ptrace/perf settings, and clients",
    )
    doctor_parser.add_argument(
        "--json",
        action="store_true",
        help="Print structured JSON output",
    )

    return parser


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gdb-mcp",
        description="Lazy stdio MCP proxy and installer for gdb-mcp",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    lifecycle = parser.add_mutually_exclusive_group()
    lifecycle.add_argument(
        "--install",
        nargs="?",
        const="auto",
        metavar="CLIENTS",
        help="Deprecated: use 'gdb-mcp install'",
    )
    lifecycle.add_argument(
        "--uninstall",
        nargs="?",
        const="auto",
        metavar="CLIENTS",
        help="Deprecated: use 'gdb-mcp uninstall'",
    )
    parser.add_argument(
        "--direct",
        action="store_true",
        help="Configure MCP directly instead of installing marketplace plugins",
    )
    parser.add_argument(
        "--scope",
        choices=["user", "project", "local"],
        default=None,
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
        help="Deprecated: use 'gdb-mcp clients'",
    )
    parser.add_argument(
        "--config",
        "--print-config",
        dest="print_config",
        nargs="?",
        const="__all__",
        default=None,
        metavar="CLIENT",
        help="Deprecated: use 'gdb-mcp config [CLIENT]'",
    )
    _add_proxy_options(parser)
    return parser


def _warn_deprecated(old: str, new: str) -> None:
    print(f"Warning: {old} is deprecated; use '{new}'.", file=sys.stderr)


def _has_server_flags(args: argparse.Namespace, raw_argv: Sequence[str]) -> list[str]:
    found: list[str] = []
    if args.unsafe:
        found.append("--unsafe")
    if args.max_sessions is not None:
        found.append("--max-sessions")
    if args.output_limit_chars is not None:
        found.append("--output-limit-chars")
    if args.idle_session_ttl is not None:
        found.append("--idle-session-ttl")
    if args.tool_profile is not None:
        found.append("--tool-profile")
    if args.tools is not None:
        found.append("--tools")
    if args.exclude_tools is not None:
        found.append("--exclude-tools")
    if args.progress is not None:
        found.append("--progress")
    if args.backend_arg:
        found.append("--backend-arg")
    if args.startup_timeout is not None:
        found.append("--startup-timeout")
    if args.log_level is not None:
        found.append("--log-level")
    if "--backend-url" in raw_argv or any(
        item.startswith("--backend-url=") for item in raw_argv
    ):
        found.append("--backend-url")
    if "--backend-command" in raw_argv or any(
        item.startswith("--backend-command=") for item in raw_argv
    ):
        found.append("--backend-command")
    if "--backend-cwd" in raw_argv or any(
        item.startswith("--backend-cwd=") for item in raw_argv
    ):
        found.append("--backend-cwd")
    return found


def _has_installer_modifiers(args: argparse.Namespace) -> list[str]:
    found: list[str] = []
    if args.direct:
        found.append("--direct")
    if args.scope is not None:
        found.append("--scope")
    if args.source is not None:
        found.append("--source")
    if args.dry_run:
        found.append("--dry-run")
    return found


def _run_serve(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    try:
        from .config import ServerConfig

        env_config = ServerConfig.from_env()
        raw_env_profile = os.getenv("GDB_MCP_TOOL_PROFILE")
        profile_value = (
            args.tool_profile if args.tool_profile is not None else raw_env_profile
        )
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
            else env_config.progress_notifications
        )
        if args.log_level is not None:
            logger.set_level(parse_log_level(args.log_level))
        else:
            logger.set_level(env_config.log_level)
    except ValueError as exc:
        parser.error(str(exc))

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
        if args.idle_session_ttl is not None:
            command_args.extend(["--idle-session-ttl", str(args.idle_session_ttl)])
        if args.log_level is not None:
            command_args.extend(["--log-level", parse_log_level(args.log_level)])
        if args.progress:
            command_args.append("--progress")

    backend_env = _backend_subprocess_env() or {}
    backend_env["GDB_MCP_TOOL_PROFILE"] = selection.profile.canonical_name
    if selection.include_tools:
        backend_env["GDB_MCP_TOOLS"] = ",".join(selection.include_tools)
    if selection.exclude_tools:
        backend_env["GDB_MCP_EXCLUDE_TOOLS"] = ",".join(selection.exclude_tools)
    if enable_progress:
        backend_env["GDB_MCP_PROGRESS"] = "1"
    if args.log_level is not None:
        backend_env["GDB_MCP_LOG_LEVEL"] = parse_log_level(args.log_level)

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


def _run_serve_http(args: argparse.Namespace) -> None:
    from . import server

    backend_argv = [
        "--transport",
        args.transport,
        "--host",
        args.host,
        "--port",
        str(args.port),
    ]
    if args.allow_remote:
        backend_argv.append("--allow-remote")
    if args.allow_unsafe_over_http:
        backend_argv.append("--allow-unsafe-over-http")
    if args.http_auth_token is not None:
        backend_argv.extend(["--http-auth-token", args.http_auth_token])
    if args.http_auth_issuer_url is not None:
        backend_argv.extend(["--http-auth-issuer-url", args.http_auth_issuer_url])
    if args.http_auth_resource_url is not None:
        backend_argv.extend(["--http-auth-resource-url", args.http_auth_resource_url])
    for host in args.http_allowed_host or []:
        backend_argv.extend(["--http-allowed-host", host])
    for origin in args.http_allowed_origin or []:
        backend_argv.extend(["--http-allowed-origin", origin])
    if args.unsafe:
        backend_argv.append("--unsafe")
    if args.max_sessions is not None:
        backend_argv.extend(["--max-sessions", str(args.max_sessions)])
    if args.output_limit_chars is not None:
        backend_argv.extend(["--output-limit-chars", str(args.output_limit_chars)])
    if args.tool_profile is not None:
        backend_argv.extend(["--tool-profile", args.tool_profile])
    for value in args.tools or []:
        backend_argv.extend(["--tools", value])
    for value in args.exclude_tools or []:
        backend_argv.extend(["--exclude-tools", value])
    if args.idle_session_ttl is not None:
        backend_argv.extend(["--idle-session-ttl", str(args.idle_session_ttl)])
    if args.log_level is not None:
        backend_argv.extend(["--log-level", args.log_level])
    if args.progress:
        backend_argv.append("--progress")
    server.main(backend_argv)


def main(argv: Sequence[str] | None = None) -> None:
    raw_argv = list(sys.argv[1:] if argv is None else argv)

    if raw_argv and raw_argv[0] in _SUBCOMMANDS:
        subcommand = raw_argv[0]
        if subcommand == "backend":
            from . import server

            server.main(raw_argv[1:])
            return

        parser = _build_subcommand_parser()
        args = parser.parse_args(raw_argv)
        if args.subcommand == "serve":
            _run_serve(args, parser)
            return
        if args.subcommand == "serve-http":
            _run_serve_http(args)
            return
        if args.subcommand == "doctor":
            from .doctor import run_doctor

            raise SystemExit(run_doctor(as_json=args.json))

        from .installer import (
            PACKAGE_SOURCE,
            install,
            list_clients,
            parse_targets,
            print_configuration,
            uninstall,
        )

        if args.subcommand == "clients":
            list_clients()
            return
        if args.subcommand == "config":
            try:
                print_configuration(
                    args.source or PACKAGE_SOURCE,
                    client=args.client,
                    installed=args.installed,
                )
            except ValueError as exc:
                parser.error(str(exc))
            return
        if args.subcommand == "install":
            try:
                install(
                    parse_targets(args.clients),
                    scope=args.scope,
                    direct=args.direct,
                    dry_run=args.dry_run,
                    package_source=args.source or PACKAGE_SOURCE,
                    installed=args.installed,
                )
            except ValueError as exc:
                parser.error(str(exc))
            return
        if args.subcommand == "uninstall":
            try:
                uninstall(
                    parse_targets(args.clients),
                    scope=args.scope,
                    direct=args.direct,
                    dry_run=args.dry_run,
                )
            except ValueError as exc:
                parser.error(str(exc))
            return

    if not raw_argv or any(flag in raw_argv for flag in ("-h", "--help", "--version")):
        if len(raw_argv) == 1 and raw_argv[0] in {"-h", "--help", "--version"}:
            _build_subcommand_parser().parse_args(raw_argv)
            return

    parser = _build_parser()
    args = parser.parse_args(raw_argv)

    lifecycle_selected = (
        args.list_clients
        or args.print_config is not None
        or args.install is not None
        or args.uninstall is not None
    )
    server_flags = _has_server_flags(args, raw_argv)
    if lifecycle_selected and server_flags:
        parser.error(
            "Cannot combine lifecycle flags (--install/--uninstall/--print-config/"
            "--list-clients) with server options "
            f"({', '.join(server_flags)}); use subcommands such as "
            "'gdb-mcp install' or 'gdb-mcp serve'."
        )

    installer_modifiers = _has_installer_modifiers(args)
    if not lifecycle_selected and installer_modifiers:
        parser.error(
            f"{', '.join(installer_modifiers)} requires --install/--uninstall "
            "(or use 'gdb-mcp install' / 'gdb-mcp config')."
        )

    if lifecycle_selected:
        from .installer import (
            PACKAGE_SOURCE,
            install,
            list_clients,
            parse_targets,
            print_configuration,
            uninstall,
        )

        package_source = args.source or PACKAGE_SOURCE
        scope = args.scope or "user"
        if args.list_clients:
            _warn_deprecated("--list-clients", "gdb-mcp clients")
            list_clients()
            return
        if args.print_config is not None:
            _warn_deprecated("--print-config/--config", "gdb-mcp config")
            client = None if args.print_config == "__all__" else args.print_config
            try:
                print_configuration(package_source, client=client)
            except ValueError as exc:
                parser.error(str(exc))
            return
        if args.install is not None:
            _warn_deprecated("--install", "gdb-mcp install")
            try:
                install(
                    parse_targets(args.install),
                    scope=scope,
                    direct=args.direct,
                    dry_run=args.dry_run,
                    package_source=package_source,
                )
            except ValueError as exc:
                parser.error(str(exc))
            return
        if args.uninstall is not None:
            _warn_deprecated("--uninstall", "gdb-mcp uninstall")
            try:
                uninstall(
                    parse_targets(args.uninstall),
                    scope=scope,
                    direct=args.direct,
                    dry_run=args.dry_run,
                )
            except ValueError as exc:
                parser.error(str(exc))
            return

    _run_serve(args, parser)


if __name__ == "__main__":
    main()
