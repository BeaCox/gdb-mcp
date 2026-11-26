# Transports, CLI, Environment Variables, and Shutdown

## Subcommands

```text
gdb-mcp [serve]            # Default lazy stdio MCP proxy
gdb-mcp serve-http         # Standalone Streamable HTTP or SSE backend
gdb-mcp install [clients]  # Configure Claude Code or Codex
gdb-mcp uninstall [clients]
gdb-mcp config [client]    # Print JSON for claude, codex, antigravity (agy), cursor, vscode, windsurf
gdb-mcp clients            # List supported clients and CLI availability
gdb-mcp doctor [--json]    # Verify GDB, gdbserver, rr, ptrace_scope, perf_event_paranoid, container caps
```

Legacy top-level flags (`--install`, `--uninstall`, `--print-config`,
`--list-clients`) and `gdb-mcp-backend` remain supported for one release cycle
with deprecation warnings on `stderr`. Combining lifecycle flags with server
flags (such as `gdb-mcp --install --unsafe`) or passing `--direct` alone is
rejected at startup.

## Lazy Stdio Proxy

`gdb-mcp` (and `gdb-mcp serve`) exposes `initialize`, `ping`, `tools/list`,
`resources/*`, and `prompts/*` immediately without starting GDB or spawning the
backend process. The backend is started only on the first `tools/call`.

Use `--tool-profile`, `--tools`, and `--exclude-tools` to restrict the exposed
surface:

```bash
gdb-mcp --tool-profile core
gdb-mcp --tool-profile advanced:binary_analysis --exclude-tools gdb_elf_info
gdb-mcp --tools gdb_create_session,gdb_run_and_context,gdb_context,gdb_close_session
```

When `--tools` is given without `--tool-profile` (and without
`GDB_MCP_TOOL_PROFILE`), only the named tools are exposed. When combined with
`--tool-profile`, `--tools` adds to the profile and `--exclude-tools` removes
from it (`--exclude-tools` always wins). Unknown tool names fail at startup.

## Stdio Progress Notifications

`notifications/progress` is **disabled by default** on stdio (`--progress` or
`GDB_MCP_PROGRESS=1` enables it). Fast operations (<100 ms) can otherwise
deliver a progress notification in the same stdio chunk as the JSON-RPC response,
causing clients such as Claude Code to reject an already-retired `progressToken`
and close the connection.

## Standalone Streamable HTTP Backend

Run an isolated HTTP backend and point a stdio proxy (or HTTP MCP client) at it:

```bash
gdb-mcp serve-http --host 127.0.0.1 --port 8000
GDB_MCP_BACKEND_URL=http://127.0.0.1:8000/mcp gdb-mcp
```

Non-loopback HTTP listeners (`--host 0.0.0.0`, etc.) are rejected unless all of
these are configured explicitly:

1. `--allow-remote` (or `GDB_MCP_ALLOW_REMOTE=1`)
2. `--http-auth-token` / `GDB_MCP_HTTP_AUTH_TOKEN`
3. `--http-auth-issuer-url` / `GDB_MCP_HTTP_AUTH_ISSUER_URL`
4. `--http-auth-resource-url` / `GDB_MCP_HTTP_AUTH_RESOURCE_URL`
5. `--http-allowed-host`

Unsafe tools remain disabled on non-loopback HTTP unless
`--allow-unsafe-over-http` (`GDB_MCP_ALLOW_UNSAFE_OVER_HTTP=1`) is also set.

## Configuration Precedence and Environment Variables

CLI flags override environment variables. Invalid environment variable values
fail immediately at startup with exit code 2 instead of silently falling back
to defaults.

| CLI Flag | Environment Variable | Default | Notes |
| --- | --- | --- | --- |
| `--unsafe` | `GDB_MCP_ALLOW_UNSAFE` | `false` | Enable `gdb_execute`, mutation, and `init_file` |
| `--max-sessions` | `GDB_MCP_MAX_SESSIONS` | `8` | Integer `>= 0` (`0` = unlimited) |
| `--output-limit-chars` | `GDB_MCP_OUTPUT_LIMIT_CHARS` | `100000` | Integer `>= 10000` |
| `--tool-profile` | `GDB_MCP_TOOL_PROFILE` | `full` | `full`, `core`, or `advanced:<group>[,...]` |
| `--tools` | `GDB_MCP_TOOLS` | unset | Comma-separated tool names |
| `--exclude-tools` | `GDB_MCP_EXCLUDE_TOOLS` | unset | Comma-separated excluded tool names |
| `--idle-session-ttl` | `GDB_MCP_IDLE_SESSION_TTL_SECONDS` | unset | Finite number `>= 0` (`0` disables) |
| `--log-level` | `GDB_MCP_LOG_LEVEL` | `off` | `off`, `error`, `warning`, `info`, `debug` |
| `--progress` | `GDB_MCP_PROGRESS` | `false` | Boolean (`1/0`, `true/false`, `yes/no`, `on/off`) |
| `--backend-url` | `GDB_MCP_BACKEND_URL` | unset | Connect proxy to Streamable HTTP backend |
| `--backend-command` | `GDB_MCP_BACKEND_COMMAND` | python backend | Custom stdio backend command |
| `--backend-cwd` | `GDB_MCP_BACKEND_CWD` | unset | Working directory for spawned backend |
| `--startup-timeout` | `GDB_MCP_BACKEND_STARTUP_TIMEOUT` | `30` | Finite number `> 0` seconds |
| `--allow-remote` | `GDB_MCP_ALLOW_REMOTE` | `false` | Acknowledge non-loopback HTTP listener |
| `--allow-unsafe-over-http` | `GDB_MCP_ALLOW_UNSAFE_OVER_HTTP` | `false` | Allow unsafe tools over remote HTTP |
| `--http-auth-token` | `GDB_MCP_HTTP_AUTH_TOKEN` | unset | Bearer token for HTTP clients |
| `--http-auth-issuer-url` | `GDB_MCP_HTTP_AUTH_ISSUER_URL` | unset | OAuth issuer URL |
| `--http-auth-resource-url` | `GDB_MCP_HTTP_AUTH_RESOURCE_URL` | unset | Public MCP resource URL |
| — | `GDB_MCP_MAX_RECENT_RECORDS` | `500` | Integer `10..5000` |
| — | `GDB_MCP_MAX_RECENT_COMMANDS` | `200` | Integer `10..2000` |

## Shutdown Semantics

- **stdin EOF**: the lazy proxy exits its read loop, closes the backend client
  session (triggering backend lifespan `close_all()`), and shuts down cleanly.
- **`SIGTERM`**: the lazy proxy cancels active tasks and closes the backend; the
  backend's `SIGTERM` handler synchronously terminates all GDB and `gdbserver`
  process groups before exiting.
- **`SIGKILL` on the proxy** (used by some MCP clients at session teardown):
  spawned stdio backends set Linux `PR_SET_PDEATHSIG(SIGTERM)` against the proxy
  PID, and every GDB and `gdbserver` subprocess is launched in its own session
  (`start_new_session=True`) with `PR_SET_PDEATHSIG(SIGKILL)` and cleaned up via
  `os.killpg`. No orphaned GDB, `gdbserver`, or inferior processes remain.
