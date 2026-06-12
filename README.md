# gdb-mcp

`gdb-mcp` is a multi-session [Model Context Protocol](https://modelcontextprotocol.io/)
server for driving GDB through its machine interface (GDB/MI). Each session owns an
isolated GDB process and can debug a local executable or connect to `gdbserver`.

The project is currently beta quality. The protocol core, lifecycle handling, safety
defaults, and tool schemas are tested; broader platform and remote-target coverage is
still growing.

## Highlights

- Multiple isolated GDB sessions with explicit session IDs.
- Token-routed asynchronous GDB/MI transport.
- Concurrent interrupt support for long-running `run` and `continue` calls.
- Local executable, existing `gdbserver`, and managed local `gdbserver` workflows.
- Structured tools for breakpoints, threads, frames, locals, registers, and memory.
- Bounded tool output with truncation metadata.
- `stdio`, Streamable HTTP, and legacy SSE transports.
- Safe default profile: unrestricted raw GDB commands are disabled.
- FastMCP lifespan cleanup for GDB and `gdbserver` child processes.

## Requirements

- Python 3.10 or newer.
- GDB available on `PATH`, or an explicit `gdb_path`.
- Optional: `gdbserver` for remote or managed-server workflows.
- A compatible MCP client.

On macOS, running an inferior under GDB may require a correctly signed GDB build.
Connecting to a remote `gdbserver` does not require local inferior launching.

## Install

From a checkout:

```bash
uv tool install .
```

For development:

```bash
uv sync --extra dev
uv run pytest
```

## Configure

Print a client-ready stdio configuration:

```bash
gdb-mcp --print-config
```

Equivalent configuration:

```json
{
  "mcpServers": {
    "gdb": {
      "command": "/absolute/path/to/gdb-mcp"
    }
  }
}
```

Run a Streamable HTTP server:

```bash
gdb-mcp --transport streamable-http --host 127.0.0.1 --port 8000
```

The default bind address is loopback. Do not expose the HTTP transport to an
untrusted network without an authenticated reverse proxy and host-level isolation.

## Typical Flow

1. Call `gdb_create_session` with an executable path.
2. Set breakpoints with `gdb_set_breakpoint`.
3. Call `gdb_run`, `gdb_continue`, `gdb_step`, or `gdb_next`.
4. Inspect state with `gdb_threads`, `gdb_backtrace`, `gdb_locals`,
   `gdb_registers`, and `gdb_read_memory`.
5. Call `gdb_close_session` when finished.

For an existing remote target:

```json
{
  "program": "/absolute/path/to/a.out",
  "endpoint": "localhost:2345",
  "extended": false
}
```

Pass the returned `session_id` to every subsequent operation. There is no implicit
current session.

## Tool Groups

Session management:

- `gdb_create_session`
- `gdb_connect_gdbserver`
- `gdb_launch_gdbserver`
- `gdb_list_sessions`
- `gdb_status`
- `gdb_close_session`
- `gdb_server_health`
- `gdb_recent_events`

Execution:

- `gdb_run`
- `gdb_continue`
- `gdb_interrupt`
- `gdb_step`
- `gdb_next`

Breakpoints and inspection:

- `gdb_set_breakpoint`
- `gdb_delete_breakpoint`
- `gdb_list_breakpoints`
- `gdb_threads`
- `gdb_select_thread`
- `gdb_backtrace`
- `gdb_select_frame`
- `gdb_locals`
- `gdb_registers`
- `gdb_read_memory`

Advanced:

- `gdb_execute`: unrestricted CLI or raw MI execution. Disabled by default.

## Safety Model

Dedicated tools are available by default. Raw GDB commands can invoke inferior
functions, write process memory, load scripts, and execute shell commands, so
`gdb_execute` requires an explicit opt-in:

```bash
gdb-mcp --unsafe
```

Or:

```bash
GDB_MCP_ALLOW_UNSAFE=1 gdb-mcp
```

Other environment settings:

- `GDB_MCP_MAX_SESSIONS`: maximum live sessions, default `8`; `0` is unlimited.
- `GDB_MCP_OUTPUT_LIMIT_CHARS`: approximate per-result output limit, default `100000`.

Tool annotations describe read-only, destructive, idempotent, and open-world
behavior to MCP clients. Treat annotations as UX hints, not an authorization layer.

## Architecture

```text
MCP client
    |
FastMCP tools and lifecycle
    |
SessionManager
    |
GdbSession (one process per session)
    |
token router + asynchronous MI reader
    |
GDB/MI -> local inferior or gdbserver
```

The reader task continuously parses MI records and routes result records by token.
Asynchronous running and stopped records are delivered to waiting execution calls
without blocking an independent interrupt request.

## Development

```bash
uv sync --extra dev
uv run ruff check .
uv run pytest --cov=gdb_mcp
uv build
```

Tests include parser coverage, real-GDB smoke coverage when GDB is installed,
deterministic asynchronous lifecycle tests, and MCP tool-contract checks.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[LICENSE](LICENSE).
