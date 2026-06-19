# gdb-mcp

[![CI](https://github.com/BeaCox/gdb-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/BeaCox/gdb-mcp/actions/workflows/ci.yml)

`gdb-mcp` is a multi-session [Model Context Protocol](https://modelcontextprotocol.io/)
server for driving GDB through its machine interface (GDB/MI). Each session owns an
isolated GDB process and can debug a local executable or connect to `gdbserver`.

The project is currently beta quality. Linux local debugging, protocol core,
lifecycle handling, safety defaults, and tool schemas are tested; remote-target
coverage is still growing.

## Highlights

- Multiple isolated GDB sessions with explicit session IDs.
- Token-routed asynchronous GDB/MI transport.
- Concurrent interrupt support for long-running `run` and `continue` calls.
- Linux local executable, existing `gdbserver`, and managed local `gdbserver` workflows.
- Structured tools for breakpoints, threads, frames, locals, registers, and memory.
- Bounded tool output with truncation metadata.
- `stdio`, Streamable HTTP, and legacy SSE transports.
- Safe default profile: unrestricted raw GDB commands are disabled.
- FastMCP lifespan cleanup for GDB and `gdbserver` child processes.

## Requirements

- Python 3.10 or newer.
- Linux for supported local debugging.
- GDB available on `PATH`, or an explicit `gdb_path`.
- Optional: `gdbserver` for remote or managed-server workflows.
- A compatible MCP client.

On Debian/Ubuntu Linux:

```bash
sudo apt-get install -y gcc gdb gdbserver
```

## Support Policy

- Supported and tested: Linux local debugging with GDB and optional `gdbserver`.
- Supported and tested: running the MCP server on Linux and connecting to remote
  `gdbserver` targets.
- Best effort: running the MCP server on macOS or Windows only as a client-side
  bridge to a remote Linux or embedded target. Local inferior debugging on macOS
  and Windows is not a supported target for this project.

Platform-specific tools such as `gdb_attach`, `gdb_load_core`, and
`gdb_memory_mappings` are designed and tested against Linux GDB behavior.

## Quick Install

Prerequisites:

- Install [uv](https://docs.astral.sh/uv/).
- Install GDB and ensure `gdb` is available on `PATH`.

### From Git

Install or run directly from the tagged public Git release:

```bash
uvx --from git+https://github.com/BeaCox/gdb-mcp.git@v0.2.0 gdb-mcp --install
```

For direct MCP registration instead of marketplace plugins:

```bash
uvx --from git+https://github.com/BeaCox/gdb-mcp.git@v0.2.0 \
  gdb-mcp --install --direct
```

### Claude Code Plugin

Add the repository as the `beacox` marketplace, then install the plugin:

```bash
claude plugin marketplace add BeaCox/gdb-mcp
claude plugin install gdb-mcp@beacox
```

Update later with:

```bash
claude plugin marketplace update beacox
claude plugin update gdb-mcp@beacox
```

### Codex Plugin

```bash
codex plugin marketplace add BeaCox/gdb-mcp --ref main
codex plugin add gdb-mcp@beacox
```

Update later with:

```bash
codex plugin marketplace upgrade beacox
codex plugin add gdb-mcp@beacox
```

### Universal Installer

PyPI publishing is planned but not currently enabled. After a PyPI package is
published, the same installer can be run as:

```bash
uvx gdb-mcp --install
```

The installer detects Claude Code and Codex. Select clients explicitly when needed:

```bash
gdb-mcp --install claude
gdb-mcp --install claude,codex
```

Use direct MCP registration instead of marketplace plugins:

```bash
gdb-mcp --install --direct
```

Preview commands without changing client configuration:

```bash
gdb-mcp --install --dry-run
gdb-mcp --list-clients
```

Uninstall:

```bash
gdb-mcp --uninstall
gdb-mcp --uninstall --direct
```

## Package Install

From a checkout:

```bash
uv tool install .
```

For development:

```bash
uv sync --extra dev
uv run pytest
```

## Manual Configuration

Print a client-ready stdio configuration:

```bash
gdb-mcp --print-config
```

The generated configuration launches the package through `uvx`, so clients do not
depend on a checkout-specific virtual environment.

Equivalent Claude Code configuration:

```json
{
  "mcpServers": {
    "gdb": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/BeaCox/gdb-mcp.git@v0.2.0",
        "gdb-mcp"
      ]
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
   `gdb_eval_expression`, `gdb_registers`, and `gdb_read_memory`.
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

See [examples/README.md](examples/README.md) for a complete Linux walkthrough and
[TOOLS.md](TOOLS.md) for the full tool reference.
Release notes are tracked in [CHANGELOG.md](CHANGELOG.md).

## Tool Groups

Session management:

- `gdb_create_session`
- `gdb_attach`
- `gdb_load_core`
- `gdb_connect_gdbserver`
- `gdb_launch_gdbserver`
- `gdb_list_sessions`
- `gdb_status`
- `gdb_close_session`
- `gdb_server_health`
- `gdb_recent_events`
- `gdb_recent_commands`
- `gdb_session_diagnostics`
- `gdb_close_idle_sessions`

Execution:

- `gdb_run`
- `gdb_restart`
- `gdb_continue`
- `gdb_interrupt`
- `gdb_signal`
- `gdb_detach`
- `gdb_kill`
- `gdb_step`
- `gdb_next`

Breakpoints:

- `gdb_set_breakpoint`
- `gdb_set_watchpoint`
- `gdb_enable_breakpoint`
- `gdb_disable_breakpoint`
- `gdb_breakpoint_condition`
- `gdb_breakpoint_commands`: set command-list actions. Requires unsafe mode.
- `gdb_delete_breakpoint`
- `gdb_list_breakpoints`

Threads and frames:

- `gdb_threads`
- `gdb_select_thread`
- `gdb_backtrace`
- `gdb_thread_apply_all_backtrace`
- `gdb_select_frame`
- `gdb_locals`
- `gdb_stack_arguments`
- `gdb_frame_variables`

Inspection:

- `gdb_eval_expression`
- `gdb_print`
- `gdb_call_function`: call an inferior function. Requires unsafe mode.
- `gdb_set_variable`: set an inferior variable. Requires unsafe mode.
- `gdb_disassemble`
- `gdb_disassemble_current_frame`
- `gdb_current_location`
- `gdb_source`
- `gdb_find_source`
- `gdb_registers`
- `gdb_read_memory`
- `gdb_write_memory`: write raw memory bytes. Requires unsafe mode.
- `gdb_search_memory`
- `gdb_read_c_string`
- `gdb_shared_libraries`
- `gdb_info_files`
- `gdb_memory_mappings`

Remote target support:

- `gdb_set_remote_paths`
- `gdb_detach_gdbserver`
- `gdb_gdbserver_status`

Advanced:

- `gdb_execute`: unrestricted CLI or raw MI execution. Disabled by default.

## Safety Model

Dedicated tools are available by default, but they are not all equally safe:

- Read-oriented tools such as `gdb_backtrace`, `gdb_locals`, `gdb_registers`,
  `gdb_eval_expression`, `gdb_disassemble`, `gdb_source`, `gdb_read_memory`,
  `gdb_read_c_string`, `gdb_info_files`, and `gdb_memory_mappings` can disclose
  local source code, process memory, registers, loaded file paths, and secrets
  visible to the debugged process.
- Execution tools such as `gdb_run`, `gdb_continue`, `gdb_step`, `gdb_next`,
  `gdb_interrupt`, `gdb_signal`, `gdb_detach`, `gdb_kill`, `gdb_attach`, and
  `gdb_launch_gdbserver` can stop, resume, detach, kill, or otherwise affect
  local processes.
- `gdb_eval_expression` and `gdb_set_watchpoint` use a conservative safe-expression
  filter by default. Expressions with assignments, increments/decrements, control
  separators, or function calls are rejected. Use `gdb_execute` only when you
  explicitly need unrestricted GDB behavior.
- `gdb_call_function`, `gdb_set_variable`, `gdb_write_memory`, and
  `gdb_breakpoint_commands` require unsafe mode because they can execute target
  code, modify target state, or run arbitrary breakpoint actions.

Raw GDB commands can invoke inferior functions, write process memory, load scripts,
and execute shell commands, so `gdb_execute` requires an explicit opt-in:

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

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md),
[SECURITY.md](SECURITY.md), and [LICENSE](LICENSE).
