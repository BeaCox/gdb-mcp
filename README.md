# gdb-mcp

[![CI](https://github.com/BeaCox/gdb-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/BeaCox/gdb-mcp/actions/workflows/ci.yml)

`gdb-mcp` is a multi-session [Model Context Protocol](https://modelcontextprotocol.io/)
server for driving GDB through GDB/MI. It lets Codex, Claude Code, and other MCP
clients create isolated GDB sessions, run local executables, connect to
`gdbserver`, set breakpoints, and inspect frames, variables, registers, and
memory.

The default `gdb-mcp` command is a lazy stdio proxy: MCP clients discover tools
at startup, and the full backend starts only on the first `gdb_*` tool call.

## Requirements

- Python 3.10 or newer.
- Linux for supported local debugging.
- GDB on `PATH`; optional `gdbserver` for remote or managed-server workflows.
- `uv` for the recommended Git-based install.

On Debian/Ubuntu:

```bash
sudo apt-get install -y gcc gdb gdbserver
```

## Install

### Codex

```bash
codex plugin marketplace add BeaCox/gdb-mcp --ref main
codex plugin add gdb-mcp@beacox
```

Or register the MCP server directly:

```bash
codex mcp add gdb -- \
  uvx --from git+https://github.com/BeaCox/gdb-mcp.git@main gdb-mcp
```

### Claude Code

```bash
claude plugin marketplace add BeaCox/gdb-mcp
claude plugin install gdb-mcp@beacox
```

Or register the MCP server directly:

```bash
claude mcp add --scope user gdb -- \
  uvx --from git+https://github.com/BeaCox/gdb-mcp.git@main gdb-mcp
```

### From a Checkout

For local development:

```bash
uv sync --extra dev
codex mcp add gdb -- uv run gdb-mcp
# or
claude mcp add --scope user gdb -- uv run gdb-mcp
```

The universal installer is also available:

```bash
uvx --from git+https://github.com/BeaCox/gdb-mcp.git@main gdb-mcp --install
uvx --from git+https://github.com/BeaCox/gdb-mcp.git@main gdb-mcp --install --direct
```

Print portable client configuration:

```bash
gdb-mcp --print-config
```

## Use

Open a new Codex or Claude Code session after installation and ask for a GDB
debugging task:

```text
Use GDB MCP to debug /tmp/gdb-mcp-hello. Set a breakpoint at add, run, show the
current location, backtrace, locals, then continue once.
```

Typical tool flow:

1. `gdb_create_session` with an executable path.
2. `gdb_set_breakpoint`.
3. `gdb_run`, `gdb_continue`, `gdb_step`, or `gdb_next`.
4. Inspect with `gdb_current_location`, `gdb_backtrace`, `gdb_locals`,
   `gdb_eval_expression`, `gdb_registers`, or `gdb_read_memory`.
5. `gdb_close_session` when finished.

Every session has an explicit `session_id`; there is no implicit current session.

See [examples/README.md](examples/README.md) for a Linux walkthrough and
[TOOLS.md](TOOLS.md) for the full tool reference.

## Backend

`gdb-mcp` normally starts the backend lazily. To run a standalone HTTP backend:

```bash
gdb-mcp-backend --transport streamable-http --host 127.0.0.1 --port 8000
GDB_MCP_BACKEND_URL=http://127.0.0.1:8000/mcp gdb-mcp
```

The default bind address is loopback. Do not expose the HTTP transport to an
untrusted network without authentication and host isolation.

## Unsafe Tools

Raw GDB execution, inferior function calls, variable mutation, memory writes,
and breakpoint command lists are disabled by default. Enable them explicitly:

```bash
gdb-mcp --unsafe
# or
GDB_MCP_ALLOW_UNSAFE=1 gdb-mcp
```

Unsafe tools can execute target code, modify process state, or run arbitrary GDB
behavior. Use them only for trusted targets.

## Development

```bash
uv sync --extra dev
uv run ruff check .
uv run pytest
uv build
```

Support policy and release notes live in [CHANGELOG.md](CHANGELOG.md). Security
guidance is in [SECURITY.md](SECURITY.md).
