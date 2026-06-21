<p align="center">
  <img src="assets/logo.svg" alt="gdb-mcp logo" width="150">
</p>

<h1 align="center">gdb-mcp</h1>

<p align="center">
  Multi-session GDB control for Codex, Claude Code, and any MCP client.
</p>

<p align="center">
  <a href="https://github.com/BeaCox/gdb-mcp/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/BeaCox/gdb-mcp/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776AB">
  <img alt="License MIT" src="https://img.shields.io/badge/license-MIT-16A34A">
  <img alt="MCP server" src="https://img.shields.io/badge/MCP-server-0F172A">
</p>

`gdb-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io/) server
that drives GDB through GDB/MI. It gives AI coding clients a structured,
session-aware debugger interface for local Linux programs, core files, and
`gdbserver` targets.

The default `gdb-mcp` command is a lazy stdio proxy. MCP clients can discover
tools immediately, while the full backend starts only when the first `gdb_*`
tool is called.

## Highlights

- **Isolated debugging sessions**: every target gets an explicit `session_id`,
  so multiple programs can be debugged side by side.
- **Compact context tools**: run, continue, step, reverse-step, and inspect with
  tool responses that include the current frame, backtrace, locals, and summary.
- **Local and remote workflows**: debug local executables, attach to Linux
  processes, load core files, connect to `gdbserver`, or launch a managed
  `gdbserver`.
- **Agent-readable capabilities**: expose workflow groups, output strategy,
  safety posture, dependency versions, and diagnostic state through structured
  read-only tools.
- **Safety by default**: reads and ordinary debugger control are available out
  of the box; raw GDB execution, inferior calls, mutation, and memory writes
  require explicit unsafe mode.

## What You Can Do

| Workflow | Tools |
| --- | --- |
| Start and manage sessions | `gdb_create_session`, `gdb_attach`, `gdb_load_core`, `gdb_close_session` |
| Control execution | `gdb_run_and_context`, `gdb_continue_and_context`, `gdb_step_and_context`, `gdb_next_and_context` |
| Reverse debug | `gdb_start_recording`, `gdb_reverse_continue_and_context`, `gdb_reverse_step_and_context` |
| Inspect state | `gdb_context`, `gdb_backtrace`, `gdb_locals`, `gdb_eval_expression`, `gdb_read_register`, `gdb_registers`, `gdb_source`, `gdb_disassemble_around_pc`, `gdb_read_memory` |
| Analyze stripped/optimized binaries | `gdb_pwn_context`, `gdb_binary_summary`, `gdb_register_context`, `gdb_vmmap_structured`, `gdb_address_info`, `gdb_rva_info`, `gdb_telescope`, `gdb_nearpc`, `gdb_symbols`, `gdb_got`, `gdb_piebase`, `gdb_break_rva`, `gdb_checksec`, `gdb_elf_info` |
| Work with remote targets | `gdb_connect_gdbserver`, `gdb_launch_gdbserver`, `gdb_gdbserver_status` |
| Inspect server capabilities | `gdb_capabilities`, `gdb_server_health`, `gdb_command_reference`, `gdb_session_diagnostics` |

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
codex plugin marketplace add BeaCox/gdb-mcp --ref v0.3.1
codex plugin add gdb-mcp@beacox
```

Or register the MCP server directly:

```bash
codex mcp add gdb -- \
  uvx --from git+https://github.com/BeaCox/gdb-mcp.git@v0.3.1 gdb-mcp
```

### Claude Code

```bash
claude plugin marketplace add BeaCox/gdb-mcp
claude plugin install gdb-mcp@beacox
```

Or register the MCP server directly:

```bash
claude mcp add --scope user gdb -- \
  uvx --from git+https://github.com/BeaCox/gdb-mcp.git@v0.3.1 gdb-mcp
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
uvx --from git+https://github.com/BeaCox/gdb-mcp.git@v0.3.1 gdb-mcp --install
uvx --from git+https://github.com/BeaCox/gdb-mcp.git@v0.3.1 gdb-mcp --install --direct
```

Print portable client configuration:

```bash
gdb-mcp --print-config
```

## Update

Use the latest release tag listed in [CHANGELOG.md](CHANGELOG.md), then restart
the MCP client after updating.

For Codex plugin installs:

```bash
codex plugin marketplace add BeaCox/gdb-mcp --ref <new-tag>
codex plugin add gdb-mcp@beacox
```

For Claude Code plugin installs, refresh the marketplace entry and reinstall the
plugin:

```bash
claude plugin marketplace add BeaCox/gdb-mcp
claude plugin install gdb-mcp@beacox
```

For direct MCP registrations, replace the tag in the registered `uvx --from`
source, for example:

```bash
codex mcp add gdb -- \
  uvx --from git+https://github.com/BeaCox/gdb-mcp.git@<new-tag> gdb-mcp

claude mcp add --scope user gdb -- \
  uvx --from git+https://github.com/BeaCox/gdb-mcp.git@<new-tag> gdb-mcp
```

For installer-managed configs, rerun the installer with the newer tag:

```bash
uvx --from git+https://github.com/BeaCox/gdb-mcp.git@<new-tag> gdb-mcp --install
uvx --from git+https://github.com/BeaCox/gdb-mcp.git@<new-tag> gdb-mcp --install --direct
```

## Quick Start

Open a new Codex or Claude Code session after installation and ask for a GDB
debugging task:

```text
Use GDB MCP to debug /tmp/gdb-mcp-hello. Set a breakpoint at add, run, show the
current location, backtrace, locals, then continue once.
```

Typical MCP tool flow:

1. `gdb_create_session` with an executable path.
2. Optional: `gdb_server_health` and `gdb_capabilities` to inspect dependency
   availability, output limits, safety mode, and recommended workflows.
3. `gdb_set_breakpoint`.
4. `gdb_run_and_context`, `gdb_continue_and_context`,
   `gdb_step_and_context`, or `gdb_next_and_context`.
5. Inspect further with `gdb_context`, `gdb_eval_expression`,
   `gdb_registers`, or `gdb_read_memory`.
6. For stripped or optimized binaries, switch to pwn-oriented tools such as
   `gdb_pwn_context`, `gdb_binary_summary`, `gdb_register_context`,
   `gdb_address_info`, `gdb_rva_info`, `gdb_symbols`, `gdb_got`,
   `gdb_nearpc`, `gdb_telescope`, and `gdb_vmmap_structured`.
7. For time-travel debugging, use `gdb_start_recording` before the run and then
   `gdb_reverse_continue_and_context`, `gdb_reverse_step_and_context`, or
   `gdb_reverse_next_and_context`.
8. `gdb_close_session` when finished.

Every session has an explicit `session_id`; there is no implicit current session.
The `*_and_context` tools return a compact summary, current frame, backtrace, and
locals. Pass `include_raw=true` when the raw GDB/MI payload is needed.

See [examples/README.md](examples/README.md) for a Linux walkthrough and
[TOOLS.md](TOOLS.md) for the full tool reference.

## Architecture

```text
MCP client
  |
  | stdio
  v
gdb-mcp lazy proxy
  |
  | starts on first gdb_* tool call
  v
gdb-mcp backend
  |
  | GDB/MI
  v
GDB / gdbserver / target program
```

## Backend

`gdb-mcp` normally starts the backend lazily. To run a standalone HTTP backend:

```bash
gdb-mcp-backend --transport streamable-http --host 127.0.0.1 --port 8000
GDB_MCP_BACKEND_URL=http://127.0.0.1:8000/mcp gdb-mcp
```

The default bind address is loopback. Do not expose the HTTP transport to an
untrusted network without authentication and host isolation.

## Unsafe Tools

Raw GDB execution, inferior function calls, variable mutation, memory writes, and
breakpoint command lists are disabled by default. Enable them explicitly:

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

## Links

- [Tool reference](TOOLS.md)
- [Linux walkthrough](examples/README.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
