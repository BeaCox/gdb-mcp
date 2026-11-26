<!-- mcp-name: io.github.beacox/gdb-mcp -->

<p align="center">
  <img src="assets/logo.svg" alt="gdb-mcp logo" width="150">
</p>

<h1 align="center">gdb-mcp</h1>

<p align="center">
  Multi-session GDB control for Antigravity, Claude Code, Codex, and any MCP client.
</p>

<p align="center">
  <a href="https://github.com/BeaCox/gdb-mcp/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/BeaCox/gdb-mcp/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://pypi.org/project/beacox-gdb-mcp/"><img alt="PyPI" src="https://img.shields.io/pypi/v/beacox-gdb-mcp"></a>
  <a href="https://github.com/BeaCox/gdb-mcp/releases"><img alt="GitHub Release" src="https://img.shields.io/github/v/release/BeaCox/gdb-mcp"></a>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776AB">
  <img alt="License MIT" src="https://img.shields.io/badge/license-MIT-16A34A">
</p>

`gdb-mcp` (PyPI package **`beacox-gdb-mcp`**) is a
[Model Context Protocol](https://modelcontextprotocol.io/) server that drives
GDB over GDB/MI. It provides isolated multi-session debugging for local Linux
executables, core dumps, `gdbserver` targets, and `rr` time-travel traces.

## Why `gdb-mcp`

- **Lazy startup**: `gdb-mcp` answers `initialize`, `tools/list`, `resources/*`,
  and `prompts/*` immediately; GDB starts only on the first tool call.
- **Explicit multi-session safety**: every session requires a `session_id`; raw
  execution, inferior calls, and memory writes require `--unsafe`.
- **Bounded, selectable tool surface**: use `--tool-profile core` (29 tools) or
  `--tools` / `--exclude-tools` on schema-constrained clients:

| Profile | Tools | `tools/list` Size | 3-Scenario Total (Schema + Calls) |
| --- | ---: | ---: | ---: |
| `full` (default) | 98 | 51,909 B (~17,303 tok) | 61,286 B (~20,436 tok) |
| `core` | 29 | 13,648 B (~4,550 tok) | 23,025 B (~7,683 tok) |

Measured with `scripts/measure_tools.py` and `scripts/run_eval_harness.py --compare-profiles`
(`core` cuts upfront schema tokens by **73.7%** and total session tokens by **62.4%**).

## Requirements & Platform Setup

- **Linux** (local attach, core files, and `gdbserver` require Linux)
- **Python 3.10+** and **`uv`** (recommended for `uv tool install`)
- **`gdb`** on `PATH`; optional **`gdbserver`** and **`rr`**

```bash
sudo apt-get install -y gcc gdb
sudo apt-get install -y gdbserver rr  # optional
```

Linux kernel / container permissions (checked automatically by `gdb-mcp doctor`):

```bash
# Allow gdb_attach on non-child processes:
sudo sysctl kernel.yama.ptrace_scope=0

# Allow rr hardware performance counters:
sudo sysctl kernel.perf_event_paranoid=1

# Inside Docker / OCI containers:
docker run -i --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined ...
# Add --pid=host when attaching to host processes.
```

## Install

```bash
uv tool install beacox-gdb-mcp
```

> [!NOTE]
> The PyPI distribution is **`beacox-gdb-mcp`** (the older `gdb-mcp` name on PyPI
> belongs to an unrelated package). The installed command is `gdb-mcp`.
> For `uvx`, `pipx`, tagged Git, marketplace plugins, Docker, or Nix flake, see
> [docs/INSTALL.md](docs/INSTALL.md).

## Verify

```bash
gdb-mcp --version
gdb-mcp doctor
```

## Configure Your Agent

```bash
claude mcp add --scope user gdb -- gdb-mcp
codex mcp add gdb -- gdb-mcp
```

Generate JSON snippets for Antigravity (`agy`), Cursor, VS Code, Windsurf,
Claude, or Codex:

```bash
gdb-mcp config agy --installed
gdb-mcp config cursor --installed
gdb-mcp config vscode --installed
```

For schema-constrained clients or smaller context windows, pass
`--tool-profile core` in the server command arguments (or set
`GDB_MCP_TOOL_PROFILE=core`):

```json
{
  "mcpServers": {
    "gdb": {
      "command": "gdb-mcp",
      "args": ["--tool-profile", "core"]
    }
  }
}
```

## Update

```bash
uv tool upgrade beacox-gdb-mcp
```

Then restart your MCP client.

## Quick Start

Ask your coding agent:

```text
Use GDB MCP to debug /tmp/gdb-mcp-hello. Set a breakpoint at add, run, show the
current location, backtrace, locals, then continue once.
```

Typical tool flow: `gdb_create_session` -> `gdb_set_breakpoint` ->
`gdb_run_and_context` -> `gdb_context` / `gdb_eval_expression` /
`gdb_read_memory` -> `gdb_close_session`. For stripped binaries, switch to
`gdb_pwn_context`, `gdb_vmmap_structured`, `gdb_telescope`, and `gdb_symbols`.

## Unsafe Mode & Shutdown

Raw `gdb_execute`, inferior calls, variable/memory writes, and `init_file` are
disabled by default. Enable them explicitly with `gdb-mcp --unsafe` or
`GDB_MCP_ALLOW_UNSAFE=1`.

On stdin EOF, `SIGTERM`, or `SIGKILL` of the proxy, `PR_SET_PDEATHSIG` and
session process groups (`start_new_session=True` + `os.killpg`) terminate all
spawned backend, GDB, and `gdbserver` processes without orphans. See
[docs/TRANSPORTS.md](docs/TRANSPORTS.md) for HTTP mode, environment variables,
and shutdown details.

## Documentation

- [Documentation Index](docs/README.md)
- [Install & Client Setup](docs/INSTALL.md)
- [Tool Reference (98 tools)](docs/TOOLS.md)
- [Transports, CLI, Env Vars, & Shutdown](docs/TRANSPORTS.md)
- [Debugging Workflows](docs/WORKFLOWS.md)
- [Compatibility Matrix](docs/COMPATIBILITY.md)
- [Testing & Benchmarks](docs/TESTING.md)
- [Security Policy](SECURITY.md) | [Changelog](CHANGELOG.md) | [MCP Registry Manifest](server.json) | [Capability Metadata](gdb-mcp.meta.json)
