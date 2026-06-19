# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added

- Compact context tools for agent workflows: `gdb_context`,
  `gdb_run_and_context`, `gdb_continue_and_context`, `gdb_step_and_context`,
  and `gdb_next_and_context`.

## [0.3.0] - 2026-06-19

### Added

- Lazy stdio proxy behavior for `gdb-mcp`: clients can discover the GDB tool
  schema at MCP startup while the full backend starts or connects on first tool use.
- `gdb-mcp-backend` for explicitly running the full backend, including HTTP and
  SSE transports.

### Changed

- Claude Code and Codex plugin/direct configurations now use `gdb-mcp`, whose
  default MCP behavior defers full backend startup until debugging tools are
  actually used.
- README and Linux walkthrough now describe the lazy, single-entry client model.

## [0.2.0] - 2026-06-19

### Added

- Linux-first support policy for local GDB debugging.
- Expanded MCP tool surface to 59 tools across session management, execution,
  breakpoints, threads/frames, inspection, memory, remote targets, and diagnostics.
- Dedicated unsafe-gated tools for inferior function calls, variable mutation,
  memory writes, and breakpoint command lists.
- Linux smoke coverage for local GDB, managed `gdbserver`, attach, core loading,
  expression evaluation, disassembly, watchpoints, and process mappings.
- Deterministic MCP tool-contract tests using the fake GDB/MI fixture.
- `gdbserver` ephemeral port handling for `localhost:0`.
- Public demo walkthrough and tool reference documentation.

### Changed

- Project metadata now advertises POSIX/Linux support instead of broad local
  macOS/Windows support.
- README installation instructions now target the tagged public Git release until
  a PyPI release is available.
- Safety documentation now distinguishes read-oriented tools, target execution
  tools, and unsafe-gated mutation tools.

### Fixed

- Fixed Linux `gdbserver` connection handling by avoiding quoted endpoint
  arguments in `-target-select`.
- Fixed managed `gdbserver` connections when `gdbserver` chooses an ephemeral port.
- Fixed core loading by using `-target-select core <path>` for reliable Linux GDB
  behavior.
