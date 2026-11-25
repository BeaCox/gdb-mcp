# Changelog

All notable changes to this project are documented here.

## [Unreleased]

## [0.5.0] - 2026-11-26

### Added

- Lazy static MCP resources and user-invoked workflow prompts (`debug_local`,
  `triage_core`, `debug_remote`, `analyze_stripped_binary`), plus real discovery
  profiles (`full`, `core`, `advanced:<group>`), machine-readable registry
  metadata (`server.json`), and `scripts/validate_registry_metadata.py`.
- Non-loopback HTTP deployment guardrails (`--allow-remote`,
  `--allow-unsafe-over-http`, bearer authentication, Host/Origin allow-lists)
  and bounded MCP progress reporting on long-running operations.
- Session initialization profiles (`gdb_apply_init_profile`) including
  `source_paths`, `remote_paths`, unsafe-gated `init_file`, and the new
  `debug_info` profile (`substitute_paths`, `debug_file_directories`, and opt-in
  `debuginfod` configuration), recorded in redacted `gdb_export_session_bundle`
  diagnostics.
- Opaque HMAC-signed pagination cursors (`gdb1.*`) rejecting non-canonical
  base64url inputs, plus deterministic response-budget checks
  (`scripts/check_response_budgets.py`), live GDB feature probes
  (`scripts/probe_gdb_features.py`), MCP stdio/Streamable HTTP interop tests,
  and clean wheel install verification (`scripts/check_release_install.py`).
- Workflow and compatibility cookbooks (`docs/WORKFLOWS.md`,
  `docs/COMPATIBILITY.md`) and public MCP compatibility contract tooling
  (`gdb_mcp.contract`, `scripts/check_mcp_contract.py`,
  `docs/COMPATIBILITY_CONTRACT.md`).
- Opt-in structured operational logging to `stderr` (`--log-level` /
  `GDB_MCP_LOG_LEVEL`) with automatic redaction of bearer tokens, passwords,
  URL credentials, inferior arguments, environment variables, and raw payloads.
- Standardized failure metadata (`error_code`, `retryable`, and optional
  `suggested_action`) across all tool error responses while preserving existing
  `ok: true` response shapes.
- Optional idle-session TTL (`--idle-session-ttl` /
  `GDB_MCP_IDLE_SESSION_TTL_SECONDS`) and bounded history retention
  (`GDB_MCP_MAX_RECENT_RECORDS`, `GDB_MCP_MAX_RECENT_COMMANDS`), plus automatic
  pruning of dead sessions before enforcing `max_sessions`.
- Deterministic agent scenario evaluation harness (`gdb_mcp.eval_harness`,
  `scripts/run_eval_harness.py`).

### Changed

- Upgraded the `mcp` dependency from `1.x` (`FastMCP`) to `mcp>=2.3.0,<3`
  (`MCPServer`), adapting HTTP transport security parameters, Streamable HTTP
  client/server APIs, `LazyBackend` single-owner lifecycle, and `mcp 2.x`
  snake_case Pydantic response attributes.
- Split ELF subprocess execution (`gdb_mcp.tools.elf`) and inspection
  formatting/pagination (`gdb_mcp.tools.inspection_format`) behind unchanged
  tool registration APIs, and deduplicated redundant `readelf` and `vmmap` calls
  in `gdb_binary_summary`, `gdb_elf_info`, and `gdb_pwn_context`.
- Raised GDB/MI stdout `StreamReader` limit to 4 MiB with bounded recovery for
  oversized lines so large outputs no longer terminate the session reader loop.
- Enabled concurrent request handling, `notifications/cancelled` propagation,
  and backend disconnect recovery in the lazy stdio proxy (`gdb_mcp.lazy`).
- Updated development tooling requirements (`build>=1.6.0`, `pytest>=9.1.1`,
  `ruff>=0.16.6`, `setuptools>=84.0.0`) and CI artifact upload action v7.

### Fixed

- Fixed `parse_checksec` reading `GNU_STACK` alignment (`0x10`) instead of
  segment flags (`RW`/`RWE`), and recognized `(FLAGS_1)` `NOW` for Full RELRO.
- Closed safe-mode `<<=` and `>>=` mutation bypasses in `_require_read_expression`
  and tightened NUL-byte validation across single-line inputs.
- Fixed session, `gdbserver`, `readelf`, and temporary `rr` directory leaks on
  cancellation or startup failures.
- Hardened GDB/MI parser with explicit nesting-depth and line-length limits,
  complete `c_escape` control-character escaping, and bounded octal escapes.
- Hardened HTTP security validation against wildcard host/origin allow-lists,
  invalid OAuth URLs, malformed bearer tokens, and bracketed IPv6 loopback hosts.
- Updated `scripts/sync_release_version.py` to also sync `BeaCox/gdb-mcp@vX.Y.Z`
  marketplace references, and fixed Codex/Claude plugin update flows.

## [0.4.0] - 2026-07-06

### Added

- Native `rr` record/replay workflow tools:
  `gdb_rr_record` and `gdb_start_rr_replay_session`.
- MCP reference resources for common workflows, core-dump inspection, binary
  analysis, GDB/MI command mapping, and tool-selection guidance.
- Response size profiles and cursor pagination metadata for large output tools,
  including paged diagnostics, memory, source, disassembly, symbol, relocation,
  and mapping responses.
- Release helper scripts for syncing version references from `pyproject.toml`
  and checking lazy MCP startup without touching the backend.

### Changed

- Split the monolithic server implementation into focused tool modules for
  session lifecycle, execution, breakpoints, inspection, binary analysis,
  remote targets, diagnostics, and shared helpers.
- Centralized GDB command construction, response helpers, and binary-analysis
  helpers to keep tool behavior consistent across the expanded API surface.
- Expanded contract, lazy-proxy, session, installer, and rr fixture coverage for
  the release-critical debugger workflows.
- Documented lazy startup behavior and added CI checks for release-version
  consistency and startup-time budgets.

### Fixed

- Hardened cancelled GDB command cleanup and cancelled session shutdown.
- Closed managed `gdbserver` sessions on invalid endpoints.
- Propagated lazy backend diagnostics configuration through the proxy path.
- Hardened debugger tool input validation and bounded `readelf` output while
  separating readelf options from file paths.
- Replaced the misleading `gdb_rr_record` `disable_perf_counters` parameter
  with `disable_syscall_buffer`, matching rr's `--no-syscall-buffer` option.
- Reported rr `perf_event_open` permission failures with structured
  `rr_perf_event_permission_denied` diagnostics and host sysctl guidance.

## [0.3.1] - 2026-06-22

### Fixed

- Pinned Codex plugin and direct `uvx` install sources to the `v0.3.1` release
  tag instead of the mutable `main` branch, avoiding repeated GitHub ref checks
  during MCP startup.

### Changed

- Expanded CLI, lazy proxy JSON-RPC, and command-result truncation test coverage
  for the lazy startup path.

### Added

- Compact context tools for agent workflows: `gdb_context`,
  `gdb_run_and_context`, `gdb_continue_and_context`, `gdb_step_and_context`,
  and `gdb_next_and_context`.
- Pwndbg-inspired, dependency-free binary analysis tools for high-optimization
  or stripped binaries where source symbols are unavailable:
  `gdb_pwn_context`, `gdb_vmmap_structured`, `gdb_address_info`,
  `gdb_telescope`, `gdb_nearpc`, `gdb_piebase`, `gdb_break_rva`,
  `gdb_checksec`, and `gdb_elf_info`.
- Structured address, mapping, PIE/RVA, near-PC disassembly, pointer-chain, and
  ELF hardening metadata so agents can reason in module offsets, registers, and
  memory instead of relying on source-level debug information.

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
