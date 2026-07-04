# TODO

Maintenance backlog for turning `gdb-mcp` from a broad feature surface into a
stable, easier-to-maintain debugger server.

This list is based on a July 2026 review of the local codebase and comparable
open source GDB MCP servers, including `signal-slot/mcp-gdb`,
`pansila/mcp_server_gdb`, `Ipiano/gdb-mcp`, `schuay/gdb-mcp`,
`maxholman/mcp-gdbmi`, `hnmr293/gdb-mcp`, and `jtang613/gdb-mcp`.

## P0: Maintainability

- [ ] Split `src/gdb_mcp/server.py` by tool domain.
  - Target modules: `tools/session.py`, `tools/execution.py`,
    `tools/breakpoints.py`, `tools/inspection.py`, `tools/binary.py`,
    `tools/remote.py`, and `tools/diagnostics.py`.
  - Keep a small central registration/entry module so MCP startup behavior stays
    unchanged.
  - Acceptance: no tool names or public argument names change; full test suite
    remains green.

- [ ] Introduce shared response models.
  - Define common shapes for success, error, session, command, and diagnostic
    responses.
  - Reduce ad hoc dictionaries and inconsistent response fields across tools.
  - Acceptance: contract tests cover representative responses for each tool
    family.

- [ ] Preserve the cancellation and cleanup guarantees during refactors.
  - Keep coverage for cancelled GDB commands, cancelled gdbserver connects,
    pending-command cleanup, and managed gdbserver teardown.
  - Acceptance: async lifecycle tests still exercise cancellation before and
    after command dispatch.

## P1: Agent Experience

- [ ] Move long-form reference material into MCP resources.
  - Add resources such as `gdb://workflows/basic`,
    `gdb://workflows/core-dump`, `gdb://workflows/binary-analysis`,
    `gdb://commands/mi`, and `gdb://tools/decision-guide`.
  - Keep `gdb_command_reference` as a compact index that points clients to the
    resources.
  - Acceptance: clients can discover workflows without calling a large tool
    response.

- [ ] Define a smaller recommended tool profile.
  - Document a core default set of roughly 20-30 tools for common debugging.
  - Keep binary-analysis, reverse-debugging, remote-target, diagnostics, and
    unsafe tools discoverable but clearly grouped as advanced workflows.
  - Acceptance: `gdb_capabilities` identifies core and advanced tool groups.

- [ ] Add response-size profiles.
  - Support consistent `summary`, `structured`, and `raw` output modes where
    useful.
  - Apply the same strategy to context, backtrace, variables, symbols, readelf,
    and memory-heavy tools.
  - Acceptance: large outputs have predictable bounded responses.

- [ ] Add pagination or resource handles for large outputs.
  - Candidate tools: symbols, GOT/relocations, readelf output, memory dumps,
    thread-all backtraces, and command history.
  - Acceptance: tools can return a cursor or resource handle instead of forcing
    all data into one MCP response.

## P1: Debugging Capability

- [ ] Add native rr workflows.
  - Add tools such as `gdb_rr_record` and `gdb_start_rr_replay_session`.
  - Reuse existing reverse/context tools for replay sessions where possible.
  - Acceptance: a smoke test records a small binary and replays it when `rr` is
    available, skipping cleanly otherwise.

- [ ] Expand remote-target coverage.
  - Cover IPv6 endpoints, Unix-socket style targets if supported by GDB, custom
    `sysroot`, and `solib-search-path` workflows.
  - Acceptance: contract tests cover validation; smoke tests cover available
    local `gdbserver` paths.

- [ ] Add core-dump workflow tests with sysroot/search-path setup.
  - Acceptance: a smoke test verifies core loading plus post-load path
    configuration and thread/backtrace inspection.

## P2: Distribution

- [ ] Publish stable PyPI releases.
  - Keep `uvx --from git+...` documented, but make `uvx gdb-mcp` or
    `pipx install gdb-mcp` viable.
  - Acceptance: README install paths include PyPI and tagged Git options.

- [ ] Add registry metadata for MCP discovery sites.
  - Consider `server.json` or equivalent metadata used by MCP marketplaces.
  - Acceptance: install instructions are machine-readable where practical.

- [ ] Evaluate Nix/Homebrew packaging.
  - Nix is especially useful for GDB/gdbserver/rr dependencies.
  - Acceptance: documented optional install path or a clear decision not to
    support it yet.

## P2: Quality

- [ ] Strengthen MI parser tests.
  - Add real GDB/MI transcript fixtures for async records, stream records,
    errors, nested values, and malformed lines.
  - Consider property/fuzz-style parser tests for `src/gdb_mcp/mi.py`.
  - Acceptance: parser regressions fail without needing a live GDB process.

- [ ] Add differential checks against known MI parsers or captured GDB output.
  - Use this only for parser confidence; avoid adding heavyweight runtime
    dependencies to the package.
  - Acceptance: fixture-based comparison documents intentional differences.

- [ ] Improve installer and lazy proxy coverage.
  - Current project coverage is strongest around server/session behavior; keep
    lifting coverage for install and proxy edge cases.
  - Acceptance: coverage gaps in `installer.py` and `lazy.py` are reduced for
    error handling and configuration branches.

- [ ] Add performance and token-budget regression checks.
  - Track response sizes for common context, pwn context, symbol, and readelf
    workflows.
  - Acceptance: tests or scripts catch accidental large-response regressions.

## P2: Documentation

- [ ] Add cookbook-style workflows.
  - Suggested topics: local source debugging, stripped binary analysis, core
    dump triage, remote gdbserver, managed gdbserver, attach/detach, reverse
    debugging, and unsafe-mode workflows.
  - Acceptance: each cookbook has a concrete tool sequence and expected result
    shape.

- [ ] Document security tradeoffs per workflow.
  - Link each unsafe or destructive workflow back to `SECURITY.md`.
  - Acceptance: docs explain when to use containers, VMs, or dedicated users.

- [ ] Add a compatibility matrix.
  - Track Python versions, GDB versions, Linux distributions, gdbserver, rr,
    and known unsupported platforms.
  - Acceptance: contributors can tell whether a failure is expected or a bug.
