# TODO

## Follow-up backlog (reviewed 2026-07-15)

The initial July maintenance plan is complete and retained below as historical
context. This follow-up deliberately favours MCP protocol fidelity, safe remote
operation, and repeatable debugging over adding another broad raw-GDB surface.

Review inputs:

- [`signal-slot/mcp-gdb`](https://github.com/signal-slot/mcp-gdb): validates the
  baseline session/core/breakpoint workflow, but its unrestricted command tool
  reinforces keeping `gdb_execute` opt-in.
- [`Ipiano/gdb-mcp`](https://github.com/Ipiano/gdb-mcp): demonstrates useful
  per-session GDB initialization for core-dump and project-specific workflows.
- [`pansila/mcp_server_gdb`](https://github.com/pansila/mcp_server_gdb): shows
  demand for remote transports and inspectable agent activity; its Nix support
  remains a useful packaging reference.
- [`maxholman/mcp-gdbmi`](https://github.com/maxholman/mcp-gdbmi): highlights
  that verbose MI output needs a token-aware, not merely character-aware,
  response budget.
- The [MCP prompts specification](https://modelcontextprotocol.io/specification/2024-11-05/server/prompts/),
  [progress specification](https://modelcontextprotocol.io/specification/2024-11-05/basic/utilities/progress),
  and [Streamable HTTP transport specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports).

### P0: Protocol fidelity and deployment safety

- [x] Make the lazy stdio proxy advertise and serve the same static MCP
  capabilities as the backend without starting GDB.
  - It currently advertises only tools and returns empty `resources/list` and
    `prompts/list` results, even though the backend has reference resources.
  - Add accurate `initialize` capabilities plus `resources/list`,
    `resources/read`, and any static prompt endpoints; preserve lazy startup.
  - Acceptance: direct-backend and proxy JSON-RPC contract tests discover and
    read the same static resources/prompts, and a resource/prompt request does
    not create a backend process or GDB session.

- [x] Harden Streamable HTTP deployment before treating it as a supported remote
  service.
  - Continue binding to loopback by default; reject non-loopback hosts unless an
    explicit acknowledgement is supplied.
  - Provide an authentication integration point compatible with MCP HTTP
    authorization (or an explicitly documented, tested reverse-proxy mode), and
    do not allow unsafe tools to be exposed accidentally.
  - Acceptance: tests cover public-bind refusal, authenticated and rejected
    requests, and an HTTP smoke workflow; the deployment guide includes TLS,
    proxy, and token-rotation guidance.

### P1: Agent-facing debugging workflows

- [x] Expose user-invoked MCP prompts for the main safe workflows.
  - Start with `debug_local`, `triage_core`, `debug_remote`, and
    `analyze_stripped_binary`; each should state prerequisites, the tool
    sequence, stopping conditions, and the unsafe-mode boundary.
  - Acceptance: `prompts/list` and `prompts/get` contract tests cover required
    and optional arguments, validation, and safe interpolation of user paths.

- [x] Report bounded MCP progress for long-running operations and preserve the
  existing cancellation guarantees.
  - Cover run/continue, `rr` recording and replay startup, managed gdbserver
    connection, and large external inspection commands when a client supplies a
    progress token.
  - Rate-limit notifications and stop them promptly on completion, timeout, or
    cancellation.
  - Acceptance: transport-level tests observe ordered progress, no notification
    after termination, and no leaked pending command or child process.

- [x] Add reusable, explicitly security-gated GDB initialization profiles.
  - Support a named/profiled set of startup commands or init files for local,
    core, and remote sessions; treat arbitrary initialization as unsafe because
    GDB command files can execute commands outside the debugger.
  - Record the profile identity and resulting configuration in session
    diagnostics so runs are reproducible.
  - Acceptance: a fixture verifies source-directory, pretty-printer, sysroot,
    and solib-search-path setup; unsafe initialization is denied by default.

- [x] Export a redacted debugging-session bundle for agent-run diagnosis.
  - Include immutable session metadata, tool/MI event chronology, selected
    breakpoints, GDB version, and a reproducible command summary; exclude raw
    memory, evaluated values, and environment secrets by default.
  - Build on `gdb_session_diagnostics` rather than a separate UI, while leaving
    room for a future local inspector.
  - Acceptance: a bundle can explain a fixture failure without containing a
    planted secret; redaction and opt-in raw fields have dedicated tests.

- [x] Add an opt-in core tool profile that actually reduces `tools/list`.
  - The current decision guide identifies core tools, but every client still
    receives the full surface. Keep the complete profile compatible by default
    and allow constrained clients to request core-only discovery.
  - Acceptance: core, full, and advanced-profile snapshots are stable; every
    documented cookbook either uses the core profile or declares its advanced
    dependency.

### P2: Reliability, performance, and release confidence

- [x] Replace decimal offset cursors with opaque, session/version-bound cursors
  for mutable or externally produced output.
  - Retain the current pagination shape, but prevent a cursor for one session or
    collection snapshot being reused against another and return a clear stale
    cursor error after invalidation.
  - Acceptance: pagination tests cover concurrent mutations, cross-session
    cursor rejection, expiry, and complete traversal without duplicate rows.

- [x] Make response regression checks token-aware.
  - Continue the existing character limits, then add deterministic serialized
    response-size fixtures and a documented conservative token estimate for
    context, backtrace-all, symbols, readelf, and memory workflows.
  - Avoid lossy MI-number rewriting; remove duplicate raw/structured data before
    introducing a compact wire representation.
  - Acceptance: CI fails on budget regressions and reports the largest fixture
    responses in bytes and estimated tokens.

- [x] Expand live compatibility CI around actual GDB behaviour.
  - Run the smoke and transcript suites on the supported Python/GDB matrix and
    add fixtures for C++, optimized binaries, shared libraries, PIE, remote
    gdbserver, and unavailable optional dependencies.
  - Record feature gates rather than assuming a GDB command exists from its
    version string alone.
  - Acceptance: CI artifacts identify the GDB build and enabled feature set;
    unsupported combinations skip with an actionable reason.

- [x] Add MCP interoperability and release-install checks.
  - Exercise stdio and Streamable HTTP initialization, tools, resources,
    prompts, cancellation, and pagination with a real MCP client harness, not
    only direct FastMCP calls.
  - Build the wheel in CI, install it into a clean environment, run the lazy
    startup check, and validate registry metadata against the published tool
    surface.
  - Acceptance: the clean-install matrix catches a missing package asset,
    protocol capability mismatch, or accidental eager backend startup.

## Completed baseline (July 2026)

Maintenance backlog for turning `gdb-mcp` from a broad feature surface into a
stable, easier-to-maintain debugger server. Completed in commit `66736f2` and
the subsequent focused commits.

This list was based on a July 2026 review of the local codebase and comparable
open source GDB MCP servers, including `signal-slot/mcp-gdb`,
`pansila/mcp_server_gdb`, `Ipiano/gdb-mcp`, `schuay/gdb-mcp`,
`maxholman/mcp-gdbmi`, `hnmr293/gdb-mcp`, and `jtang613/gdb-mcp`.

## P0: Maintainability

- [x] Split `src/gdb_mcp/server.py` by tool domain.
  - Target modules: `tools/session.py`, `tools/execution.py`,
    `tools/breakpoints.py`, `tools/inspection.py`, `tools/binary.py`,
    `tools/remote.py`, and `tools/diagnostics.py`.
  - Keep a small central registration/entry module so MCP startup behavior stays
    unchanged.
  - Acceptance: no tool names or public argument names change; full test suite
    remains green.

- [x] Introduce shared response models.
  - Define common shapes for success, error, session, command, and diagnostic
    responses.
  - Reduce ad hoc dictionaries and inconsistent response fields across tools.
  - Acceptance: contract tests cover representative responses for each tool
    family.

- [x] Preserve the cancellation and cleanup guarantees during refactors.
  - Keep coverage for cancelled GDB commands, cancelled gdbserver connects,
    pending-command cleanup, and managed gdbserver teardown.
  - Acceptance: async lifecycle tests still exercise cancellation before and
    after command dispatch.

## P1: Agent Experience

- [x] Move long-form reference material into MCP resources.
  - Add resources such as `gdb://workflows/basic`,
    `gdb://workflows/core-dump`, `gdb://workflows/binary-analysis`,
    `gdb://commands/mi`, and `gdb://tools/decision-guide`.
  - Keep `gdb_command_reference` as a compact index that points clients to the
    resources.
  - Acceptance: clients can discover workflows without calling a large tool
    response.

- [x] Define a smaller recommended tool profile.
  - Document a core default set of roughly 20-30 tools for common debugging.
  - Keep binary-analysis, reverse-debugging, remote-target, diagnostics, and
    unsafe tools discoverable but clearly grouped as advanced workflows.
  - Acceptance: `gdb_capabilities` identifies core and advanced tool groups.

- [x] Add response-size profiles.
  - Support consistent `summary`, `structured`, and `raw` output modes where
    useful.
  - Apply the same strategy to context, backtrace, variables, symbols, readelf,
    and memory-heavy tools.
  - Acceptance: large outputs have predictable bounded responses.

- [x] Add pagination or resource handles for large outputs.
  - Candidate tools: symbols, GOT/relocations, readelf output, memory dumps,
    thread-all backtraces, and command history.
  - Acceptance: tools can return a cursor or resource handle instead of forcing
    all data into one MCP response.

## P1: Debugging Capability

- [x] Add native rr workflows.
  - Add tools such as `gdb_rr_record` and `gdb_start_rr_replay_session`.
  - Reuse existing reverse/context tools for replay sessions where possible.
  - Acceptance: a smoke test records a small binary and replays it when `rr` is
    available, skipping cleanly otherwise.

- [x] Expand remote-target coverage.
  - Cover IPv6 endpoints, Unix-socket style targets if supported by GDB, custom
    `sysroot`, and `solib-search-path` workflows.
  - Acceptance: contract tests cover validation; smoke tests cover available
    local `gdbserver` paths.

- [x] Add core-dump workflow tests with sysroot/search-path setup.
  - Acceptance: a smoke test verifies core loading plus post-load path
    configuration and thread/backtrace inspection.

## P2: Distribution

- [x] Publish stable PyPI releases.
  - Keep `uvx --from git+...` documented, but make `uvx gdb-mcp` or
    `pipx install gdb-mcp` viable.
  - Acceptance: README install paths include PyPI and tagged Git options.

- [x] Add registry metadata for MCP discovery sites.
  - Consider `server.json` or equivalent metadata used by MCP marketplaces.
  - Acceptance: install instructions are machine-readable where practical.

- [x] Evaluate Nix/Homebrew packaging.
  - Nix is especially useful for GDB/gdbserver/rr dependencies.
  - Acceptance: documented optional install path or a clear decision not to
    support it yet.

## P2: Quality

- [x] Strengthen MI parser tests.
  - Add real GDB/MI transcript fixtures for async records, stream records,
    errors, nested values, and malformed lines.
  - Consider property/fuzz-style parser tests for `src/gdb_mcp/mi.py`.
  - Acceptance: parser regressions fail without needing a live GDB process.

- [x] Add differential checks against known MI parsers or captured GDB output.
  - Use this only for parser confidence; avoid adding heavyweight runtime
    dependencies to the package.
  - Acceptance: fixture-based comparison documents intentional differences.

- [x] Improve installer and lazy proxy coverage.
  - Current project coverage is strongest around server/session behavior; keep
    lifting coverage for install and proxy edge cases.
  - Acceptance: coverage gaps in `installer.py` and `lazy.py` are reduced for
    error handling and configuration branches.

- [x] Add performance and token-budget regression checks.
  - Track response sizes for common context, pwn context, symbol, and readelf
    workflows.
  - Acceptance: tests or scripts catch accidental large-response regressions.

## P2: Documentation

- [x] Add cookbook-style workflows.
  - Suggested topics: local source debugging, stripped binary analysis, core
    dump triage, remote gdbserver, managed gdbserver, attach/detach, reverse
    debugging, and unsafe-mode workflows.
  - Acceptance: each cookbook has a concrete tool sequence and expected result
    shape.

- [x] Document security tradeoffs per workflow.
  - Link each unsafe or destructive workflow back to `SECURITY.md`.
  - Acceptance: docs explain when to use containers, VMs, or dedicated users.

- [x] Add a compatibility matrix.
  - Track Python versions, GDB versions, Linux distributions, gdbserver, rr,
    and known unsupported platforms.
  - Acceptance: contributors can tell whether a failure is expected or a bug.
