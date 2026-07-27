# Roadmap

Reviewed 2026-07-27. Current released version: `0.4.0`.

The July maintenance backlogs are complete. This roadmap now tracks only work
that has not shipped, grouped by delivery horizon instead of by a growing list
of historical priorities. Version headings are planning targets, not release
date promises.

## Direction

- Preserve safe, structured debugger workflows before expanding the tool
  surface. Raw GDB access remains opt-in.
- Keep stdio startup lazy and keep remote HTTP deployment explicit,
  authenticated, and isolated.
- Prefer reproducible workflows, bounded responses, and actionable failures
  over client-specific presentation features.
- Require deterministic protocol tests for every public contract change and a
  live-GDB test where behavior depends on GDB itself.
- Move completed work to `CHANGELOG.md`; do not retain checked tasks in the
  active roadmap.

## Now — 0.5.0 release and contract stability

### P0: Release integrity

- [ ] Publish the completed July follow-up work as a coherent release.
  - Populate the `Unreleased` changelog from the commits after `0.4.0`, choose
    the release version, and synchronize package metadata, lock data, registry
    metadata, plugin manifests, and pinned install examples.
  - Acceptance: version-reference, registry, lazy-startup, response-budget, full
    test, build, and clean-wheel-install checks pass from a clean checkout.

- [ ] Define and enforce the public MCP compatibility contract.
  - Snapshot initialize capabilities, prompt/resource metadata, and complete
    tool input schemas for each discovery profile; the current snapshots cover
    tool names only.
  - Document additive, breaking, and deprecated changes and the minimum notice
    required before removing a public tool or field.
  - Acceptance: CI reports a readable contract diff and rejects an unapproved
    breaking change; the policy is linked from `CONTRIBUTING.md`.

- [ ] Complete a pre-release security and deployment review.
  - Exercise malformed authentication, forwarded host/origin handling,
    disconnects, concurrent HTTP clients, session isolation, and unsafe-mode
    combinations through the transport rather than direct function calls.
  - Keep reverse-proxy guidance vendor-neutral and verify every public-listener
    requirement against an integration fixture.
  - Acceptance: the threat model and tested deployment behavior agree, and no
    rejected request starts GDB or leaves a session or child process behind.

### P1: Runtime resilience

- [ ] Make session resource limits enforceable without agent housekeeping.
  - Add an optional idle-session TTL, prune dead sessions before enforcing the
    session limit, and expose bounded retention settings for command/event
    history.
  - Preserve the explicit `gdb_close_idle_sessions` tool for manual cleanup and
    keep automatic cleanup disabled by default for compatibility.
  - Acceptance: fake-clock tests cover expiry during idle, running, disconnected,
    and shutdown states with no process or task leaks.

- [ ] Standardize failures across all tool families.
  - Define stable error codes, retryability, and an optional suggested action
    while retaining concise human-readable messages.
  - Convert validation, dependency, GDB/MI, timeout, cancellation, stale-cursor,
    and policy-denial paths without exposing secrets or raw subprocess output by
    default.
  - Acceptance: representative contract tests cover each error category and
    existing success response shapes remain unchanged.

## Next — 0.6.0 agent effectiveness and maintainability

### P1: Measurable debugging outcomes

- [ ] Add a scenario-based agent evaluation harness.
  - Include local source bugs, optimized/stripped binaries, core dumps, shared
    libraries, remote gdbserver, and unavailable dependencies.
  - Record completion, tool-call count, serialized bytes, estimated tokens,
    elapsed time, and cleanup state without requiring a hosted model in CI.
  - Acceptance: deterministic scripted baselines run in CI and make workflow or
    response-budget regressions visible per scenario.

- [ ] Improve source and debug-information discovery.
  - Provide explicit, security-reviewed setup for source maps, separate debug
    files, build IDs, and opt-in debuginfod use; record the resolved setup in
    session diagnostics and exported bundles.
  - Acceptance: fixtures cover relocated source, a split-debug executable, and
    an unavailable symbol server with actionable fallback guidance.

- [ ] Add opt-in operational observability.
  - Emit structured logs to stderr with request/session correlation and redacted
    lifecycle, latency, timeout, and cleanup events; never write protocol logs
    to stdout.
  - Acceptance: logging is off or minimal by default, planted secrets are
    redacted, and tests prove stdio JSON-RPC remains uncontaminated.

### P2: Internal boundaries

- [ ] Split the largest tool modules behind unchanged registration APIs.
  - Separate inspection formatting/pagination from GDB commands, and separate
    ELF/readelf execution from binary-analysis interpretation.
  - Acceptance: public tool names, argument schemas, annotations, profile
    membership, and response fixtures are unchanged after the refactor.

- [ ] Broaden the GDB/MI compatibility corpus without adding a runtime parser
  dependency.
  - Capture sanitized transcripts from supported distro GDB builds and add
    property tests for escaping, nesting depth, malformed input, and async
    record ordering.
  - Acceptance: every parser fix adds a minimized fixture and all corpus cases
    enforce bounded parse time and memory.

## Later — ecosystem options

These items require evidence from users or maintainers before they are promoted
to a release milestone.

- [ ] Evaluate a maintained Nix flake/package for reproducible GDB, gdbserver,
  compiler, and optional rr dependencies.
- [ ] Evaluate cross-architecture remote debugging with explicit architecture,
  sysroot, and multiarch-GDB compatibility reporting.
- [ ] Evaluate additional MCP client and authorization-provider fixtures when
  they reveal protocol or deployment behavior not covered by the current
  stdio/Streamable HTTP harness.

## Non-goals for the current roadmap

- Turning `gdb-mcp` into a general shell or enabling unsafe tools by default.
- Adding more thin wrappers around raw GDB commands without a demonstrated
  agent workflow.
- Claiming local macOS or Windows debugging support without dedicated CI and
  maintainership.
- Building an IDE, terminal UI, or hosted multi-tenant debugging service.

## Completed milestones

- July 2026 baseline (`66736f2` and focused follow-ups): modular tool domains,
  shared responses, cancellation cleanup, resources, compact profiles, bounded
  and paginated outputs, rr and remote/core workflows, packaging, parser tests,
  cookbooks, and compatibility documentation.
- July 2026 protocol and reliability follow-up (`51c999a`, `4a17615`, and
  `e52ae61`): lazy static resources/prompts, HTTP safety, workflow prompts,
  progress, initialization profiles, redacted bundles, real discovery profiles,
  opaque cursors, token budgets, live compatibility CI, and MCP/release-install
  interoperability checks.

Release-level detail belongs in `CHANGELOG.md`; the Git history remains the
source for implementation-level detail.
