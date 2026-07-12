# Cookbook Workflows

These workflows mirror the MCP resources exposed by the server and give concrete
tool sequences for common debugger tasks. Every session-scoped tool requires the
`session_id` returned by the first session tool.

Security guidance for all workflows lives in [SECURITY.md](../SECURITY.md).

## Local Source Debugging

Use when a local executable has symbols or source paths.

Tool sequence:

1. `gdb_create_session` with `program`, optional `args`, and optional `cwd`.
2. `gdb_set_breakpoint` at `main`, `file.c:line`, or another GDB location.
3. `gdb_run_and_context` with a finite `timeout`.
4. `gdb_context`, `gdb_backtrace`, `gdb_locals`, and `gdb_source` for inspection.
5. `gdb_continue_and_context`, `gdb_step_and_context`, or `gdb_next_and_context`.
6. `gdb_close_session`.

Expected result shape: `ok`, `session_id`, `summary`, `location`, `backtrace`,
and `locals`.

Security tradeoff: the inferior executes with the server account permissions.
Use a dedicated user, container, or VM for untrusted programs.

## Stripped Binary Analysis

Use when source and symbols are sparse and address-oriented context matters.

Tool sequence:

1. `gdb_create_session`.
2. `gdb_binary_summary` with `output="summary"` or `output="structured"`.
3. `gdb_pwn_context` with bounded `telescope_count` and `nearpc_lines`.
4. `gdb_address_info`, `gdb_rva_info`, `gdb_piebase`, and `gdb_vmmap_structured`.
5. `gdb_symbols` and `gdb_got` with `query`, `cursor`, and `page_size`.
6. `gdb_break_rva` when a module-relative breakpoint is needed.

Expected result shape: `summary`, `security`, `mapping_count`, `pc`, `sp`,
`nearpc`, and paginated `symbols` or `entries`.

Security tradeoff: inspection can expose secrets in memory and file paths.
Prefer `summary` output before raw memory, symbol, or readelf payloads.

## Core Dump Triage

Use when investigating a post-mortem Linux core file.

Tool sequence:

1. `gdb_load_core` with `core_path` and optional `program`.
2. `gdb_set_remote_paths` with `sysroot` or `solib_search_path` if libraries are missing.
3. `gdb_threads`.
4. `gdb_thread_apply_all_backtrace` with bounded `max_frames`.
5. `gdb_context` and `gdb_shared_libraries`.
6. `gdb_close_session`.

Expected result shape: `session`, `threads`, `backtrace`, `location`, and
`locals`.

Security tradeoff: loading a core does not run the target, but core files can
contain secrets. Keep copied production cores in isolated storage.

## Remote Gdbserver

Use when connecting to an existing `gdbserver` endpoint.

Tool sequence:

1. `gdb_connect_gdbserver` with `endpoint`, optional `program`, `sysroot`, and
   `solib_search_path`.
2. `gdb_gdbserver_status`.
3. `gdb_set_breakpoint`.
4. `gdb_continue_and_context` or `gdb_interrupt`.
5. `gdb_detach_gdbserver` or `gdb_close_session`.

Expected result shape: `session`, `gdbserver_endpoint`, `summary`, and current
context fields.

Security tradeoff: never expose debug ports to untrusted networks. Bind local
or tunnel endpoints and use host firewall policy.

## Managed Gdbserver

Use when the MCP server should launch local `gdbserver` and connect GDB to it.

Tool sequence:

1. `gdb_launch_gdbserver` with `program`, `listen`, optional `target_endpoint`,
   and optional remote paths.
2. `gdb_gdbserver_status`.
3. `gdb_run_and_context` or `gdb_continue_and_context`.
4. `gdb_detach_gdbserver` or `gdb_close_session`.

Expected result shape: `session`, managed `gdbserver` PID, endpoint, and compact
execution context.

Security tradeoff: this starts another local process. Use a dedicated user or
container for untrusted binaries.

## Attach And Detach

Use when a process is already running under the same Linux permission boundary.

Tool sequence:

1. `gdb_attach` with `pid`, optional `program`, and optional `session_id`.
2. `gdb_context`.
3. `gdb_threads` and `gdb_select_thread` when the process is multithreaded.
4. `gdb_backtrace`, `gdb_locals`, and `gdb_eval_expression`.
5. `gdb_detach`.

Expected result shape: `session`, `summary`, selected frame, threads, and
bounded stack data.

Security tradeoff: attach can stop or inspect sensitive local processes. Run
the server as a dedicated user with only the processes it should debug.

## Reverse Debugging

Use when reproducing or replaying a failure requires time travel.

Tool sequence:

1. `gdb_rr_record` to capture a run when `rr` is available.
2. `gdb_start_rr_replay_session` to open a replay session.
3. `gdb_context`.
4. `gdb_reverse_continue_and_context`, `gdb_reverse_step_and_context`, or
   `gdb_reverse_next_and_context`.
5. `gdb_stop_recording` if GDB process recording was used instead of rr.

Expected result shape: `trace_dir`, `session`, `recording` state, and compact
reverse-execution context.

Security tradeoff: rr records can contain memory and system interaction data.
Store traces like sensitive debugging artifacts.

## Unsafe Mode

Use only when explicit target mutation or raw GDB commands are required.

Tool sequence:

1. Start the proxy with `--unsafe` or `GDB_MCP_ALLOW_UNSAFE=1`.
2. Prefer narrow unsafe tools: `gdb_call_function`, `gdb_set_variable`,
   `gdb_write_memory`, or `gdb_breakpoint_commands`.
3. Use `gdb_execute` only when no dedicated tool covers the operation.
4. Return to normal mode for routine inspection.

Expected result shape: normal command responses with `ok`, `command`, `results`,
and bounded raw output when requested.

Security tradeoff: unsafe mode can execute target code, mutate memory, and run
arbitrary GDB commands. Use a VM, container, or disposable dedicated user.
