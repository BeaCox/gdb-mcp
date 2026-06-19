# Tool Reference

`gdb-mcp` exposes explicit tools for common GDB workflows. Every tool that
operates on a session requires a `session_id`; there is no implicit current
session.

Safety levels:

- `Read`: reads debugger or target state.
- `Execution`: starts, resumes, interrupts, attaches, detaches, or kills a target.
- `Mutation`: changes debugger state such as selected frame, breakpoints, or paths.
- `Unsafe`: requires `--unsafe` or `GDB_MCP_ALLOW_UNSAFE=1`.

## Session Management

| Tool | Safety | Main Parameters | Purpose |
| --- | --- | --- | --- |
| `gdb_create_session` | Mutation | `program`, `args`, `cwd`, `gdb_path` | Start an isolated GDB process. |
| `gdb_attach` | Execution | `pid`, `program`, `session_id` | Attach to a local Linux process. |
| `gdb_load_core` | Mutation | `core_path`, `program`, `session_id` | Load a Linux core file. `core_path` must be a single unquoted MI argument. |
| `gdb_connect_gdbserver` | Mutation | `endpoint`, `program`, `extended`, `sysroot`, `solib_search_path` | Connect to an existing remote target. |
| `gdb_launch_gdbserver` | Execution | `program`, `listen`, `target_endpoint`, `args` | Launch local `gdbserver` and connect to it. |
| `gdb_list_sessions` | Read | none | List live sessions. |
| `gdb_status` | Read | `session_id` | Describe one session. |
| `gdb_close_session` | Mutation | `session_id` | Close GDB and any managed `gdbserver`. |
| `gdb_close_idle_sessions` | Mutation | `max_idle_seconds` | Close sessions idle for at least the given duration. |

## Execution

| Tool | Safety | Main Parameters | Purpose |
| --- | --- | --- | --- |
| `gdb_run` | Execution | `session_id`, `args`, `timeout`, `auto_interrupt` | Run or restart the inferior. |
| `gdb_run_and_context` | Execution | `session_id`, `args`, `timeout`, `max_frames`, `include_raw` | Run or restart, then return compact location, backtrace, and locals. |
| `gdb_restart` | Execution | `session_id`, `args`, `timeout`, `auto_interrupt` | Alias for a restart-style `gdb_run`. |
| `gdb_continue` | Execution | `session_id`, `timeout`, `auto_interrupt` | Continue execution until stop or timeout. |
| `gdb_continue_and_context` | Execution | `session_id`, `timeout`, `max_frames`, `include_raw` | Continue, then return compact stop or exit context. |
| `gdb_interrupt` | Execution | `session_id`, `timeout` | Interrupt a running target. |
| `gdb_signal` | Execution | `session_id`, `signal_name` | Resume with a signal such as `SIGTERM` or `0`. |
| `gdb_step` | Execution | `session_id`, `instruction` | Step into a line or instruction. |
| `gdb_step_and_context` | Execution | `session_id`, `instruction`, `timeout`, `max_frames`, `include_raw` | Step into, then return compact context. |
| `gdb_next` | Execution | `session_id`, `instruction` | Step over a line or instruction. |
| `gdb_next_and_context` | Execution | `session_id`, `instruction`, `timeout`, `max_frames`, `include_raw` | Step over, then return compact context. |
| `gdb_detach` | Execution | `session_id` | Detach from the current target. |
| `gdb_kill` | Execution | `session_id` | Kill the current inferior. |

## Breakpoints

| Tool | Safety | Main Parameters | Purpose |
| --- | --- | --- | --- |
| `gdb_set_breakpoint` | Mutation | `session_id`, `location`, `condition`, `temporary` | Set a breakpoint using GDB location syntax. |
| `gdb_set_watchpoint` | Mutation | `session_id`, `expression`, `access` | Set write, read, or access watchpoints with safe-expression filtering. |
| `gdb_enable_breakpoint` | Mutation | `session_id`, `number` | Enable a breakpoint. |
| `gdb_disable_breakpoint` | Mutation | `session_id`, `number` | Disable a breakpoint. |
| `gdb_breakpoint_condition` | Mutation | `session_id`, `number`, `condition` | Set or clear a safe breakpoint condition. |
| `gdb_breakpoint_commands` | Unsafe | `session_id`, `number`, `commands` | Set breakpoint command-list actions. |
| `gdb_delete_breakpoint` | Mutation | `session_id`, `number` | Delete a breakpoint. |
| `gdb_list_breakpoints` | Read | `session_id` | List breakpoints as MI data. |

## Threads and Frames

| Tool | Safety | Main Parameters | Purpose |
| --- | --- | --- | --- |
| `gdb_threads` | Read | `session_id` | List threads. |
| `gdb_select_thread` | Mutation | `session_id`, `thread_id` | Select a thread. |
| `gdb_backtrace` | Read | `session_id`, `max_frames` | List stack frames. |
| `gdb_thread_apply_all_backtrace` | Read | `session_id`, `max_frames` | Backtrace every thread. |
| `gdb_select_frame` | Mutation | `session_id`, `frame` | Select a stack frame. |
| `gdb_locals` | Read | `session_id` | List locals in the selected frame. |
| `gdb_stack_arguments` | Read | `session_id`, `max_frames` | List stack frame arguments. |
| `gdb_frame_variables` | Read | `session_id`, `mode` | List `locals`, `args`, or `all` variables. |

## Inspection

| Tool | Safety | Main Parameters | Purpose |
| --- | --- | --- | --- |
| `gdb_current_location` | Read | `session_id` | Return selected frame and last stop information. |
| `gdb_context` | Read | `session_id`, `max_frames`, `include_raw` | Return compact current location, backtrace, locals, and a summary. |
| `gdb_eval_expression` | Read | `session_id`, `expression` | Evaluate a safe expression. Rejects calls and mutations. |
| `gdb_print` | Read | `session_id`, `expression` | Print a safe expression using GDB formatting. |
| `gdb_call_function` | Unsafe | `session_id`, `expression` | Call an inferior function or evaluate unsafe expression. |
| `gdb_set_variable` | Unsafe | `session_id`, `expression`, `value` | Set an inferior variable or lvalue. |
| `gdb_disassemble` | Read | `session_id`, `location`, `start_address`, `end_address`, `mixed`, `raw_bytes` | Disassemble a location or range. |
| `gdb_disassemble_current_frame` | Read | `session_id`, `mixed`, `raw_bytes` | Disassemble around `$pc`. |
| `gdb_source` | Read | `session_id`, `location` | List source around current frame or location. |
| `gdb_find_source` | Read | `session_id`, `query`, `limit` | Search known source file paths. |
| `gdb_registers` | Read | `session_id`, `register_numbers`, `fmt` | Read registers. |
| `gdb_read_memory` | Read | `session_id`, `address`, `count` | Read raw memory bytes. |
| `gdb_write_memory` | Unsafe | `session_id`, `address`, `data_hex` | Write raw memory bytes. |
| `gdb_search_memory` | Read | `session_id`, `start_address`, `length`, `pattern` | Search memory with GDB `find`. |
| `gdb_read_c_string` | Read | `session_id`, `address`, `max_bytes` | Read a NUL-terminated string. |
| `gdb_shared_libraries` | Read | `session_id` | List shared libraries known to GDB. |
| `gdb_info_files` | Read | `session_id` | Return `info files`. |
| `gdb_memory_mappings` | Read | `session_id` | Return Linux process mappings when available. |

## Remote Targets

| Tool | Safety | Main Parameters | Purpose |
| --- | --- | --- | --- |
| `gdb_set_remote_paths` | Mutation | `session_id`, `sysroot`, `solib_search_path` | Set remote symbol/library paths. |
| `gdb_detach_gdbserver` | Execution | `session_id` | Detach from a remote target or managed `gdbserver`. |
| `gdb_gdbserver_status` | Read | `session_id` | Return managed `gdbserver` PID, endpoint, and status. |

## Diagnostics

| Tool | Safety | Main Parameters | Purpose |
| --- | --- | --- | --- |
| `gdb_recent_events` | Read | `session_id`, `limit` | Return recent MI async/result records. |
| `gdb_recent_commands` | Read | `session_id`, `limit` | Return recent commands sent to GDB. |
| `gdb_session_diagnostics` | Read | `session_id` | Return session state plus recent commands/events. |
| `gdb_server_health` | Read | none | Report version, dependency availability, safety mode, and sessions. |

## Advanced

| Tool | Safety | Main Parameters | Purpose |
| --- | --- | --- | --- |
| `gdb_execute` | Unsafe | `session_id`, `command`, `timeout`, `wait_for_stop`, `auto_interrupt` | Execute raw CLI or MI command. Disabled by default. |

## Examples

Set a breakpoint:

```json
{
  "session_id": "<session_id>",
  "location": "main"
}
```

Evaluate a safe expression:

```json
{
  "session_id": "<session_id>",
  "expression": "value + 1"
}
```

Read memory:

```json
{
  "session_id": "<session_id>",
  "address": "&value",
  "count": 4
}
```

Unsafe variable mutation requires unsafe mode:

```json
{
  "session_id": "<session_id>",
  "expression": "value",
  "value": "42"
}
```
