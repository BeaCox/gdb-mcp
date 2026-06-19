# Linux Walkthrough

This example exercises the supported local Linux path.

## Build

```bash
cc -g -gdwarf-4 -O0 examples/hello.c -o /tmp/gdb-mcp-hello
```

## Configure the MCP Server

From a checkout:

```bash
codex mcp add gdb -- uv run gdb-mcp
```

From Git:

```bash
codex mcp add gdb -- \
  uvx --from git+https://github.com/BeaCox/gdb-mcp.git@main gdb-mcp
```

`gdb-mcp` is the client-facing lazy stdio proxy. The MCP client discovers tools
at startup, and the full backend starts only when the first `gdb_*` tool is
called.

## Tool Flow

Call `gdb_create_session`:

```json
{
  "program": "/tmp/gdb-mcp-hello"
}
```

Set a breakpoint in the function that computes the result:

```json
{
  "session_id": "<session_id>",
  "location": "add"
}
```

Run to the breakpoint with `gdb_run_and_context`:

```json
{
  "session_id": "<session_id>",
  "timeout": 10
}
```

The result includes a compact summary plus `location`, `backtrace`, and `locals`
fields. Expected location:

```text
function: add
file: examples/hello.c
```

Expected locals:

```text
a = 2
b = 40
```

Useful inspection tools at this point:

- `gdb_context`
- `gdb_eval_expression` with `{"expression": "value"}`
- `gdb_disassemble_current_frame`
- `gdb_info_files`

Continue to exit with `gdb_continue_and_context`:

```json
{
  "session_id": "<session_id>",
  "timeout": 10
}
```

Close the session:

```json
{
  "session_id": "<session_id>"
}
```

## Unsafe Tools

The demo above does not require unsafe mode. Tools such as `gdb_call_function`,
`gdb_set_variable`, `gdb_write_memory`, `gdb_breakpoint_commands`, and raw
`gdb_execute` require launching the client-facing proxy with:

```bash
gdb-mcp --unsafe
```

or:

```bash
GDB_MCP_ALLOW_UNSAFE=1 gdb-mcp
```
