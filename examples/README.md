# Linux Walkthrough

This example exercises the supported local Linux path.

## Build

```bash
cc -g -gdwarf-4 -O0 examples/hello.c -o /tmp/gdb-mcp-hello
```

## Start the MCP Server

From a checkout:

```bash
uv run gdb-mcp
```

From Git:

```bash
uvx --from git+https://github.com/BeaCox/gdb-mcp.git@v0.2.0 gdb-mcp
```

## Tool Flow

Call `gdb_create_session`:

```json
{
  "program": "/tmp/gdb-mcp-hello"
}
```

Set a breakpoint:

```json
{
  "session_id": "<session_id>",
  "location": "main"
}
```

Run to the breakpoint with `gdb_run`:

```json
{
  "session_id": "<session_id>",
  "timeout": 10
}
```

Inspect state:

```json
{
  "session_id": "<session_id>"
}
```

Useful inspection tools at this point:

- `gdb_current_location`
- `gdb_backtrace`
- `gdb_locals`
- `gdb_eval_expression` with `{"expression": "value"}`
- `gdb_disassemble_current_frame`
- `gdb_info_files`

Continue to exit:

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
`gdb_execute` require launching the server with:

```bash
gdb-mcp --unsafe
```

or:

```bash
GDB_MCP_ALLOW_UNSAFE=1 gdb-mcp
```
