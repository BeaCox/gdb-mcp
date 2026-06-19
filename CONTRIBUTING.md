# Contributing

Contributions are welcome through focused issues and pull requests.
By participating, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Setup

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
```

GDB-dependent smoke tests skip automatically when GDB or a C compiler is not
available. New protocol behavior should also have a deterministic fake-GDB test so
CI does not depend only on host debugger behavior.

## Pull Requests

- Keep tools explicit about the required `session_id`.
- Preserve structured return shapes and MCP tool metadata.
- Add regression tests for MI parsing, lifecycle, or process cleanup changes.
- Avoid writing logs to stdout because stdio MCP reserves stdout for protocol data.
- Document new environment variables, transports, and security-sensitive behavior.

Run the full verification set before submitting:

```bash
uv run ruff check .
uv run pytest --cov=gdb_mcp
uv build
```
