# Testing and Benchmarks

All local and CI checks share the `Makefile` entry points:

```bash
make check
```

Individual targets:

| Target | Purpose |
| --- | --- |
| `make lint` | Run `uv run ruff check .` |
| `make test` | Run full test suite with branch coverage |
| `make test-fast` | Run `pytest -q` without coverage |
| `make tools-doc` | Regenerate [docs/TOOLS.md](TOOLS.md) from live MCP tool schemas |
| `make tools-doc-check` | Verify [docs/TOOLS.md](TOOLS.md) matches live code |
| `make measure-tools` | Measure `tools/list` JSON bytes and estimated tokens per profile |
| `make eval` | Run deterministic evaluation scenarios and `full` vs `core` comparison |
| `make validate-manifests` | Validate JSON syntax and registry metadata (`server.json`, `gdb-mcp.meta.json`, plugins) |
| `make build` | Build wheel and sdist into `dist/` |
| `make check` | Full CI gate including clean-venv wheel installation and lazy startup check |

## Contract and Budget Scripts

- `uv run python scripts/check_mcp_contract.py` — print normalized MCP contract snapshot.
- `uv run python scripts/check_response_budgets.py` — check representative large responses against byte/token limits.
- `uv run python scripts/check_lazy_startup.py` — verify `initialize` and `tools/list` never spawn the backend.
- `uv run python scripts/probe_gdb_features.py` — emit host GDB feature-probe JSON.
