.PHONY: lint test test-fast tools-doc tools-doc-check measure-tools eval validate-manifests build check

lint:
	uv run ruff check .

test:
	uv run pytest --cov=gdb_mcp --cov-report=term-missing

test-fast:
	uv run pytest -q

tools-doc:
	uv run python scripts/gen_tools_doc.py --write

tools-doc-check:
	uv run python scripts/gen_tools_doc.py --check

measure-tools:
	uv run python scripts/measure_tools.py

eval:
	uv run python scripts/run_eval_harness.py
	uv run python scripts/run_eval_harness.py --compare-profiles

validate-manifests:
	uv run python -m json.tool .claude-plugin/marketplace.json >/dev/null
	uv run python -m json.tool .claude-plugin/plugin.json >/dev/null
	uv run python -m json.tool .agents/plugins/marketplace.json >/dev/null
	uv run python -m json.tool plugins/gdb-mcp/.codex-plugin/plugin.json >/dev/null
	uv run python -m json.tool plugins/gdb-mcp/.mcp.json >/dev/null
	uv run python -m json.tool server.json >/dev/null
	uv run python -m json.tool gdb-mcp.meta.json >/dev/null

build:
	rm -rf dist
	uv build

check: lint tools-doc-check validate-manifests
	uv run python scripts/sync_release_version.py --check
	uv run python scripts/validate_registry_metadata.py
	uv run python scripts/check_lazy_startup.py --budget 5 --initialize-budget 3
	uv run python scripts/check_response_budgets.py
	uv run python scripts/run_eval_harness.py
	$(MAKE) test
	$(MAKE) build
	uv run python scripts/check_release_install.py dist/*.whl
