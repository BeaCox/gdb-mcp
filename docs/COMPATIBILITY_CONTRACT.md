# Public MCP Compatibility Contract

`gdb-mcp` treats its MCP discovery surface (initialization capabilities, tool
names, input schemas, tool annotations, static resource URIs, and prompt specs)
as a versioned public contract across `full`, `core`, and `advanced:*` discovery
profiles.

## Change Classification

### Additive Changes (Backward-Compatible)

Additive changes may ship in any minor or patch release:

- Adding a new `gdb_*` tool or a new `advanced:<group>` profile group.
- Adding an **optional** parameter (with a default value) to an existing tool or
  prompt.
- Adding new fields to an `ok: true` response payload while preserving existing
  required keys and types.
- Adding a new static `gdb://...` resource URI or prompt template.

### Breaking Changes

Breaking changes are rejected by `gdb_mcp.contract.diff_contract` unless
explicitly approved for a major or pre-1.0 minor deprecation cycle:

- Removing or renaming any public `gdb_*` tool, profile, resource URI, or
  prompt.
- Removing an input parameter, adding a new **required** parameter, making an
  optional parameter required, or narrowing a parameter's JSON Schema type/enum.
- Weakening safety annotations (`readOnlyHint` flipped `true -> false`, or
  `destructiveHint` flipped `false -> true`).

## Deprecation Notice Window

Before removing or incompatibly changing a public tool, parameter, or response
field:

1. Mark the item as deprecated in `TOOLS.md` and `CHANGELOG.md` for **at least
   one minor release** before removal.
2. Provide a non-breaking migration path (for example, keeping an additive alias
   or legacy flag such as `include_raw` alongside `output`).
3. Verify the contract diff with `python scripts/check_mcp_contract.py --check`.
