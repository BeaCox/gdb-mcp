"""Public MCP compatibility contract normalization and diff checking."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def normalize_tool_contract(tool: dict[str, Any]) -> dict[str, Any]:
    """Normalize a serialized MCP tool definition into a stable contract record."""

    input_schema = tool.get("inputSchema")
    properties = input_schema.get("properties") if isinstance(input_schema, dict) else {}
    required = input_schema.get("required") if isinstance(input_schema, dict) else []
    annotations = tool.get("annotations")
    normalized_annotations = (
        {
            key: annotations.get(key)
            for key in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
            if key in annotations
        }
        if isinstance(annotations, dict)
        else {}
    )
    return {
        "name": str(tool.get("name", "")),
        "description": str(tool.get("description", "")),
        "inputSchema": {
            "type": (
                input_schema.get("type", "object")
                if isinstance(input_schema, dict)
                else "object"
            ),
            "required": sorted(str(item) for item in (required or [])),
            "properties": {
                str(key): value
                for key, value in sorted((properties or {}).items())
            },
        },
        "annotations": normalized_annotations,
    }


def build_contract_snapshot(
    *,
    capabilities: dict[str, Any],
    profiles: dict[str, list[dict[str, Any]]],
    resources: list[dict[str, Any]],
    prompts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a deterministic JSON-serializable MCP contract snapshot."""

    normalized_profiles: dict[str, dict[str, dict[str, Any]]] = {}
    for profile_name, tools in sorted(profiles.items()):
        normalized_tools = [normalize_tool_contract(tool) for tool in tools]
        normalized_profiles[profile_name] = {
            item["name"]: item for item in sorted(normalized_tools, key=lambda t: t["name"])
        }

    normalized_resources = {
        str(item["uri"]): {
            "uri": str(item["uri"]),
            "name": str(item.get("name", "")),
            "mimeType": str(item.get("mimeType", "")),
        }
        for item in sorted(resources, key=lambda r: str(r.get("uri", "")))
    }

    normalized_prompts: dict[str, dict[str, Any]] = {}
    for item in sorted(prompts, key=lambda p: str(p.get("name", ""))):
        args = item.get("arguments") or []
        normalized_prompts[str(item["name"])] = {
            "name": str(item["name"]),
            "arguments": {
                str(arg["name"]): {"required": bool(arg.get("required", False))}
                for arg in sorted(args, key=lambda a: str(a.get("name", "")))
                if isinstance(arg, dict) and "name" in arg
            },
        }

    return {
        "schema_version": 1,
        "capabilities": capabilities,
        "profiles": normalized_profiles,
        "resources": normalized_resources,
        "prompts": normalized_prompts,
    }


@dataclass(frozen=True)
class ContractDiff:
    """Result of comparing a baseline contract snapshot against a current snapshot."""

    breaking: list[str] = field(default_factory=list)
    additive: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.breaking

    def format_report(self) -> str:
        lines: list[str] = []
        if self.breaking:
            lines.append("Breaking changes:")
            lines.extend(f"  - {item}" for item in self.breaking)
        if self.additive:
            lines.append("Additive changes:")
            lines.extend(f"  + {item}" for item in self.additive)
        if not lines:
            lines.append("No MCP compatibility contract changes detected.")
        return "\n".join(lines)


def _schema_signature(prop: Any) -> Any:
    if not isinstance(prop, dict):
        return prop
    sig: dict[str, Any] = {}
    for key in ("type", "enum", "items", "anyOf", "oneOf", "allOf"):
        if key in prop:
            sig[key] = prop[key]
    return sig


def _diff_tool_schema(
    profile_name: str,
    tool_name: str,
    old_tool: dict[str, Any],
    new_tool: dict[str, Any],
    breaking: list[str],
    additive: list[str],
) -> None:
    old_schema = old_tool.get("inputSchema", {})
    new_schema = new_tool.get("inputSchema", {})
    old_props = old_schema.get("properties", {})
    new_props = new_schema.get("properties", {})
    old_req = set(old_schema.get("required", []))
    new_req = set(new_schema.get("required", []))

    for prop_name in sorted(old_props):
        if prop_name not in new_props:
            breaking.append(f"[{profile_name}] {tool_name}: removed parameter '{prop_name}'")
            continue
        if _schema_signature(old_props[prop_name]) != _schema_signature(new_props[prop_name]):
            breaking.append(
                f"[{profile_name}] {tool_name}: changed schema for parameter '{prop_name}'"
            )

    for prop_name in sorted(new_props):
        if prop_name not in old_props:
            if prop_name in new_req:
                breaking.append(
                    f"[{profile_name}] {tool_name}: added required parameter '{prop_name}'"
                )
            else:
                additive.append(
                    f"[{profile_name}] {tool_name}: added optional parameter '{prop_name}'"
                )
        elif prop_name in new_req and prop_name not in old_req:
            breaking.append(
                f"[{profile_name}] {tool_name}: parameter '{prop_name}' became required"
            )

    old_ann = old_tool.get("annotations", {})
    new_ann = new_tool.get("annotations", {})
    if old_ann.get("readOnlyHint") is True and new_ann.get("readOnlyHint") is False:
        breaking.append(f"[{profile_name}] {tool_name}: readOnlyHint changed True -> False")
    if old_ann.get("destructiveHint") is False and new_ann.get("destructiveHint") is True:
        breaking.append(f"[{profile_name}] {tool_name}: destructiveHint changed False -> True")


def diff_contract(baseline: dict[str, Any], current: dict[str, Any]) -> ContractDiff:
    """Compare baseline and current contract snapshots and classify changes."""

    breaking: list[str] = []
    additive: list[str] = []

    old_caps = baseline.get("capabilities", {})
    new_caps = current.get("capabilities", {})
    for cap_name in sorted(old_caps):
        if cap_name not in new_caps:
            breaking.append(f"capabilities: removed capability '{cap_name}'")
    for cap_name in sorted(new_caps):
        if cap_name not in old_caps:
            additive.append(f"capabilities: added capability '{cap_name}'")

    old_profiles = baseline.get("profiles", {})
    new_profiles = current.get("profiles", {})
    for profile_name, old_tools in sorted(old_profiles.items()):
        if profile_name not in new_profiles:
            breaking.append(f"profile '{profile_name}': removed")
            continue
        new_tools = new_profiles[profile_name]
        for tool_name, old_tool in sorted(old_tools.items()):
            if tool_name not in new_tools:
                breaking.append(f"[{profile_name}] tool '{tool_name}': removed")
                continue
            _diff_tool_schema(
                profile_name,
                tool_name,
                old_tool,
                new_tools[tool_name],
                breaking,
                additive,
            )
        for tool_name in sorted(new_tools):
            if tool_name not in old_tools:
                additive.append(f"[{profile_name}] tool '{tool_name}': added")

    for profile_name in sorted(new_profiles):
        if profile_name not in old_profiles:
            additive.append(f"profile '{profile_name}': added")

    old_resources = baseline.get("resources", {})
    new_resources = current.get("resources", {})
    for uri in sorted(old_resources):
        if uri not in new_resources:
            breaking.append(f"resource '{uri}': removed")
    for uri in sorted(new_resources):
        if uri not in old_resources:
            additive.append(f"resource '{uri}': added")

    old_prompts = baseline.get("prompts", {})
    new_prompts = current.get("prompts", {})
    for name, old_prompt in sorted(old_prompts.items()):
        if name not in new_prompts:
            breaking.append(f"prompt '{name}': removed")
            continue
        old_args = old_prompt.get("arguments", {})
        new_args = new_prompts[name].get("arguments", {})
        for arg_name in sorted(old_args):
            if arg_name not in new_args:
                breaking.append(f"prompt '{name}': removed argument '{arg_name}'")
        for arg_name, arg_meta in sorted(new_args.items()):
            if arg_name not in old_args:
                if arg_meta.get("required"):
                    breaking.append(
                        f"prompt '{name}': added required argument '{arg_name}'"
                    )
                else:
                    additive.append(
                        f"prompt '{name}': added optional argument '{arg_name}'"
                    )
            elif arg_meta.get("required") and not old_args[arg_name].get("required"):
                breaking.append(
                    f"prompt '{name}': argument '{arg_name}' became required"
                )
    for name in sorted(new_prompts):
        if name not in old_prompts:
            additive.append(f"prompt '{name}': added")

    return ContractDiff(breaking=breaking, additive=additive)
