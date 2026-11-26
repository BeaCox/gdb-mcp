#!/usr/bin/env python3
"""Sync release-version references from pyproject.toml."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

PROJECT_VERSION_RE = re.compile(r'(?m)^version\s*=\s*"(?P<version>[^"]+)"\s*$')
RELEASE_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
TAG_RE = r"v\d+\.\d+\.\d+"
PACKAGE_SOURCE_PREFIX = "git+https://github.com/BeaCox/gdb-mcp.git@"
PYPI_DIST_NAME = "beacox-gdb-mcp"
PINNED_DIST_RE = re.compile(rf"{re.escape(PYPI_DIST_NAME)}==\d+\.\d+\.\d+")


def root_from_script() -> Path:
    return Path(__file__).resolve().parents[1]


def validate_release_version(version: str) -> str:
    if not RELEASE_VERSION_RE.fullmatch(version):
        raise ValueError("release version must use MAJOR.MINOR.PATCH, for example 0.4.0")
    return version


def project_version(root: Path) -> str:
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    match = PROJECT_VERSION_RE.search(text)
    if match is None:
        raise ValueError("pyproject.toml is missing project.version")
    return validate_release_version(match.group("version"))


def set_project_version(root: Path, version: str, *, check: bool) -> list[str]:
    path = root / "pyproject.toml"
    text = path.read_text(encoding="utf-8")
    next_text, count = PROJECT_VERSION_RE.subn(f'version = "{version}"', text, count=1)
    if count != 1:
        raise ValueError("pyproject.toml is missing project.version")
    if next_text == text:
        return []
    if not check:
        path.write_text(next_text, encoding="utf-8")
    return ["pyproject.toml"]


def sync_text_file(
    root: Path,
    relative: str,
    transform: Callable[[str], str],
    *,
    check: bool,
) -> list[str]:
    path = root / relative
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8")
    next_text = transform(text)
    if next_text == text:
        return []
    if not check:
        path.write_text(next_text, encoding="utf-8")
    return [relative]


def sync_json_file(
    root: Path,
    relative: str,
    transform: Callable[[dict[str, Any]], None],
    *,
    check: bool,
) -> list[str]:
    path = root / relative
    data = json.loads(path.read_text(encoding="utf-8"))
    before = json.dumps(data, sort_keys=True, separators=(",", ":"))
    transform(data)
    after = json.dumps(data, sort_keys=True, separators=(",", ":"))
    if after == before:
        return []
    if not check:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return [relative]


def replace_release_tags(text: str, version: str) -> str:
    tag = f"v{version}"
    text = re.sub(
        rf"{re.escape(PACKAGE_SOURCE_PREFIX)}{TAG_RE}",
        f"{PACKAGE_SOURCE_PREFIX}{tag}",
        text,
    )
    text = re.sub(rf"(BeaCox/gdb-mcp@){TAG_RE}", rf"\g<1>{tag}", text)
    text = re.sub(rf"(--ref\s+){TAG_RE}", rf"\g<1>{tag}", text)
    return PINNED_DIST_RE.sub(f"{PYPI_DIST_NAME}=={version}", text)


def set_manifest_version(version: str) -> Callable[[dict[str, Any]], None]:
    def transform(data: dict[str, Any]) -> None:
        if "version" not in data:
            raise ValueError("plugin manifest is missing version")
        data["version"] = version

    return transform


def _update_pinned_dist_args(args: list[Any], version: str, location: str) -> None:
    expected = f"{PYPI_DIST_NAME}=={version}"
    for index, value in enumerate(args):
        if isinstance(value, str) and value.startswith(f"{PYPI_DIST_NAME}=="):
            args[index] = expected
            return
    raise ValueError(f"{location} is missing pinned {PYPI_DIST_NAME}==<version>")


def set_plugin_manifest_version_and_source(version: str) -> Callable[[dict[str, Any]], None]:
    def transform(data: dict[str, Any]) -> None:
        if "version" not in data:
            raise ValueError("plugin manifest is missing version")
        data["version"] = version
        args = data["mcpServers"]["gdb"]["args"]
        _update_pinned_dist_args(args, version, ".claude-plugin/plugin.json")

    return transform


def set_mcp_package_source(version: str) -> Callable[[dict[str, Any]], None]:
    def transform(data: dict[str, Any]) -> None:
        args = data["mcpServers"]["gdb"]["args"]
        _update_pinned_dist_args(args, version, "plugins/gdb-mcp/.mcp.json")

    return transform


def set_meta_metadata(version: str) -> Callable[[dict[str, Any]], None]:
    def transform(data: dict[str, Any]) -> None:
        if "version" not in data:
            raise ValueError("gdb-mcp.meta.json is missing version")
        data["version"] = version
        _update_pinned_dist_args(
            data["install"]["pypi"]["args"],
            version,
            "gdb-mcp.meta.json install.pypi",
        )
        _update_pinned_dist_args(
            data["mcpServers"]["gdb"]["args"],
            version,
            "gdb-mcp.meta.json mcpServers.gdb",
        )
        args = data["install"]["taggedGit"]["args"]
        expected = f"{PACKAGE_SOURCE_PREFIX}v{version}"
        for index, value in enumerate(args):
            if isinstance(value, str) and value.startswith(PACKAGE_SOURCE_PREFIX):
                args[index] = expected
                return
        raise ValueError("gdb-mcp.meta.json is missing tagged Git package source")

    return transform


def set_server_registry_metadata(version: str) -> Callable[[dict[str, Any]], None]:
    def transform(data: dict[str, Any]) -> None:
        if "version" not in data:
            raise ValueError("server.json is missing version")
        data["version"] = version
        packages = data.get("packages") or []
        updated = False
        for pkg in packages:
            if (
                isinstance(pkg, dict)
                and pkg.get("registryType") == "pypi"
                and pkg.get("identifier") == PYPI_DIST_NAME
            ):
                pkg["version"] = version
                updated = True
        if not updated:
            raise ValueError("server.json is missing pypi package entry for beacox-gdb-mcp")

    return transform


def set_flake_version(version: str) -> Callable[[str], str]:
    def transform(text: str) -> str:
        return re.sub(
            r'(?m)^(\s*version\s*=\s*")\d+\.\d+\.\d+(";)$',
            rf"\g<1>{version}\g<2>",
            text,
            count=1,
        )

    return transform


def set_todo_released_version(version: str) -> Callable[[str], str]:
    def transform(text: str) -> str:
        return re.sub(
            r"(Current released version:\s*`)\d+\.\d+\.\d+(`)",
            rf"\g<1>{version}\g<2>",
            text,
            count=1,
        )

    return transform


def latest_changelog_version(root: Path) -> str | None:
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(r"(?m)^## \[(?P<version>\d+\.\d+\.\d+)\](?:\s+-\s+.*)?$", text)
    return match.group("version") if match is not None else None


def lockfile_project_version(root: Path) -> str | None:
    path = root / "uv.lock"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    for match in re.finditer(r"(?ms)^\[\[package\]\]\n(?P<body>.*?)(?=^\[\[package\]\]|\Z)", text):
        body = match.group("body")
        if re.search(rf'(?m)^name = "{re.escape(PYPI_DIST_NAME)}"$', body):
            version_match = re.search(r'(?m)^version = "(?P<version>[^"]+)"$', body)
            return version_match.group("version") if version_match is not None else None
    return None


def sync_release_version(root: Path, version: str, *, check: bool) -> tuple[list[str], list[str]]:
    changed: list[str] = []
    problems: list[str] = []

    if check and project_version(root) != version:
        problems.append(f"pyproject.toml has {project_version(root)}, expected {version}")
    else:
        changed.extend(set_project_version(root, version, check=check))

    for relative in ("README.md", "docs/INSTALL.md", "examples/README.md"):
        changed.extend(
            sync_text_file(
                root,
                relative,
                lambda text, release_version=version: replace_release_tags(text, release_version),
                check=check,
            )
        )

    changed.extend(
        sync_json_file(
            root,
            ".claude-plugin/plugin.json",
            set_plugin_manifest_version_and_source(version),
            check=check,
        )
    )
    changed.extend(
        sync_json_file(
            root,
            "plugins/gdb-mcp/.codex-plugin/plugin.json",
            set_manifest_version(version),
            check=check,
        )
    )
    changed.extend(
        sync_json_file(
            root,
            "plugins/gdb-mcp/.mcp.json",
            set_mcp_package_source(version),
            check=check,
        )
    )
    changed.extend(
        sync_json_file(root, "gdb-mcp.meta.json", set_meta_metadata(version), check=check)
    )
    changed.extend(
        sync_json_file(root, "server.json", set_server_registry_metadata(version), check=check)
    )
    changed.extend(
        sync_text_file(root, "flake.nix", set_flake_version(version), check=check)
    )
    changed.extend(
        sync_text_file(root, "TODO.md", set_todo_released_version(version), check=check)
    )

    changelog_version = latest_changelog_version(root)
    if changelog_version != version:
        problems.append(
            f"CHANGELOG.md latest release section is {changelog_version or 'missing'}, "
            f"expected {version}"
        )

    lock_version = lockfile_project_version(root)
    if lock_version != version:
        problems.append(
            f"uv.lock has {PYPI_DIST_NAME} {lock_version or 'missing'}, "
            f"expected {version}; run uv lock"
        )

    if check:
        problems.extend(f"{relative} is not synced to v{version}" for relative in changed)
    return changed, problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version",
        help="Set pyproject.toml to this release version before syncing references.",
    )
    parser.add_argument("--check", action="store_true", help="Check without writing files.")
    parser.add_argument("--root", type=Path, default=root_from_script())
    args = parser.parse_args()

    root = args.root.resolve()
    try:
        version = validate_release_version(args.version) if args.version else project_version(root)
        changed, problems = sync_release_version(root, version, check=args.check)
    except (KeyError, TypeError, ValueError) as exc:
        print(f"release version sync failed: {exc}", file=sys.stderr)
        return 2

    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1

    tag = f"v{version}"
    if changed:
        action = "Would update" if args.check else "Updated"
        print(f"{action} release version references to {tag}:")
        for relative in changed:
            print(f"- {relative}")
    else:
        print(f"Release version references are synced to {tag}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
