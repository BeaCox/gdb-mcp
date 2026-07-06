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
    return re.sub(rf"(--ref\s+){TAG_RE}", rf"\g<1>{tag}", text)


def set_manifest_version(version: str) -> Callable[[dict[str, Any]], None]:
    def transform(data: dict[str, Any]) -> None:
        if "version" not in data:
            raise ValueError("plugin manifest is missing version")
        data["version"] = version

    return transform


def set_mcp_package_source(version: str) -> Callable[[dict[str, Any]], None]:
    def transform(data: dict[str, Any]) -> None:
        args = data["mcpServers"]["gdb"]["args"]
        expected = f"{PACKAGE_SOURCE_PREFIX}v{version}"
        for index, value in enumerate(args):
            if isinstance(value, str) and value.startswith(PACKAGE_SOURCE_PREFIX):
                args[index] = expected
                return
        raise ValueError("plugins/gdb-mcp/.mcp.json is missing the package source")

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
        if re.search(r'(?m)^name = "gdb-mcp"$', body):
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

    for relative in ("README.md", "examples/README.md"):
        changed.extend(
            sync_text_file(
                root,
                relative,
                lambda text, release_version=version: replace_release_tags(text, release_version),
                check=check,
            )
        )

    for relative in (
        ".claude-plugin/plugin.json",
        "plugins/gdb-mcp/.codex-plugin/plugin.json",
    ):
        changed.extend(sync_json_file(root, relative, set_manifest_version(version), check=check))

    changed.extend(
        sync_json_file(
            root,
            "plugins/gdb-mcp/.mcp.json",
            set_mcp_package_source(version),
            check=check,
        )
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
            f"uv.lock has gdb-mcp {lock_version or 'missing'}, expected {version}; run uv lock"
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
