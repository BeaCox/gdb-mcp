"""Extract release notes for a tag from CHANGELOG.md."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def _heading_key(heading: str) -> str:
    heading = heading.strip()
    bracketed = re.match(r"^\[([^\]]+)\](?:\s|$)", heading)
    if bracketed:
        return bracketed.group(1)
    return re.split(r"\s+-\s+|\s+", heading, maxsplit=1)[0]


def extract_release_notes(changelog: Path, tag: str) -> str:
    versions = {tag, tag.removeprefix("v")}
    lines = changelog.read_text(encoding="utf-8").splitlines()

    start: int | None = None
    for index, line in enumerate(lines):
        match = re.match(r"^##\s+(.+?)\s*$", line)
        if match and _heading_key(match.group(1)) in versions:
            start = index + 1
            break

    if start is None:
        expected = " or ".join(sorted(versions))
        raise ValueError(f"No CHANGELOG.md section found for {expected}")

    end = len(lines)
    for index in range(start, len(lines)):
        if re.match(r"^##\s+", lines[index]):
            end = index
            break

    notes = "\n".join(lines[start:end]).strip()
    if not notes:
        raise ValueError(f"CHANGELOG.md section for {tag} is empty")
    return notes + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("changelog", type=Path)
    parser.add_argument("tag")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    try:
        notes = extract_release_notes(args.changelog, args.tag)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1

    args.output.write_text(notes, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
