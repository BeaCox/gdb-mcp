"""Minimal GDB/MI parser and helpers.

The parser covers the MI record shapes needed by this MVP:
result records, async records, stream records, tuples, lists, and C strings.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class MIParseError(ValueError):
    """Raised when a GDB/MI output line cannot be parsed."""


@dataclass(frozen=True)
class MIRecord:
    """One parsed GDB/MI output record."""

    kind: str
    raw: str
    token: int | None = None
    record_class: str | None = None
    results: dict[str, Any] | None = None
    stream: str | None = None
    text: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "token": self.token,
            "class": self.record_class,
            "results": self.results or {},
            "stream": self.stream,
            "text": self.text,
            "raw": self.raw,
        }


STREAM_MARKERS = {
    "~": "console",
    "@": "target",
    "&": "log",
}

RECORD_MARKERS = {
    "^": "result",
    "*": "exec",
    "+": "status",
    "=": "notify",
}


def c_escape(value: str) -> str:
    """Return a GDB/MI compatible C string literal."""

    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def quote_cli_command(command: str) -> str:
    """Wrap a CLI command for MI `-interpreter-exec console`."""

    return f"-interpreter-exec console {c_escape(command)}"


def parse_mi_record(line: str) -> MIRecord:
    """Parse one GDB/MI output line."""

    raw = line.rstrip("\r\n")
    if raw.strip() == "(gdb)":
        return MIRecord(kind="prompt", raw=raw)

    index = 0
    while index < len(raw) and raw[index].isdigit():
        index += 1
    token = int(raw[:index]) if index else None

    if index >= len(raw):
        raise MIParseError(f"missing MI marker: {raw!r}")

    marker = raw[index]
    payload = raw[index + 1 :]

    if marker in STREAM_MARKERS:
        parser = _Parser(payload)
        text = parser.parse_c_string()
        parser.expect_end()
        return MIRecord(
            kind="stream",
            raw=raw,
            token=token,
            stream=STREAM_MARKERS[marker],
            text=text,
        )

    if marker in RECORD_MARKERS:
        if "," in payload:
            record_class, rest = payload.split(",", 1)
            results = _Parser(rest).parse_results_until_end()
        else:
            record_class = payload
            results = {}
        return MIRecord(
            kind=RECORD_MARKERS[marker],
            raw=raw,
            token=token,
            record_class=record_class,
            results=results,
        )

    raise MIParseError(f"unknown MI marker {marker!r}: {raw!r}")


class _Parser:
    def __init__(self, text: str):
        self.text = text
        self.pos = 0

    def parse_results_until_end(self) -> dict[str, Any]:
        results = self.parse_results(stop_chars="")
        self.expect_end()
        return results

    def parse_results(self, stop_chars: str) -> dict[str, Any]:
        results: dict[str, Any] = {}
        first = True
        while not self.at_end() and self.peek() not in stop_chars:
            if not first:
                self.expect(",")
            first = False
            key = self.parse_identifier()
            self.expect("=")
            results[key] = self.parse_value()
        return results

    def parse_value(self) -> Any:
        if self.at_end():
            raise self.error("expected value")
        char = self.peek()
        if char == '"':
            return self.parse_c_string()
        if char == "{":
            self.pos += 1
            value = self.parse_results(stop_chars="}")
            self.expect("}")
            return value
        if char == "[":
            return self.parse_list()
        return self.parse_bare()

    def parse_list(self) -> list[Any] | dict[str, Any]:
        self.expect("[")
        if self.peek_or_none() == "]":
            self.pos += 1
            return []

        items: list[Any] = []
        result_items: list[tuple[str, Any]] = []
        saw_result = False
        saw_value = False

        first = True
        while not self.at_end() and self.peek() != "]":
            if not first:
                self.expect(",")
            first = False

            if self.next_value_is_result():
                saw_result = True
                key = self.parse_identifier()
                self.expect("=")
                result_items.append((key, self.parse_value()))
            else:
                saw_value = True
                items.append(self.parse_value())

        self.expect("]")
        if saw_result and not saw_value:
            keys = {key for key, _ in result_items}
            if len(keys) == 1:
                return [{key: value} for key, value in result_items]
            return [{key: value} for key, value in result_items]
        if saw_result:
            items.extend({key: value} for key, value in result_items)
        return items

    def parse_c_string(self) -> str:
        self.expect('"')
        chars: list[str] = []
        while not self.at_end():
            char = self.text[self.pos]
            self.pos += 1
            if char == '"':
                return "".join(chars)
            if char != "\\":
                chars.append(char)
                continue

            if self.at_end():
                chars.append("\\")
                break
            esc = self.text[self.pos]
            self.pos += 1
            simple = {
                "n": "\n",
                "t": "\t",
                "r": "\r",
                "a": "\a",
                "b": "\b",
                "f": "\f",
                "v": "\v",
                "\\": "\\",
                '"': '"',
            }
            if esc in simple:
                chars.append(simple[esc])
            elif esc in "01234567":
                digits = [esc]
                while (
                    len(digits) < 3
                    and not self.at_end()
                    and self.text[self.pos] in "01234567"
                ):
                    digits.append(self.text[self.pos])
                    self.pos += 1
                chars.append(chr(int("".join(digits), 8)))
            elif esc == "x":
                digits = []
                while (
                    len(digits) < 2
                    and not self.at_end()
                    and self.text[self.pos] in "0123456789abcdefABCDEF"
                ):
                    digits.append(self.text[self.pos])
                    self.pos += 1
                if digits:
                    chars.append(chr(int("".join(digits), 16)))
                else:
                    chars.append("\\x")
            else:
                chars.append("\\" + esc)
        raise self.error("unterminated C string")

    def parse_bare(self) -> str:
        start = self.pos
        while not self.at_end() and self.peek() not in ",]}":
            self.pos += 1
        if self.pos == start:
            raise self.error("expected bare value")
        return self.text[start : self.pos]

    def parse_identifier(self) -> str:
        start = self.pos
        if self.at_end() or not (self.peek().isalpha() or self.peek() in "_-."):
            raise self.error("expected identifier")
        while not self.at_end() and (
            self.peek().isalnum() or self.peek() in "_-."
        ):
            self.pos += 1
        return self.text[start : self.pos]

    def next_value_is_result(self) -> bool:
        pos = self.pos
        if pos >= len(self.text) or not (self.text[pos].isalpha() or self.text[pos] in "_-."):
            return False
        pos += 1
        while pos < len(self.text) and (
            self.text[pos].isalnum() or self.text[pos] in "_-."
        ):
            pos += 1
        return pos < len(self.text) and self.text[pos] == "="

    def expect(self, expected: str) -> None:
        if self.at_end() or self.text[self.pos] != expected:
            raise self.error(f"expected {expected!r}")
        self.pos += 1

    def expect_end(self) -> None:
        if not self.at_end():
            raise self.error("expected end of input")

    def peek(self) -> str:
        if self.at_end():
            raise self.error("unexpected end of input")
        return self.text[self.pos]

    def peek_or_none(self) -> str | None:
        return None if self.at_end() else self.text[self.pos]

    def at_end(self) -> bool:
        return self.pos >= len(self.text)

    def error(self, message: str) -> MIParseError:
        return MIParseError(f"{message} at {self.pos} in {self.text!r}")
