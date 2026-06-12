#!/usr/bin/env python3
"""Small deterministic GDB/MI stub used by lifecycle tests."""

from __future__ import annotations

import os
import re
import sys


def emit(line: str) -> None:
    print(line, flush=True)


def main() -> None:
    log_path = os.getenv("FAKE_GDB_LOG")
    if not os.getenv("FAKE_GDB_NO_PROMPT"):
        emit("(gdb)")

    for raw in sys.stdin:
        line = raw.rstrip("\r\n")
        if log_path:
            with open(log_path, "a", encoding="utf-8") as log:
                log.write(line + "\n")
        match = re.match(r"(\d+)(.*)", line)
        if match is None:
            continue
        token, command = match.groups()

        if command == "-gdb-exit":
            emit(f"{token}^exit")
            emit("(gdb)")
            return
        if command == "-exec-run":
            emit(f"{token}^running")
            emit('*running,thread-id="all"')
            emit("(gdb)")
            continue
        if command == "-exec-interrupt":
            emit(f"{token}^done")
            emit(
                '*stopped,reason="signal-received",signal-name="SIGINT",'
                'thread-id="1",frame={level="0",func="main"}'
            )
            emit("(gdb)")
            continue

        escaped = (
            command.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
        )
        emit(f'~"{escaped}\\n"')
        emit(f"{token}^done")
        emit("(gdb)")


if __name__ == "__main__":
    main()
