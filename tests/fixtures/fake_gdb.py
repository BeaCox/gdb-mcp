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
        if command.startswith("-data-evaluate-expression "):
            if '"$pc"' in command:
                emit(f'{token}^done,value="0x401004"')
            elif '"$sp"' in command:
                emit(f'{token}^done,value="0x7fffffffe000"')
            elif '"0x' in command:
                value = command.split('"', 2)[1]
                emit(f'{token}^done,value="{value}"')
            else:
                emit(f'{token}^done,value="42"')
            emit("(gdb)")
            continue
        if command.startswith("-data-read-memory-bytes "):
            emit(
                f'{token}^done,memory=[{{begin="0x7fffffffe000",offset="0x0",'
                'end="0x7fffffffe040",contents="04104000000000000020400000000000"}]'
            )
            emit("(gdb)")
            continue
        if command == '-interpreter-exec console "info proc mappings"':
            emit(
                '~"Mapped address spaces:\\n'
                '          Start Addr           End Addr       Size     Offset  Perms  objfile\\n'
                '            0x400000           0x402000     0x2000        0x0  r-xp   '
                '/tmp/sample\\n'
                '      0x7ffffffde000     0x7ffffffff000    0x21000        0x0  rw-p   '
                '[stack]\\n"'
            )
            emit(f"{token}^done")
            emit("(gdb)")
            continue
        if command.startswith('-interpreter-exec console "x/'):
            emit(
                '~"=> 0x401004 <main+4>:\\tcall   0x401030 <puts@plt>\\n'
                '   0x401009 <main+9>:\\tret\\n"'
            )
            emit(f"{token}^done")
            emit("(gdb)")
            continue
        if command == '-interpreter-exec console "info symbol 0x401004"':
            emit('~"main + 4 in section .text of /tmp/sample\\n"')
            emit(f"{token}^done")
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
