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
    large_output = bool(os.getenv("FAKE_GDB_LARGE_OUTPUT"))
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
            if os.getenv("FAKE_GDB_HOLD_RUN"):
                continue
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
        if command == "-bad-command":
            emit(f'{token}^error,msg="Undefined MI command"')
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
            if large_output:
                count_match = re.search(r" (\d+)$", command)
                count = int(count_match.group(1)) if count_match else 64
                contents = "41" * count
                emit(
                    f'{token}^done,memory=[{{begin="0x7fffffffe000",offset="0x0",'
                    f'end="0x7ffffffff000",contents="{contents}"}}]'
                )
                emit("(gdb)")
                continue
            emit(
                f'{token}^done,memory=[{{begin="0x7fffffffe000",offset="0x0",'
                'end="0x7fffffffe040",contents="04104000000000000020400000000000"}]'
            )
            emit("(gdb)")
            continue
        if large_output and command == "-stack-info-frame":
            emit(
                f'{token}^done,frame={{level="0",addr="0x401004",func="main",'
                'file="sample.c",fullname="/tmp/sample.c",line="42"}'
            )
            emit("(gdb)")
            continue
        if large_output and command.startswith("-stack-list-frames "):
            high = int(command.rsplit(" ", 1)[1])
            frames = ",".join(
                f'frame={{level="{index}",addr="0x{0x401000 + index * 8:x}",'
                f'func="function_{index}",file="sample.c",'
                f'fullname="/tmp/sample.c",line="{42 + index}"}}'
                for index in range(high + 1)
            )
            emit(f"{token}^done,stack=[{frames}]")
            emit("(gdb)")
            continue
        if large_output and command == "-stack-list-variables --simple-values":
            variables = ",".join(
                f'{{name="local_{index}",arg="0",type="long",value="{index}"}}'
                for index in range(20)
            )
            emit(f"{token}^done,variables=[{variables}]")
            emit("(gdb)")
            continue
        if large_output and "thread apply all backtrace" in command:
            lines = "\\n".join(
                f"Thread {index // 20 + 1} frame {index}: function_{index} at sample.c:{index + 1}"
                for index in range(200)
            )
            emit(f'~"{lines}\\n"')
            emit(f"{token}^done")
            emit("(gdb)")
            continue
        if large_output and "info functions" in command:
            lines = ["All functions matching regular expression main:", "sample.c:"]
            lines.extend(
                f"0x{0x401000 + index * 8:x}  int main_helper_{index}(int);"
                for index in range(200)
            )
            output = "\\n".join(lines)
            emit(f'~"{output}\\n"')
            emit(f"{token}^done")
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
