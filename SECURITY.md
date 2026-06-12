# Security Policy

## Threat Model

GDB controls native processes and can execute code with the permissions of the MCP
server account. A debugging session may read secrets from process memory, modify
files through the inferior, attach to sensitive processes, or execute shell commands.

`gdb_execute` is disabled by default because arbitrary GDB CLI and MI commands bypass
the narrower intent of the dedicated tools. Enable it only for trusted clients and
targets.

## Deployment Guidance

- Run the server as an unprivileged user.
- Keep HTTP transports bound to `127.0.0.1` unless protected by authentication and
  network policy.
- Use containers, virtual machines, or dedicated hosts for untrusted executables.
- Do not expose debugging ports to untrusted networks.
- Set a finite `GDB_MCP_MAX_SESSIONS`.
- Review client confirmations for tools marked destructive or open-world.

## Reporting

Please report suspected vulnerabilities privately to the repository maintainers.
Include affected versions, reproduction steps, and impact. Do not publish working
exploits before a fix or mitigation is available.
