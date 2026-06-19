# Security Policy

## Supported Versions

Security fixes are provided for the latest commit on the default branch until
versioned releases are established. After public releases begin, this policy will
be updated with the maintained release lines.

## Threat Model

GDB controls native processes and can execute code with the permissions of the MCP
server account. A debugging session may read secrets from process memory, modify
files through the inferior, attach to sensitive processes, or execute shell commands.
The supported local-debugging threat model is Linux GDB behavior.

Dedicated tools still have security impact. `gdb_attach` can stop local processes
owned by the server account, execution tools can resume or interrupt inferiors, and
inspection tools can read source paths, registers, memory, and secrets from the target.

`gdb_eval_expression` and `gdb_set_watchpoint` reject obvious mutation and function
call patterns by default. This is a conservative guardrail for common read-only
inspection, not a sandbox for hostile input.

`gdb_call_function`, `gdb_set_variable`, `gdb_write_memory`, and
`gdb_breakpoint_commands` are also disabled unless unsafe mode is enabled. They are
separate tools so clients can present clearer confirmations than a generic raw
command.

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

Please report suspected vulnerabilities privately through GitHub Private
Vulnerability Reporting:

https://github.com/BeaCox/gdb-mcp/security/advisories/new

If GitHub private reporting is unavailable, open a minimal public issue asking for
a private contact channel, but do not include exploit details, vulnerable targets,
or sensitive logs in the public issue.

Include affected versions or commits, reproduction steps, expected impact, and any
relevant tool output. Private advisories are welcome for coordinated disclosure.
Please do not publish working exploits before a fix or mitigation is available.
