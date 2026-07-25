# Compatibility Matrix

This project targets Linux GDB workflows. Host-dependent smoke tests skip when a
native dependency is unavailable, but parser, protocol, lazy proxy, and fake-GDB
tests should pass everywhere the Python package supports.

| Area | Supported | Notes |
| --- | --- | --- |
| Python | 3.10, 3.11, 3.12, 3.13 | CI runs the full test suite on these versions. |
| Operating system | Linux | Local attach, core, process, and gdbserver workflows rely on Linux GDB behavior. |
| GDB | Ubuntu 22.04 and 24.04 distro builds with MI support | CI runs MI transcript and live smoke suites on both builds and uploads a feature report. The fake-GDB tests cover protocol behavior without a host GDB. |
| gdbserver | Optional | Required only for remote-target and managed-gdbserver workflows. |
| rr | Optional | Required only for `gdb_rr_record` and replay workflows. Tests skip cleanly when unavailable. |
| C compiler | Optional for smoke tests | CI uses `gcc` to build fixture programs. |
| C++ compiler | Optional for smoke tests | CI debugs a namespaced C++ fixture. |
| macOS | Unsupported for local target control | The Python package may import, but local Linux debugging workflows are not supported. |
| Windows | Unsupported | GDB process control, attach, and core workflows are not tested. |

## Known Unsupported Cases

- Attaching to processes blocked by Linux ptrace policy or container security
  settings.
- rr recording on hosts that deny `perf_event_open` without the required sysctl
  or rr fallback configuration.
- Remote targets that require authentication or transport setup outside GDB's
  `target remote` and `target extended-remote` forms.
- Non-Linux core files.

## Feature Gates

`gdb_server_health` and `scripts/probe_gdb_features.py` execute bounded probes
instead of inferring support from the version string. Reports currently cover
MI2, GDB Python, `record full`, reverse execution, `gcore`, extended remote
targets, and debuginfod. A missing feature includes the probe's first error line
so skips and deployment diagnostics are actionable.

Live compatibility fixtures cover C, C++, optimized PIE executables, shared
libraries, attach, core files, local gdbserver, and unavailable optional
dependencies. CI publishes `gdb-features.json` for each Ubuntu/Python pair.

## Native Dependencies

Debian and Ubuntu:

```bash
sudo apt-get install -y gcc gdb gdbserver
sudo apt-get install -y rr
```

Nix is useful for repeatable debugger dependencies, but this repository does
not maintain a flake or Nix package yet. Use an ad hoc shell when needed:

```bash
nix shell nixpkgs#gdb nixpkgs#gdbserver nixpkgs#gcc
```

Homebrew packaging is not maintained yet. Linux users should prefer distro
packages or the Nix shell above for native debugger dependencies. Python
installation remains through PyPI, `pipx`, `uvx`, or the tagged Git source
documented in [README.md](../README.md).
