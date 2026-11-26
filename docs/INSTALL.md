# Installation and Client Configuration

> [!IMPORTANT]
> The PyPI distribution name for this project is **`beacox-gdb-mcp`**. The
> installed CLI command remains **`gdb-mcp`**. Do not install `gdb-mcp` from
> PyPI, which belongs to an unrelated package.

## Recommended: Persistent Tool Install

```bash
uv tool install beacox-gdb-mcp
gdb-mcp --version
gdb-mcp doctor
```

Upgrade and uninstall:

```bash
uv tool upgrade beacox-gdb-mcp
uv tool uninstall beacox-gdb-mcp
```

## Alternative Package Managers

### Ephemeral `uvx`

```bash
uvx --from beacox-gdb-mcp gdb-mcp --version
```

### `pipx`

```bash
pipx install beacox-gdb-mcp
pipx upgrade beacox-gdb-mcp
```

### Tagged Git Snapshot

```bash
uvx --from git+https://github.com/BeaCox/gdb-mcp.git@v0.6.0 gdb-mcp --version
```

### Local Development Checkout

```bash
uv sync --extra dev
uv run gdb-mcp --version
```

## Client Marketplace Plugins

Both marketplace manifests pin the exact released wheel from PyPI:

### Claude Code

```bash
claude plugin marketplace add BeaCox/gdb-mcp@v0.6.0
claude plugin install gdb-mcp@beacox --scope user
```

### Codex

```bash
codex plugin marketplace add BeaCox/gdb-mcp --ref v0.6.0
codex plugin add gdb-mcp@beacox
```

## Direct Client Registration

With `beacox-gdb-mcp` installed via `uv tool install` or `pipx`:

```bash
claude mcp add --scope user gdb -- gdb-mcp
codex mcp add gdb -- gdb-mcp
gemini mcp add gdb -- gdb-mcp
```

Or use the built-in helper to inspect or install configurations:

```bash
gdb-mcp clients
gdb-mcp install auto --direct --installed
gdb-mcp config --installed
gdb-mcp config cursor --installed
gdb-mcp config vscode --installed
gdb-mcp config windsurf --installed
```

For ephemeral `uvx` snippets (without a prior `uv tool install`), omit `--installed`:

```bash
gdb-mcp config
```

## OCI Container (Includes `gdb`, `gdbserver`, and `rr`)

Build locally from [Dockerfile](../Dockerfile) or pull the published image:

```bash
docker build -t gdb-mcp:local .
```

Linux `ptrace` inside containers requires `CAP_SYS_PTRACE` and an unconfined
seccomp profile (add `--pid=host` to attach to processes on the host):

```bash
docker run -i --rm \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  -v "$PWD:/work" -w /work \
  ghcr.io/beacox/gdb-mcp
```

## Nix Flake

Run in an isolated environment with `gdb` and `binutils` on `PATH`:

```bash
nix run github:BeaCox/gdb-mcp
```
