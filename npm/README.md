# mcpscore

**Lighthouse for MCP** — audit any [Model Context Protocol](https://modelcontextprotocol.io)
server and get a scored, actionable report in seconds.

## Requirements

- Node.js 18 or newer.
- **uv (which provides `uvx`) or pipx on your PATH.** Node.js alone is not
  enough: this package launches the Python engine, not a JavaScript port.
- For local servers, their runtime and any required configuration.

Already have uv or pipx? Skip to **Run an audit**. Otherwise install uv:

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

```powershell
# Windows
winget install --id=astral-sh.uv -e
```

See [uv installation](https://docs.astral.sh/uv/getting-started/installation/)
for alternative methods. Open a new terminal and verify:

```bash
uvx --version
npx @mcp-box/mcpscore --help
```

## Run an audit

```bash
npx @mcp-box/mcpscore https://your-server.example/mcp
```

This npm package is a thin wrapper around the Python
[mcpscore](https://pypi.org/project/mcpscore/) CLI, pinned to the matching
version. It tries `uvx` first, then `pipx` if `uvx` is absent. The runner
installs the engine in an isolated environment; the first run needs network
access and can take longer. The wrapper does not install uv or pipx itself.

If neither runner is found, follow the printed installation steps, open a new
terminal, and retry your original command. If a runner is already installed,
check that its executable directory is on PATH. A runner or audit failure is
returned directly rather than retried through the other runner.

## What you get

- A severity-weighted quality score across protocol compliance, server
  metadata, capabilities, tools, security, and transport — deterministic,
  no API keys, CI-ready (`--json`).
- A separate readiness score for the MCP spec revision
  (2026-07-28, stateless lifecycle).
- Actionable messages: every failed check says what to fix, and every rule
  is anchored to the spec.

## Documentation

- [docs.mcpscore.dev](https://docs.mcpscore.dev) — quick start, scoring
  methodology, full rules reference
- [GitHub](https://github.com/mcp-box/mcpscore) — source, issues, contributing
