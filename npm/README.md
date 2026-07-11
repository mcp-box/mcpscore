# mcpscore

**Lighthouse for MCP** — audit any [Model Context Protocol](https://modelcontextprotocol.io)
server and get a scored, actionable report in seconds.

```bash
npx @mcp-box/mcpscore https://your-server.example/mcp
```

This npm package is a thin wrapper around the Python
[mcpscore](https://pypi.org/project/mcpscore/) CLI, pinned to the matching
version — `npx @mcp-box/mcpscore` and `uvx mcpscore` behave identically. It requires
[uv](https://docs.astral.sh/uv/) or [pipx](https://pipx.pypa.io/) on your PATH
(no packages are installed into your environment).

## What you get

- A severity-weighted quality score across protocol compliance, server
  metadata, capabilities, tools, security, and transport — deterministic,
  no API keys, CI-ready (`--json`).
- A separate readiness score for the upcoming MCP spec revision
  (2026-07-28, stateless lifecycle).
- Actionable messages: every failed check says what to fix, and every rule
  is anchored to the spec.

## Documentation

- [docs.mcpscore.dev](https://docs.mcpscore.dev) — quick start, scoring
  methodology, full rules reference
- [GitHub](https://github.com/mcp-box/mcpscore) — source, issues, contributing
