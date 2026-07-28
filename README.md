# mcpscore

[![CI](https://github.com/mcp-box/mcpscore/actions/workflows/ci.yml/badge.svg)](https://github.com/mcp-box/mcpscore/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/mcp-box/mcpscore/graph/badge.svg)](https://codecov.io/gh/mcp-box/mcpscore)
[![PyPI](https://img.shields.io/pypi/v/mcpscore.svg)](https://pypi.org/project/mcpscore/)
[![Python](https://img.shields.io/pypi/pyversions/mcpscore.svg)](https://pypi.org/project/mcpscore/)
[![License](https://img.shields.io/github/license/mcp-box/mcpscore.svg)](https://github.com/mcp-box/mcpscore/blob/main/LICENSE)

**Lighthouse for MCP.** Audit any MCP (Model Context Protocol) server and get a scored, actionable report in seconds.

Point mcpscore at a server — from the CLI, a GitHub Action, or [mcpscore.dev](https://mcpscore.dev) — and it grades protocol conformance, tool quality, security and auth posture, and readiness for the 2026-07-28 spec revision, then tells you exactly what to fix. Deterministic, no API key, no sign-up.

## Why mcpscore?

MCP servers that violate the spec fail silently in the worst place: inside someone else's AI agent. A missing tool description, an outdated protocol version, or an unencrypted endpoint won't crash your server — it will just make agents pick the wrong tool, drop your server from their registry, or leak traffic. mcpscore catches these issues in seconds, before your users do.

```bash
pip install mcpscore
mcpscore https://your-server.example/mcp
```

**Documentation**: [docs.mcpscore.dev](https://docs.mcpscore.dev) — including the full
[scoring methodology](https://docs.mcpscore.dev/methodology/) and
[rules reference](https://docs.mcpscore.dev/rules/).

## How scoring works

Every rule has a severity, and each passing rule contributes its weight to the score:

| Severity | Points | Meaning                                                                          |
|----------|--------|----------------------------------------------------------------------------------|
| CRITICAL | 5      | Spec violations that break interoperability (protocol version, server name, TLS) |
| HIGH     | 3      | Strong spec expectations (server version, valid tool schemas)                    |
| MEDIUM   | 2      | Recommendations that improve agent UX (titles, descriptions, error hygiene)      |
| LOW      | 1      | Nice-to-haves (capability extras, transport recommendations)                     |

The final score is reported as `earned/maximum` — higher means a better-quality server.

## Features

- **Multiple transports**: STDIO (local servers), Streamable HTTP, and SSE (remote servers)
- **Auto-detection**: Picks the right transport automatically — tries Streamable HTTP first, falls back to SSE for URLs
- **Real handshake verification**: A connection only counts once the server completes the MCP `initialize` handshake — pointing it at a non-MCP endpoint fails cleanly
- **Multi-language**: Audits both Python (`.py`) and Node.js (`.js`) MCP servers via STDIO
- **Severity-based reporting**: Rules categorized as CRITICAL, HIGH, MEDIUM, or LOW
- **Library-friendly**: Fully typed (`py.typed`); use `MCPClient` + `MCPAuditor` programmatically

## What it scores

52 rules across four categories — the same four the report, the JSON output, and
[mcpscore.dev](https://mcpscore.dev) show. Every rule cites the spec section or RFC it
enforces; the full list is in the [rules reference](https://docs.mcpscore.dev/rules/).

**Protocol** (16 rules) — protocol version (allowed, latest, not deprecated), server
name, title and version, advertised capabilities, and transport. Streamable HTTP is the
current standard, so SSE-only servers get migration advice.

**Tools Quality** (13 rules) — tool names (presence, uniqueness, format), titles,
descriptions, and JSON Schema validity of input and output schemas, plus the equivalent
checks for prompts and resources. These decide whether an agent picks the right tool and
calls it correctly.

**Security & Auth** (11 rules) — HTTPS/TLS with the actually negotiated version,
certificate validity, and error responses checked for data leaks. For auth-gated servers,
the OAuth posture too: the `WWW-Authenticate` challenge, RFC 9728 protected-resource
metadata, the RFC 8414 authorization-server chain, and whether PKCE (S256) is enforced.
A gated server is scored on this surface without credentials — see
[auditing authenticated servers](https://docs.mcpscore.dev/authenticated-servers/).

**Readiness** (12 rules) — how ready the server is for the 2026-07-28 MCP spec revision,
reported on its own axis. For servers already speaking the new lifecycle those points
also count toward the main score; for everyone else the axis stays informative.

## Requirements

- Python 3.11+
- Node.js on `PATH` if auditing a Node.js MCP server
- A Python interpreter on `PATH` if auditing a Python MCP server

## Installation

```bash
pip install mcpscore
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv tool install mcpscore
```

## Quick start

Run `mcpscore` against any MCP server — local script or remote URL. The transport is detected automatically.

```bash
# Local Python MCP server (STDIO)
mcpscore path/to/your/server.py

# Local Node.js MCP server (STDIO)
mcpscore path/to/your/server.js

# Remote MCP server (auto-detects Streamable HTTP or SSE)
mcpscore https://example.com/mcp

# Machine-readable report for CI pipelines and tooling
mcpscore path/to/your/server.py --json > report.json
```

### Example output

```
Welcome to mcpscore!
Connected to the MCP server: /path/to/server.py
Transport: stdio
Starting the audit...
✅ Protocol version '2025-11-25' is one of the allowed versions
✅ Protocol version '2025-11-25' is not deprecated
❌ Not using the latest protocol version: negotiated '2025-11-25', latest is '2026-07-28'
✅ Server name is present: 'weather'
✅ Server version is present: '1.17.0'
❌ Server title is not present in server info
✅ Declares the tools capability and serves 3 via tools/list
❌ listChanged is not supported by Tools
✅ Declares the prompts capability and serves 1 via prompts/list
❌ listChanged is not supported by Prompts
✅ Declares the resources capability and serves 2 via resources/list
❌ listChanged is not supported by Resources
✅ MCP Server provides at least one tool
✅ All Tools have a Name property specified
✅ All Tools have a Title property specified
✅ All Tools have a Description property specified
✅ All Tools have a valid Input Schema
✅ All Tools have a valid Output Schema
Audit finished. Final score: 55/71
```

### JSON output

With `--json`, a machine-readable report is written to stdout (all log
output goes to stderr, so the JSON can be piped or redirected cleanly):

```json
{
  "schema_version": 1,
  "mcpscore_version": "0.7.0",
  "generated_at": "2026-06-10T10:42:22+00:00",
  "target": "/path/to/server.py",
  "transport": "stdio",
  "score": 73,
  "max_score": 89,
  "summary": {
    "total": 26,
    "passed": 20,
    "failed": 6,
    "by_severity": {
      "CRITICAL": { "total": 9, "passed": 9, "failed": 0 },
      "HIGH": { "total": 11, "passed": 7, "failed": 4 },
      "MEDIUM": { "total": 5, "passed": 3, "failed": 2 },
      "LOW": { "total": 1, "passed": 1, "failed": 0 }
    }
  },
  "results": [
    {
      "rule_id": "protocol_version_allowed",
      "rule_name": "MCP Protocol Version - Allowed Versions",
      "severity": "CRITICAL",
      "severity_value": 5,
      "passed": true,
      "message": "✅ Protocol version '2025-11-25' is one of the allowed versions",
      "details": { "version": "2025-11-25" }
    }
  ]
}
```

`rule_id` values are stable identifiers intended for machine consumers
(snapshots, dashboards); display names and messages may change between
releases.

## Score badge

Every server audited on [mcpscore.dev](https://mcpscore.dev) gets a stable badge URL,
keyed by the server's URL rather than by any single audit — embed it once and it always
shows the latest completed score:

```markdown
[![mcpscore score](https://mcpscore.dev/api/v1/servers/badge.svg?url=https%3A%2F%2Fyour-server.example%2Fmcp)](https://mcpscore.dev/audits/<audit-id>)
```

The report page on mcpscore.dev has a copy-paste block with these prefilled for your
server. Full details, including the HTML form and how freshness works, are in the
[badge docs](https://docs.mcpscore.dev/badge/).

## Troubleshooting

**Connection fails**

- Check the path or URL is correct and reachable
- For local servers, make sure Python or Node.js is on `PATH`
- "Not a valid MCP server (handshake failed)" means the endpoint responded but did not complete the MCP `initialize` handshake — verify the URL points at an actual MCP endpoint (often `/mcp`)

**Protocol version errors**

- Confirm your server uses a currently supported MCP protocol version
- If your server uses a newer version that mcpscore doesn't yet recognize, please [open an issue](https://github.com/mcp-box/mcpscore/issues)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and how to add audit rules. Why this project exists: [MISSION.md](MISSION.md). Security reports: [SECURITY.md](SECURITY.md). Release history: [CHANGELOG.md](CHANGELOG.md).

## Feedback

Bug reports, feature requests, and general feedback are welcome at <https://github.com/mcp-box/mcpscore/issues>.

## License

MIT — see [LICENSE](LICENSE).
