# MCPScore

[![CI](https://github.com/mcp-box/mcpscore/actions/workflows/ci.yml/badge.svg)](https://github.com/mcp-box/mcpscore/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/mcp-box/mcpscore/graph/badge.svg)](https://codecov.io/gh/mcp-box/mcpscore)
[![PyPI](https://img.shields.io/pypi/v/mcpscore.svg)](https://pypi.org/project/mcpscore/)
[![Python](https://img.shields.io/pypi/pyversions/mcpscore.svg)](https://pypi.org/project/mcpscore/)
[![License](https://img.shields.io/github/license/mcp-box/mcpscore.svg)](LICENSE)

A command-line tool for auditing MCP (Model Context Protocol) servers. MCPScore connects to your server, runs a comprehensive set of validation rules against it, and produces a severity-based report showing what's compliant and what needs attention.

## Why MCPScore?

MCP servers that violate the spec fail silently in the worst place: inside someone else's AI agent. A missing tool description, an outdated protocol version, or an unencrypted endpoint won't crash your server — it will just make agents pick the wrong tool, drop your server from their registry, or leak traffic. MCPScore catches these issues in seconds, before your users do.

```bash
pip install mcpscore
mcpscore https://your-server.example/mcp
```

## How scoring works

Every rule has a severity, and each passing rule contributes its weight to the score:

| Severity | Points | Meaning                                                                          |
|----------|--------|----------------------------------------------------------------------------------|
| CRITICAL | 5      | Spec violations that break interoperability (protocol version, server name, TLS) |
| HIGH     | 3      | Strong spec expectations (server version, valid tool schemas)                    |
| MEDIUM   | 2      | Recommendations that improve agent UX (titles, descriptions, error hygiene)      |
| LOW      | 1      | Nice-to-haves (capability extras, transport recommendations)                     |

The final score is reported as `earned/maximum` — higher means better MCP compliance.

## Features

- **Multiple transports**: STDIO (local servers), Streamable HTTP, and SSE (remote servers)
- **Auto-detection**: Picks the right transport automatically — tries Streamable HTTP first, falls back to SSE for URLs
- **Real handshake verification**: A connection only counts once the server completes the MCP `initialize` handshake — pointing it at a non-MCP endpoint fails cleanly
- **Multi-language**: Audits both Python (`.py`) and Node.js (`.js`) MCP servers via STDIO
- **Severity-based reporting**: Rules categorized as CRITICAL, HIGH, MEDIUM, or LOW
- **Library-friendly**: Fully typed (`py.typed`); use `MCPClient` + `MCPAuditor` programmatically

## What it audits

- **Protocol Version Compliance**:
  - ✅ Allowed versions check (CRITICAL)
  - ✅ Latest version recommendation (MEDIUM)
  - ✅ Deprecated version detection (HIGH)

- **Server Information**:
  - ✅ Server name presence (CRITICAL)
  - ✅ Server title presence (MEDIUM)
  - ✅ Server version presence (HIGH)

- **Capabilities**: Tools, resources, prompts, logging, and subscription support

- **Tools**: Names (presence, uniqueness, format), titles, descriptions, and JSON Schema validity of input/output schemas

- **Security**:
  - ✅ HTTPS/TLS usage with the actually negotiated TLS version
  - ✅ Valid certificate checks
  - ✅ Error responses checked for data leaks

- **Transport**:
  - ✅ Streamable HTTP usage (the current MCP standard; SSE-only servers get migration advice)

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
Welcome to MCPScore!
Connected to the MCP server: /path/to/server.py
Transport: stdio
Starting the audit...
✅ Protocol version '2025-11-25' is one of the allowed versions
✅ Protocol version '2025-11-25' is not deprecated
✅ Protocol version '2025-11-25' is the latest version
✅ Server name is present: 'weather'
✅ Server version is present: '1.17.0'
❌ Server title is not present in server info
✅ Tools capability is present
❌ listChanged is not supported by Tools
✅ Prompts capability is present
❌ listChanged is not supported by Prompts
✅ Resources capability is present
❌ listChanged is not supported by Resources
❌ subscribe is not supported by Resources
❌ Logging is not present in capabilities
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
  "mcpscore_version": "0.5.0",
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

## Troubleshooting

**Connection fails**

- Check the path or URL is correct and reachable
- For local servers, make sure Python or Node.js is on `PATH`
- "Not a valid MCP server (handshake failed)" means the endpoint responded but did not complete the MCP `initialize` handshake — verify the URL points at an actual MCP endpoint (often `/mcp`)

**Protocol version errors**

- Confirm your server uses a currently supported MCP protocol version
- If your server uses a newer version that MCPScore doesn't yet recognize, please [open an issue](https://github.com/mcp-box/mcpscore/issues)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and how to add audit rules. Security reports: [SECURITY.md](SECURITY.md). Release history: [CHANGELOG.md](CHANGELOG.md).

## Feedback

Bug reports, feature requests, and general feedback are welcome at <https://github.com/mcp-box/mcpscore/issues>.

## License

MIT — see [LICENSE](LICENSE).
