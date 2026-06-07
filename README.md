# MCPScore

A command-line tool for auditing MCP (Model Context Protocol) servers. MCPScore connects to your server, runs a comprehensive set of validation rules against it, and produces a severity-based report showing what's compliant and what needs attention.

## Features

- **Multiple transports**: STDIO (local servers), Streamable HTTP, and SSE (remote servers)
- **Auto-detection**: Picks the right transport automatically — tries Streamable HTTP first, falls back to SSE for URLs
- **Multi-language**: Audits both Python (`.py`) and Node.js (`.js`) MCP servers via STDIO
- **Severity-based reporting**: Rules categorized as CRITICAL, HIGH, MEDIUM, or LOW
- **Comprehensive validation**: Protocol compliance, server metadata, capabilities, security, and transport

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

- **Security**:
  - ✅ HTTPS/TLS usage verification
  - ✅ Valid certificate checks

- **Transport**:
  - ✅ SSE transport support detection

## Requirements

- Python 3.13+
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
```

### Example output

```
Welcome to MCPScore!
Connected to the MCP server: /path/to/server.py
Transport: stdio
Starting the audit...
✅ Protocol version '2025-06-18' is one of the allowed versions
✅ Protocol version '2025-06-18' is not deprecated
✅ Protocol version '2025-06-18' is the latest version
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

### Understanding the score

Each passing rule contributes points equal to its severity weight: **CRITICAL = 5, HIGH = 3, MEDIUM = 2, LOW = 1**. Higher scores indicate better compliance with MCP standards.

## Troubleshooting

**Connection fails**

- Check the path or URL is correct and reachable
- For local servers, make sure Python or Node.js is on `PATH`
- Verify the server actually implements the MCP protocol

**Protocol version errors**

- Confirm your server uses a currently supported MCP protocol version
- If your server uses a newer version that MCPScore doesn't yet recognize, please [open an issue](https://github.com/mcp-box/mcpscore/issues)

## Feedback

Bug reports, feature requests, and general feedback are welcome at <https://github.com/mcp-box/mcpscore/issues>.

## License

MIT — see [LICENSE](LICENSE).
