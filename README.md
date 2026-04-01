# MCPAudit

A command-line tool and library for auditing MCP (Model Context Protocol) servers. MCPAudit connects to MCP servers, initializes them, and runs a comprehensive set of validation rules to ensure compliance with MCP standards. The tool provides detailed audit reports with severity-based categorization and extensible rule framework.


## Features

- **Multiple transports**: Supports STDIO (local servers), Streamable HTTP, and SSE (remote servers)
- **Auto-detection**: Automatically detects the right transport — tries Streamable HTTP first, falls back to SSE for URLs
- **Multi-language support**: Audits both Python (`.py`) and Node.js (`.js`) MCP servers via STDIO
- **Comprehensive validation**: Checks protocol compliance, server metadata, security, and transport configuration
- **Severity-based reporting**: Rules categorized by CRITICAL, HIGH, MEDIUM, and LOW severity levels
- **Extensible rule system**: Easy to add custom audit rules
- **Detailed reporting**: Provides pass/fail status with descriptive messages and technical details

## What it audits

MCPAudit connects to your MCP server and validates:

- **Protocol Version Compliance**:
  - ✅ Allowed versions check (CRITICAL)
  - ✅ Latest version recommendation (MEDIUM)
  - ✅ Deprecated version detection (HIGH)

- **Server Information**:
  - ✅ Server name presence (CRITICAL)
  - ✅ Server title presence (MEDIUM)
  - ✅ Server version presence (HIGH)

- **Capabilities validation**: Checks tools, resources, prompts, logging, and subscription support

- **Security**:
  - ✅ HTTPS/TLS usage verification
  - ✅ Valid certificate checks

- **Transport**:
  - ✅ SSE transport support detection


## Requirements

- Python 3.13+
- The `mcp` package (installed via uv or pip)
- If auditing a Node.js server: Node.js available on PATH
- If auditing a Python server: Python available on PATH

This repo is configured for uv, but pip works as well.


## Installation

Using [uv](https://docs.astral.sh/uv/) (recommended):

```bash
uv sync
```

Using pip:

```bash
pip install -e .
```

This will install the `mcpaudit` package and its dependency `mcp`.


## Quick start

Run the auditor against any MCP server. The tool automatically detects the transport type: STDIO for local scripts, Streamable HTTP (with SSE fallback) for URLs.

### Basic usage

After installation, you can use the `mcpaudit` command:

```bash
# Audit a local Python MCP server (via STDIO)
mcpaudit path/to/your/server.py

# Audit a local Node.js MCP server (via STDIO)
mcpaudit path/to/your/server.js

# Audit a remote MCP server (auto-detects Streamable HTTP or SSE)
mcpaudit https://example.com/mcp
```

**Alternative (backwards compatible):**

```bash
# Using uv run
uv run mcpaudit path/to/your/server.py

# Or using the legacy main.py
python main.py path/to/your/server.py
```

### Example output

```
Welcome to MCPAudit!
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

### Understanding the audit score

The audit score is calculated based on rule severity and pass/fail status:
- **Passed rules**: Add points equal to their severity value (CRITICAL=5, HIGH=3, MEDIUM=2, LOW=1)
- **Higher scores**: Indicate better compliance with MCP standards

### Error handling

If the server cannot be launched or initialized, you'll see descriptive error messages to help troubleshoot the issue.


## Architecture

MCPAudit follows a modular architecture designed for extensibility:

### Core Components

- **`main.py`**: CLI entry point that orchestrates the audit process
- **`MCPClient`**: Wrapper around the official MCP client for server communication
- **`MCPAuditor`**: Orchestrates the audit process and rule execution
- **`BaseRule` system**: Extensible framework for implementing audit rules
- **`RuleRegistry`**: Central registry managing all available audit rules

### Rule System

The audit system is built around a flexible rule framework:

- **`BaseRule`**: Abstract base class for all audit rules
- **`ProtocolVersionRule`**: Specialized base for protocol version checks
- **`ServerInfoRule`**: Specialized base for server information checks
- **`RuleRegistry`**: Manages rule registration and retrieval

### Extending the system

To add new audit rules:

1. Create a new rule class inheriting from `BaseRule` (or a specialized base like `ProtocolVersionRule` or `ServerInfoRule`)
2. Implement the required abstract methods (`rule_name`, `severity`, `check`)
3. Use the `@register_rule` decorator for automatic registration

### Using the library programmatically

You can also use MCPAudit as a library in your own applications:

```python
import asyncio
from mcpaudit import MCPAuditor, MCPClient, MCPTransportType


async def audit_local_server(server_path: str):
    """Audit a local MCP server via STDIO."""
    client = MCPClient()
    auditor = MCPAuditor()

    success = await client.connect_to_server(MCPTransportType.STDIO, server_path)
    if not success:
        print("Failed to connect to server")
        return

    score = await auditor.audit(client)
    summary = auditor.get_audit_summary()
    print(f"Audit completed with score: {score}")
    print(f"Summary: {summary}")
    await client.cleanup()


async def audit_remote_server(url: str):
    """Audit a remote MCP server with auto-detection (Streamable HTTP → SSE fallback)."""
    client = MCPClient()
    auditor = MCPAuditor()

    success, transport = await client.detect_and_connect(url)
    if not success:
        print("Failed to connect to server")
        return

    print(f"Connected via {transport}")
    score = await auditor.audit(client)
    summary = auditor.get_audit_summary()
    print(f"Audit completed with score: {score}")
    print(f"Summary: {summary}")
    await client.cleanup()

# Usage
asyncio.run(audit_local_server("path/to/server.py"))
asyncio.run(audit_remote_server("https://example.com/mcp"))
```

## API Reference

### Core Classes

#### `MCPClient`
Client for connecting to and communicating with MCP servers.

**Key methods:**
- `detect_and_connect(server_path_or_url)`: Auto-detect transport and connect (Streamable HTTP → SSE fallback for URLs, STDIO for local files)
- `connect_to_server(transport, server_path)`: Connect using a specific transport
- `initialize()`: Initialize the server session and get capabilities
- `list_tools()`: List available tools from the server
- `cleanup()`: Clean up resources and close connections

#### `MCPAuditor`
Orchestrates the complete audit process.

**Key methods:**
- `audit(client)`: Execute the full audit workflow
- `get_audit_summary()`: Get detailed summary of audit results

#### `BaseRule`
Abstract base class for all audit rules.

**Required methods:**
- `rule_name`: Human-readable name of the rule
- `severity`: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
- `check(audit_data)`: Execute the rule validation

### Enums

#### `MCPTransportType`
Supported transport methods:
- `STDIO`: Standard input/output for local server processes
- `STREAMABLE_HTTP`: HTTP-based transport with streaming capabilities
- `SSE`: Server-Sent Events transport for real-time communication
- `WEBSOCKET`: WebSocket transport (planned)

#### `MCPProtocolVersion`
Supported protocol versions:
- `v2024_11_05`: November 5, 2024 version
- `v2025_03_26`: March 26, 2025 version
- `v2025_06_18`: Latest version (June 18, 2025)
- `Latest`: Alias for the most recent version

#### `RuleSeverity`
Rule severity levels with point values:
- `CRITICAL`: 5 points
- `HIGH`: 3 points
- `MEDIUM`: 2 points
- `LOW`: 1 point

### Data Classes

#### `AuditData`
Container for all server data used in audits:
- `protocol_version`: Server's MCP protocol version
- `server_info`: Server implementation details
- `capabilities`: Server capabilities and features
- `instructions`: Server usage instructions

#### `RuleResult`
Result of a rule execution:
- `rule_name`: Name of the executed rule
- `severity`: Severity level of the rule
- `passed`: Whether the rule passed or failed
- `message`: Human-readable result message
- `details`: Additional technical details (optional)

## Development

### Setup

```bash
# Clone the repository
git clone https://github.com/mcpaudit/mcpaudit.git
cd mcpaudit

# Install dependencies and pre-commit hooks
make install
```

### Development workflow

```bash
make format    # Auto-format code
make lint      # Lint (no auto-fix)
make typecheck # Type check with pyright
make test      # Run tests
make testcov   # Run tests with coverage report
make all       # Run everything (mirrors CI)
```

### Project structure

```
mcpaudit/
├── mcpaudit/                  # Core package
│   ├── __init__.py           # Package exports and documentation
│   ├── cli.py                # CLI entry point (mcpaudit command)
│   ├── mcp_client.py         # MCP client wrapper for server communication
│   ├── mcp_auditor.py        # Audit orchestrator and workflow management
│   ├── enums.py              # Enumerations and constants (protocol versions, transport types)
│   └── rules/                # Rule system and implementations
│       ├── __init__.py       # Rule system exports
│       ├── base.py           # Base rule classes and decorators
│       ├── registry.py       # Rule registry and registration system
│       ├── protocol_version.py  # Protocol version validation rules
│       ├── server_info.py    # Server information validation rules
│       ├── capabilities.py   # Capabilities validation rules
│       ├── tools.py          # Tools validation rules
│       ├── security.py       # Security validation rules
│       └── transport.py      # Transport validation rules
├── tests/                    # Test suite (97% coverage)
├── .github/workflows/ci.yml  # GitHub Actions CI (lint, typecheck, test)
├── .pre-commit-config.yaml   # Pre-commit hooks (ruff, codespell, pyright)
├── pyproject.toml            # Project configuration and dependencies
├── ruff.toml                 # Linting configuration
├── uv.lock                   # Dependency lock file
├── Makefile                  # Development commands
└── README.md                 # This file
```

### Code quality

- **Linting & formatting**: ruff (configured in `ruff.toml`)
- **Type checking**: pyright with strict settings
- **Testing**: pytest with 97% coverage
- **Pre-commit hooks**: ruff, codespell, pyright, file checks — run automatically on every commit
- **CI**: GitHub Actions runs lint, typecheck, and tests on ubuntu, windows, and macos
- **Python version**: Requires Python 3.13+


## Troubleshooting

### Common issues

**Server connection fails**

- Ensure the server script path is correct and accessible
- Verify the server script is executable (Python/Node.js available on PATH)
- Check that the server script implements the MCP protocol correctly

**Protocol version errors**

- Update `mcpaudit/enums.py` with the latest MCP protocol versions
- Ensure your server is using a supported protocol version
- Check the `MCPProtocolVersion` enum for currently supported versions

**Missing dependencies**

- Run `uv sync` or `pip install -e .` to install required dependencies
- Ensure Python 3.13+ is installed

### Getting help

If you encounter issues not covered here:

1. Check the error messages for specific guidance
2. Verify your MCP server implementation follows the protocol specification
3. Review the audit rule details in the `mcpaudit/rules/` package
4. Check the comprehensive docstrings in the source code for API details
5. Use the programmatic API for more control over the audit process

## Limitations

- **WebSocket**: WebSocket transport is not yet implemented
- **Output**: Results are printed to stdout; structured output (JSON) available via programmatic API
- **Protocol versions**: Version definitions in `enums.py` need manual updates as MCP spec evolves
- **Server types**: Optimized for Python and Node.js servers; other languages may require additional setup

## Contributing

Contributions are welcome! Areas for improvement:

- **WebSocket transport**: Implement WebSocket support in `MCPClient`
- **Audit rules**: More comprehensive compliance checks
- **Output formats**: JSON/structured output options for CLI
- **Documentation**: Additional examples and tutorials
- **Performance**: Optimizations for large-scale server auditing

### Development guidelines

- Run `make all` before submitting a PR (mirrors CI checks)
- Add tests for new functionality (maintain 95%+ coverage)
- Use type hints throughout — all public APIs must be typed
- Follow the existing code style (ruff handles formatting automatically)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
