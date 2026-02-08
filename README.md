# MCPAudit

A command-line tool and library for auditing MCP (Model Context Protocol) servers. MCPAudit connects to MCP servers via stdio transport, initializes them, and runs a comprehensive set of validation rules to ensure compliance with MCP standards. The tool provides detailed audit reports with severity-based categorization and extensible rule framework.


## Features

- **Multi-language support**: Audits both Python (`.py`) and Node.js (`.js`) MCP servers
- **Comprehensive validation**: Checks protocol compliance, server metadata, and configuration
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

- **Future capabilities**: Framework ready for additional checks (capabilities, tools, resources)


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

Run the auditor against a local MCP server script. The tool automatically detects the script type and uses the appropriate launcher.

### Basic usage

```bash
# Audit a Python MCP server
python main.py path/to/your/server.py

# Audit a Node.js MCP server  
python main.py path/to/your/server.js
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

async def audit_server(server_path: str):
    """Audit an MCP server programmatically."""
    client = MCPClient()
    auditor = MCPAuditor()

    # Connect to the server
    success = await client.connect_to_server(MCPTransportType.STDIO, server_path)
    if not success:
        print("Failed to connect to server")
        return

    # Run the audit
    score = await auditor.audit(client)

    # Get detailed summary
    summary = auditor.get_audit_summary()
    print(f"Audit completed with score: {score}")
    print(f"Summary: {summary}")

    # Cleanup
    await client.cleanup()

# Usage
asyncio.run(audit_server("path/to/server.py"))
```

## API Reference

### Core Classes

#### `MCPClient`
Client for connecting to and communicating with MCP servers.

**Key methods:**
- `connect_to_server(transport, server_path)`: Connect to an MCP server
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
- `STDIO`: Standard input/output (currently supported)
- `STREAMABLE_HTTP`: HTTP with streaming (planned)
- `SSE`: Server-Sent Events (planned)
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
git clone <repository-url>
cd MCPAudit

# Install dependencies with uv (recommended)
uv sync

# Or with pip
pip install -e .
```

### Development workflow

```bash
# Run the auditor during development
uv run python main.py path/to/server.py

# Run linting
uv run ruff check .

# Run tests
uv run pytest
```

### Project structure

```
MCPAudit/
├── main.py                    # CLI entry point
├── mcpaudit/                  # Core package
│   ├── __init__.py           # Package exports and documentation
│   ├── mcp_client.py         # MCP client wrapper for server communication
│   ├── mcp_auditor.py        # Audit orchestrator and workflow management
│   ├── enums.py              # Enumerations and constants (protocol versions, transport types)
│   └── rules/                # Rule system and implementations
│       ├── __init__.py       # Rule system exports
│       ├── base.py           # Base rule classes and decorators
│       ├── registry.py       # Rule registry and registration system
│       ├── protocol_version.py  # Protocol version validation rules
│       └── server_info.py    # Server information validation rules
├── pyproject.toml            # Project configuration and dependencies
├── ruff.toml                 # Linting configuration
├── uv.lock                   # Dependency lock file
├── Makefile                  # Development commands
└── README.md                 # This file
```

### Code quality

- **Linting**: ruff is configured for code formatting and style
- **Type hints**: Full type annotation support with comprehensive docstrings
- **Documentation**: Google-style docstrings throughout the codebase
- **Testing**: pytest framework included
- **Python version**: Requires Python 3.13+
- **Architecture**: Modular design with clear separation of concerns


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

- **Transport**: Currently only stdio transport is supported (HTTP, WebSocket, SSE planned)
- **Output**: Results are printed to stdout; structured output (JSON) available via programmatic API
- **Protocol versions**: Version definitions in `enums.py` need manual updates as MCP spec evolves
- **Rule coverage**: Focuses on basic compliance; advanced server capabilities (tools, resources) not yet audited
- **Server types**: Optimized for Python and Node.js servers; other languages may require additional setup

## Contributing

Contributions are welcome! Areas for improvement:

- **Transport methods**: HTTP, WebSocket, SSE support
- **Audit rules**: More comprehensive compliance checks (tools, resources, capabilities)
- **Output formats**: JSON/structured output options for CLI
- **Test coverage**: Unit tests and integration tests
- **Documentation**: Additional examples and tutorials
- **Performance**: Optimizations for large-scale server auditing
- **CI/CD**: Automated testing and deployment pipelines

### Development guidelines

- Follow the existing code style and docstring format
- Add comprehensive docstrings for all new classes and methods
- Use type hints throughout
- Write tests for new functionality
- Update this README when adding new features

## License

This project is licensed under the MIT License - see the LICENSE file for details.
