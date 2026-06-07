"""MCPDoctor - A comprehensive auditing tool for MCP (Model Context Protocol) servers.

This package provides tools for auditing MCP servers to ensure compliance with
protocol standards and best practices. It includes:

- MCPClient: For connecting to and communicating with MCP servers
- MCPDoctor: For orchestrating the audit process
- Rule system: Extensible framework for implementing audit checks
- Enums: Protocol versions and transport types

The audit system uses a rule-based approach where each rule checks specific
aspects of MCP compliance and contributes to an overall audit score.
"""

from .enums import MCPProtocolVersion, MCPTransportType
from .mcp_doctor import MCPDoctor
from .mcp_client import MCPClient
from .rules import (
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
)

__all__ = (
    "AuditData",
    "BaseRule",
    "MCPDoctor",
    "MCPClient",
    "MCPProtocolVersion",
    "MCPTransportType",
    "RuleResult",
    "RuleSeverity",
)
