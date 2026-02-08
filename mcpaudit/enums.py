"""Enumerations and constants for MCP (Model Context Protocol) auditing.

This module defines the core enumerations used throughout the MCPAudit system:

- MCPTransportType: Supported transport methods for MCP communication
- MCPProtocolVersion: Supported versions of the MCP protocol

These enums provide type safety and ensure consistent usage of protocol
versions and transport types across the audit system.
"""

from enum import StrEnum


class MCPTransportType(StrEnum):
    """Transport types supported by MCP (Model Context Protocol)."""

    STDIO = "stdio"
    """Standard input/output transport for local processes."""

    STREAMABLE_HTTP = "streamable-http"
    """HTTP-based transport with streaming capabilities."""

    SSE = "sse"
    """Server-Sent Events transport for real-time communication."""

    WEBSOCKET = "websocket"
    """WebSocket transport for bidirectional communication."""


class MCPProtocolVersion(StrEnum):
    """Supported versions of the MCP (Model Context Protocol)."""

    v2024_11_05 = "2024-11-05"
    """MCP protocol version from November 5, 2024."""

    v2025_03_26 = "2025-03-26"
    """MCP protocol version from March 26, 2025."""

    v2025_06_18 = "2025-06-18"
    """Latest MCP protocol version (June 18, 2025)."""

    Latest = v2025_06_18
    """Alias for the latest protocol version."""
