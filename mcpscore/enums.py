"""Enumerations and constants for MCP (Model Context Protocol) auditing.

This module defines the core enumerations used throughout the MCPScore system:

- MCPTransportType: Supported transport methods for MCP communication
- MCPProtocolVersion: Supported versions of the MCP protocol
- ConnectionErrorReason: Why a connection attempt failed

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


class ConnectionErrorReason(StrEnum):
    """Why a connection attempt to an MCP server failed.

    Lets callers distinguish a server that is up but gated (auth) or
    misbehaving (HTTP error) from one that is genuinely unreachable, so they
    can show an actionable message instead of a generic "could not connect".
    """

    INVALID_URL = "invalid_url"
    """The target was not a usable URL or server path."""

    UNREACHABLE = "unreachable"
    """DNS/TCP failure — the host could not be reached at all."""

    TIMEOUT = "timeout"
    """The server did not respond within the connection/handshake timeout."""

    UNAUTHORIZED = "unauthorized"
    """The server returned HTTP 401 — it requires authentication."""

    FORBIDDEN = "forbidden"
    """The server returned HTTP 403 — access is forbidden."""

    HTTP_ERROR = "http_error"
    """The server returned some other 4xx/5xx during the handshake."""

    NOT_MCP = "not_mcp"
    """The endpoint was reachable but did not complete an MCP handshake."""

    UNKNOWN = "unknown"
    """The attempt failed for an unclassified reason."""


class MCPProtocolVersion(StrEnum):
    """Supported versions of the MCP (Model Context Protocol)."""

    v2024_11_05 = "2024-11-05"
    """MCP protocol version from November 5, 2024."""

    v2025_03_26 = "2025-03-26"
    """MCP protocol version from March 26, 2025."""

    v2025_06_18 = "2025-06-18"
    """MCP protocol version from June 18, 2025."""

    v2025_11_25 = "2025-11-25"
    """Latest MCP protocol version (November 25, 2025)."""

    Latest = v2025_11_25
    """Alias for the latest protocol version.

    This is an enum alias, not a distinct member: it does not appear in
    `list(MCPProtocolVersion)` or in iteration-derived version lists.
    """
