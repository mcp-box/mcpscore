"""Unit tests for transport audit rules."""

import pytest

from mcpscore.enums import MCPTransportType
from mcpscore.rules import (
    AuditData,
    RuleSeverity,
    StreamableHTTPTransportRule,
)


class TestStreamableHTTPTransportRule:
    """Test StreamableHTTPTransportRule."""

    @pytest.fixture
    def rule(self):
        return StreamableHTTPTransportRule()

    def test_streamable_http_passes(self, rule):
        """Test that the current-standard Streamable HTTP transport passes."""
        audit_data = AuditData(transport_type=MCPTransportType.STREAMABLE_HTTP, url="https://example.com/mcp")

        result = rule.check(audit_data)

        assert result.passed is True
        assert "✅" in result.message
        assert "Streamable HTTP" in result.message
        assert result.severity == RuleSeverity.LOW

    def test_sse_only_fails_with_migration_advice(self, rule):
        """Test that the deprecated SSE transport fails with migration advice."""
        audit_data = AuditData(transport_type=MCPTransportType.SSE, url="https://example.com/sse")

        result = rule.check(audit_data)

        assert result.passed is False
        assert "deprecated" in result.message
        assert "Migrate to Streamable HTTP" in result.message

    def test_stdio_transport_not_applicable(self, rule):
        """Test that the remote transport check is not applicable for stdio."""
        audit_data = AuditData(transport_type=MCPTransportType.STDIO, url=None)

        result = rule.check(audit_data)

        assert result.passed is True
        assert "not applicable" in result.message.lower()

    def test_unknown_transport_type(self, rule):
        """Test handling of unknown transport type."""
        audit_data = AuditData(transport_type=MCPTransportType.WEBSOCKET, url="https://example.com/mcp")

        result = rule.check(audit_data)

        assert result.passed is False
        assert "Unknown transport" in result.message

    def test_no_url_for_http_transport(self, rule):
        """Test when URL is None for HTTP transport."""
        audit_data = AuditData(transport_type=MCPTransportType.STREAMABLE_HTTP, url=None)

        result = rule.check(audit_data)

        assert result.passed is True
        assert "not applicable" in result.message.lower()
