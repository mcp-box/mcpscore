"""Unit tests for transport audit rules."""

import pytest

from mcpaudit.rules import (
    AuditData,
    RuleSeverity,
    SSETransportSupportRule,
)


class TestSSETransportSupportRule:
    """Test SSETransportSupportRule."""

    @pytest.fixture
    def rule(self):
        return SSETransportSupportRule()

    def test_sse_transport_passes(self, rule):
        """Test that SSE transport passes."""
        audit_data = AuditData(transport_type="sse", url="https://example.com/sse")

        result = rule.check(audit_data)

        assert result.passed is True
        assert "✅" in result.message
        assert "SSE" in result.message
        assert result.severity == RuleSeverity.LOW

    def test_streamable_http_fails(self, rule):
        """Test that Streamable HTTP without SSE fails."""
        audit_data = AuditData(transport_type="streamable-http", url="https://example.com/mcp")

        result = rule.check(audit_data)

        assert result.passed is False
        assert "⚠️" in result.message
        assert "Consider adding SSE" in result.message

    def test_stdio_transport_not_applicable(self, rule):
        """Test that SSE check is not applicable for stdio."""
        audit_data = AuditData(transport_type="stdio", url=None)

        result = rule.check(audit_data)

        assert result.passed is True
        assert "not applicable" in result.message.lower()

    def test_unknown_transport_type(self, rule):
        """Test handling of unknown transport type."""
        audit_data = AuditData(transport_type="unknown", url="https://example.com/mcp")

        result = rule.check(audit_data)

        assert result.passed is False
        assert "Unknown transport" in result.message

    def test_no_url_for_http_transport(self, rule):
        """Test when URL is None for HTTP transport."""
        audit_data = AuditData(transport_type="streamable-http", url=None)

        result = rule.check(audit_data)

        assert result.passed is True
        assert "not applicable" in result.message.lower()
