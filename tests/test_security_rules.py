"""Unit tests for security audit rules."""

import pytest

from mcpscore.enums import MCPTransportType
from mcpscore.rules import (
    AuditData,
    ErrorDataLeakRule,
    MalformedRequestHandlingRule,
    RuleSeverity,
    TLSEnabledRule,
)


class TestTLSEnabledRule:
    """Test TLSEnabledRule."""

    @pytest.fixture
    def rule(self):
        return TLSEnabledRule()

    def test_https_with_tls_passes(self, rule):
        """Test that HTTPS with TLS verification passes."""
        audit_data = AuditData(url="https://example.com/mcp", tls_verified=True, tls_version="TLSv1.3")

        result = rule.check(audit_data)

        assert result.passed is True
        assert "✅" in result.message
        assert result.severity == RuleSeverity.CRITICAL

    def test_http_without_tls_fails(self, rule):
        """Test that HTTP without TLS fails."""
        audit_data = AuditData(url="http://example.com/mcp", tls_verified=False, tls_version=None)

        result = rule.check(audit_data)

        assert result.passed is False
        assert "❌" in result.message
        assert "HTTPS" in result.message

    def test_tls_verification_failed(self, rule):
        """Test that TLS verification failure is caught."""
        audit_data = AuditData(url="https://example.com/mcp", tls_verified=False, tls_version=None)

        result = rule.check(audit_data)

        assert result.passed is False
        assert "certificate verification failed" in result.message.lower()

    def test_outdated_tls_version_fails(self, rule):
        """Test that outdated TLS versions fail."""
        audit_data = AuditData(url="https://example.com/mcp", tls_verified=True, tls_version="TLSv1.0")

        result = rule.check(audit_data)

        assert result.passed is False
        assert "Outdated TLS version" in result.message

    def test_stdio_transport_not_applicable(self, rule):
        """Test that TLS check is not applicable for stdio."""
        audit_data = AuditData(url=None, tls_verified=None, tls_version=None)

        result = rule.check(audit_data)

        assert result.passed is True
        assert "not applicable" in result.message.lower()


class TestMalformedRequestHandlingRule:
    """Test MalformedRequestHandlingRule."""

    @pytest.fixture
    def rule(self):
        return MalformedRequestHandlingRule()

    def test_proper_json_rpc_error_passes(self, rule):
        """Test that proper JSON-RPC error response passes."""
        audit_data = AuditData(
            error_response='{"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null}',
            transport_type=MCPTransportType.STREAMABLE_HTTP,
        )

        result = rule.check(audit_data)

        assert result.passed is True
        assert "✅" in result.message
        assert "JSON-RPC" in result.message

    def test_crash_response_fails(self, rule):
        """Test that crash responses fail."""
        audit_data = AuditData(
            error_response="Server crash: Segmentation fault (core dumped)",
            transport_type=MCPTransportType.STREAMABLE_HTTP,
        )

        result = rule.check(audit_data)

        assert result.passed is False
        assert "❌" in result.message
        assert "crash" in result.message.lower()

    def test_non_json_rpc_error_fails(self, rule):
        """Test that non-JSON-RPC error format fails."""
        audit_data = AuditData(error_response="Error: Invalid input", transport_type=MCPTransportType.STREAMABLE_HTTP)

        result = rule.check(audit_data)

        assert result.passed is False
        assert "⚠️" in result.message

    def test_stdio_transport_not_tested(self, rule):
        """Test that stdio transport is not tested."""
        audit_data = AuditData(error_response=None, transport_type=MCPTransportType.STDIO)

        result = rule.check(audit_data)

        assert result.passed is True
        assert "not tested" in result.message.lower()

    def test_no_error_response_captured(self, rule):
        """Test when no error response was captured."""
        audit_data = AuditData(error_response=None, transport_type=MCPTransportType.STREAMABLE_HTTP)

        result = rule.check(audit_data)

        assert result.passed is True
        assert "not performed" in result.message.lower()


class TestErrorDataLeakRule:
    """Test ErrorDataLeakRule."""

    @pytest.fixture
    def rule(self):
        return ErrorDataLeakRule()

    def test_no_leaks_passes(self, rule):
        """Test that clean error responses pass."""
        audit_data = AuditData(
            error_response='{"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": null}'
        )

        result = rule.check(audit_data)

        assert result.passed is True
        assert "✅" in result.message
        assert "do not appear to leak" in result.message

    def test_file_path_leak_fails(self, rule):
        """Test that file path leakage fails."""
        audit_data = AuditData(error_response="Error at /home/user/server.py line 42")

        result = rule.check(audit_data)

        assert result.passed is False
        assert "❌" in result.message
        assert "file path" in result.message.lower()

    def test_stack_trace_leak_fails(self, rule):
        """Test that stack trace leakage fails."""
        audit_data = AuditData(
            error_response=(
                'Traceback (most recent call last):\n  File "server.py", line 10, in main\n    raise Exception("Error")'
            )
        )

        result = rule.check(audit_data)

        assert result.passed is False
        assert "❌" in result.message
        assert "stack trace" in result.message.lower()

    def test_password_leak_fails(self, rule):
        """Test that password leakage fails."""
        audit_data = AuditData(error_response='Connection failed: password="secret123"')

        result = rule.check(audit_data)

        assert result.passed is False
        assert "❌" in result.message
        assert "password" in result.message.lower()

    def test_api_key_leak_fails(self, rule):
        """Test that API key leakage fails."""
        audit_data = AuditData(error_response="Authentication failed: api_key=sk-1234567890abcdef")

        result = rule.check(audit_data)

        assert result.passed is False
        assert "❌" in result.message
        assert "api key" in result.message.lower()

    def test_bearer_token_leak_fails(self, rule):
        """Test that Bearer token leakage fails."""
        audit_data = AuditData(error_response="Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")

        result = rule.check(audit_data)

        assert result.passed is False
        assert "❌" in result.message

    def test_no_error_response(self, rule):
        """Test when no error response is provided."""
        audit_data = AuditData(error_response=None)

        result = rule.check(audit_data)

        assert result.passed is True
        assert "No error response" in result.message
