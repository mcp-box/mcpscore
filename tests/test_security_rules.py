"""Unit tests for security audit rules."""

import pytest

from mcpscore.enums import MCPTransportType
from mcpscore.probes import PROBE_MALFORMED_JSON, ProbeOutcome, ProbeResult
from mcpscore.rules import (
    AuditData,
    ErrorDataLeakRule,
    MalformedRequestHandlingRule,
    RuleSeverity,
    TLSEnabledRule,
)
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE


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

    def test_https_with_verified_tls_and_unknown_version_passes(self, rule):
        """A verified TLS connection remains valid when version probing yields no version."""
        audit_data = AuditData(url="https://example.com/mcp", tls_verified=True, tls_version=None)

        assert rule.skip_reason(audit_data) is None
        result = rule.check(audit_data)

        assert result.passed is True
        assert result.message == "✅ Server uses HTTPS with valid TLS"

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
        audit_data = AuditData(transport_type=MCPTransportType.STDIO)

        assert rule.skip_reason(audit_data) == SKIP_REASON_NOT_APPLICABLE

    def test_missing_remote_url_is_insufficient_data(self, rule):
        audit_data = AuditData(transport_type=MCPTransportType.STREAMABLE_HTTP, url=None)

        assert rule.skip_reason(audit_data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_missing_remote_tls_observation_is_insufficient_data(self, rule):
        audit_data = AuditData(
            transport_type=MCPTransportType.STREAMABLE_HTTP,
            url="https://example.com/mcp",
            tls_verified=None,
        )

        assert rule.skip_reason(audit_data) == SKIP_REASON_INSUFFICIENT_DATA


class TestMalformedRequestHandlingRule:
    """Test MalformedRequestHandlingRule."""

    @pytest.fixture
    def rule(self):
        return MalformedRequestHandlingRule()

    def test_parse_error_with_null_id_passes(self, rule):
        audit_data = AuditData(
            probes={
                PROBE_MALFORMED_JSON: ProbeResult(
                    PROBE_MALFORMED_JSON,
                    ProbeOutcome.SUPPORTED,
                    {
                        "http_status": 200,
                        "error_code": -32700,
                        "error_message": "server-controlled text that must not reach reports",
                        "response_id_is_null": True,
                        "control_http_status": 200,
                    },
                )
            },
            transport_type=MCPTransportType.STREAMABLE_HTTP,
        )

        assert rule.skip_reason(audit_data) is None
        result = rule.check(audit_data)

        assert result.passed is True
        assert "✅" in result.message
        assert "JSON-RPC" in result.message

        assert result.details["spec"] == "https://www.jsonrpc.org/specification#response_object"
        assert result.details["control_http_status"] == 200
        assert "error_message" not in result.details

    def test_wrong_error_shape_fails(self, rule):
        audit_data = AuditData(
            probes={
                PROBE_MALFORMED_JSON: ProbeResult(
                    PROBE_MALFORMED_JSON,
                    ProbeOutcome.UNSUPPORTED,
                    {"http_status": 400, "error_code": -32600, "response_id_is_null": True},
                )
            },
            transport_type=MCPTransportType.STREAMABLE_HTTP,
        )

        result = rule.check(audit_data)

        assert result.passed is False
        assert "❌" in result.message
        assert "-32700" in result.message

    def test_stdio_transport_not_tested(self, rule):
        """Test that stdio transport is not tested."""
        audit_data = AuditData(probes=None, transport_type=MCPTransportType.STDIO)

        assert rule.skip_reason(audit_data) == SKIP_REASON_NOT_APPLICABLE

    def test_no_probe_captured(self, rule):
        audit_data = AuditData(probes=None, transport_type=MCPTransportType.STREAMABLE_HTTP)

        assert rule.skip_reason(audit_data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_unobservable_probe_is_not_applicable(self, rule):
        audit_data = AuditData(
            probes={PROBE_MALFORMED_JSON: ProbeResult(PROBE_MALFORMED_JSON, ProbeOutcome.NOT_APPLICABLE, {})},
            transport_type=MCPTransportType.STREAMABLE_HTTP,
        )

        assert rule.skip_reason(audit_data) == SKIP_REASON_NOT_APPLICABLE

    def test_probe_error_is_insufficient_data(self, rule):
        audit_data = AuditData(
            probes={PROBE_MALFORMED_JSON: ProbeResult(PROBE_MALFORMED_JSON, ProbeOutcome.ERROR, {})},
            transport_type=MCPTransportType.STREAMABLE_HTTP,
        )

        assert rule.skip_reason(audit_data) == SKIP_REASON_INSUFFICIENT_DATA


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

        assert rule.skip_reason(audit_data) is None
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
        """Test that an absent remote error response is insufficient data."""
        audit_data = AuditData(error_response=None, transport_type=MCPTransportType.STREAMABLE_HTTP)

        assert rule.skip_reason(audit_data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_stdio_transport_not_applicable(self, rule):
        audit_data = AuditData(error_response=None, transport_type=MCPTransportType.STDIO)

        assert rule.skip_reason(audit_data) == SKIP_REASON_NOT_APPLICABLE
