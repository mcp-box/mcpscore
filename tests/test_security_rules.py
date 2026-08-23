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

        assert rule.skip_reason(audit_data) == SKIP_REASON_INSUFFICIENT_DATA

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


def _leak_audit(body: str | None, *, outcome: ProbeOutcome = ProbeOutcome.UNSUPPORTED) -> AuditData:
    """AuditData carrying a malformed-JSON probe with a captured error body.

    The rule reads the raw body from the probe's ``payload`` (which is
    excluded from reports) — the malformed request is where a server dumps a
    stack trace or path. ``body=None`` models a probe that captured nothing.
    """
    payload = {"error_body": body} if body is not None else None
    probe = ProbeResult(PROBE_MALFORMED_JSON, outcome, {}, payload=payload)
    return AuditData(transport_type=MCPTransportType.STREAMABLE_HTTP, probes={PROBE_MALFORMED_JSON: probe})


class TestErrorDataLeakRule:
    """Test ErrorDataLeakRule."""

    @pytest.fixture
    def rule(self):
        return ErrorDataLeakRule()

    def test_no_leaks_passes(self, rule):
        """A clean JSON-RPC error body passes."""
        audit_data = _leak_audit(
            '{"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": null}',
        )

        assert rule.skip_reason(audit_data) is None
        result = rule.check(audit_data)

        assert result.passed is True
        assert "✅" in result.message
        assert "do not appear to leak" in result.message

    def test_file_path_leak_fails(self, rule):
        """A file path in the error body fails."""
        result = rule.check(_leak_audit("Error at /home/user/server.py line 42"))

        assert result.passed is False
        assert "❌" in result.message
        assert "file path" in result.message.lower()

    def test_stack_trace_leak_fails(self, rule):
        """A stack trace in the error body fails."""
        result = rule.check(
            _leak_audit(
                'Traceback (most recent call last):\n  File "server.py", line 10, in main\n    raise Exception("Error")'
            )
        )

        assert result.passed is False
        assert "stack trace" in result.message.lower()

    def test_password_leak_fails(self, rule):
        """A real password value in the error body fails — and is NOT echoed into our report."""
        result = rule.check(_leak_audit('Connection failed: password="hunter2Xy9"'))

        assert result.passed is False
        assert "password" in result.message.lower()
        # The leaked value must never appear in our own (shareable) report.
        assert "hunter2Xy9" not in str(result.details)
        assert result.message == "❌ Error messages leak sensitive data: password"

    def test_bearer_token_leak_fails(self, rule):
        """A real Bearer token value in the error body fails."""
        result = rule.check(_leak_audit("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"))

        assert result.passed is False

    def test_api_key_leak_fails(self, rule):
        """A real API key value fails."""
        result = rule.check(_leak_audit("upstream error: api_key=sk-live-1a2B3c4D5e6F7g8H"))

        assert result.passed is False
        assert "api key" in result.message.lower()

    def test_auth_placeholder_phrases_do_not_leak(self, rule):
        """Live auth-gated bodies routinely name credentials without leaking one.

        This is the whole reason the rule validates the captured value: matching
        the keyword alone would fail well-behaved servers.
        """
        for safe in (
            "Bearer token required",
            "Unauthorized: missing api_key",
            'password="redacted"',
            "secret: <your-secret-here>",
            "token=required",
            "Provide a valid Bearer token to continue",
            '{"error":"invalid_token","error_description":"The access token is invalid"}',
        ):
            result = rule.check(_leak_audit(safe))
            assert result.passed is True, f"false positive on: {safe!r}"

    def test_non_json_html_body_is_scanned(self, rule):
        """A non-JSON HTML error page (payload could not parse it) is still scanned."""
        result = rule.check(
            _leak_audit("<html><body><pre>Traceback (most recent call last): /home/app/x.py</pre></body></html>")
        )

        assert result.passed is False
        assert "stack trace" in result.message.lower()

    def test_absent_probe_is_insufficient_data(self, rule):
        """No malformed probe at all — nothing to scan."""
        audit_data = AuditData(transport_type=MCPTransportType.STREAMABLE_HTTP)

        assert rule.skip_reason(audit_data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_probe_without_body_is_insufficient_data(self, rule):
        """The probe ran but captured no body (network error path)."""
        assert rule.skip_reason(_leak_audit(None)) == SKIP_REASON_INSUFFICIENT_DATA

    def test_probe_error_is_insufficient_data(self, rule):
        """A probe that errored at the network level captured no body."""
        assert rule.skip_reason(_leak_audit(None, outcome=ProbeOutcome.ERROR)) == SKIP_REASON_INSUFFICIENT_DATA

    def test_not_applicable_probe_without_body_is_insufficient_data(self, rule):
        """Parse verdict is irrelevant; no captured body is insufficient data."""
        assert rule.skip_reason(_leak_audit(None, outcome=ProbeOutcome.NOT_APPLICABLE)) == SKIP_REASON_INSUFFICIENT_DATA

    def test_not_applicable_probe_with_body_still_scans(self, rule):
        """A server can leak even when its parse-error verdict is not judgeable."""
        audit_data = _leak_audit("boom /home/user/secret.py", outcome=ProbeOutcome.NOT_APPLICABLE)

        assert rule.skip_reason(audit_data) is None
        assert rule.check(audit_data).passed is False

    def test_stdio_transport_not_applicable(self, rule):
        audit_data = AuditData(transport_type=MCPTransportType.STDIO)

        assert rule.skip_reason(audit_data) == SKIP_REASON_NOT_APPLICABLE
