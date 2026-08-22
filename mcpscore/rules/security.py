import re
from typing import ClassVar

from ..enums import MCPTransportType
from ..probes import PROBE_MALFORMED_JSON, ProbeOutcome
from .base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_NOT_APPLICABLE,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
    requires_fields,
)
from .registry import register_rule


@register_rule
class TLSEnabledRule(BaseRule):
    """Check if the server uses HTTPS with valid TLS.

    This is a critical security check ensuring that the connection is encrypted
    and the TLS certificate is properly verified.

    Scoring: 10 points (CRITICAL)
    """

    rule_id = "security_tls_enabled"
    basis = "MCP 2025-11-25 Transports §Streamable HTTP Security Warning; TLS transport-security best practice"
    group_name = "security"
    group_order = 3
    rule_order = 1

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when TLS does not apply or its remote observation is missing."""
        if audit_data.transport_type == MCPTransportType.STDIO:
            return SKIP_REASON_NOT_APPLICABLE
        if audit_data.url is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        if audit_data.url.startswith("https://") and audit_data.tls_verified is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    @property
    def rule_name(self) -> str:
        return "HTTPS/TLS Enabled"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    @requires_fields("url", "tls_verified", "tls_version")
    def check(self, url: str | None, tls_verified: bool | None, tls_version: str | None) -> RuleResult:  # type: ignore[override]
        """Check if HTTPS/TLS is enabled and properly configured.

        Args:
            url: The server URL
            tls_verified: Whether TLS certificate was verified
            tls_version: TLS version used

        Returns:
            RuleResult indicating pass/fail

        """
        assert url is not None  # noqa: S101 — skip_reason guarantees a remote URL

        # Check if URL uses HTTPS
        if not url.startswith("https://"):
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message="❌ Server does not use HTTPS. All MCP servers should use encrypted connections.",
                details={"url": url, "scheme": "http"},
            )

        # Check if TLS was verified
        if tls_verified is False:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message="❌ TLS certificate verification failed. This is a critical security issue.",
                details={"url": url},
            )

        # Check TLS version (should be 1.2 or higher)
        if tls_version and tls_version not in ["TLSv1.2", "TLSv1.3"]:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message=f"⚠️ Outdated TLS version: {tls_version}. Should use TLS 1.2 or 1.3.",
                details={"url": url, "tls_version": tls_version},
            )

        # All checks passed
        message = "✅ Server uses HTTPS with valid TLS"
        if tls_version:
            message += f" ({tls_version})"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=True,
            message=message,
            details={"url": url, "tls_version": tls_version},
        )


@register_rule
class MalformedRequestHandlingRule(BaseRule):
    """Check the normative JSON-RPC response to malformed JSON.

    JSON-RPC 2.0 requires Parse error (``-32700``) and a null response ID when
    the request cannot be parsed. Its transport-agnostic specification does
    not prescribe an HTTP status, so this rule deliberately does not either.

    Scoring: 2 points (MEDIUM)
    """

    rule_id = "security_malformed_request_handling"
    basis = "JSON-RPC 2.0 §Response Object / §Error Object (-32700 Parse error; unknown id is null)"
    group_name = "security"
    group_order = 3
    rule_order = 2

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when the raw malformed-request response is unobservable."""
        if audit_data.transport_type == MCPTransportType.STDIO:
            # The JSON-RPC requirement applies, but the SDK-backed stdio probe
            # cannot safely inject a truncated wire message. That is missing
            # evidence, not an inapplicable requirement.
            return SKIP_REASON_INSUFFICIENT_DATA
        probe = (audit_data.probes or {}).get(PROBE_MALFORMED_JSON)
        if probe is not None and probe.outcome is ProbeOutcome.NOT_APPLICABLE:
            return SKIP_REASON_NOT_APPLICABLE
        if probe is None or probe.outcome is ProbeOutcome.ERROR:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    @property
    def rule_name(self) -> str:
        return "Malformed Request Handling"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        """Require the exact JSON-RPC parse-error shape, independent of HTTP status."""
        probe = (audit_data.probes or {})[PROBE_MALFORMED_JSON]
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=(
                "✅ Malformed JSON returns JSON-RPC -32700 (Parse error) with a null ID"
                if passed
                else "❌ Malformed JSON does not return JSON-RPC -32700 (Parse error) with a null ID"
            ),
            details={
                "spec": "https://www.jsonrpc.org/specification#response_object",
                "http_status": probe.details.get("http_status"),
                "error_code": probe.details.get("error_code"),
                "response_id_is_null": probe.details.get("response_id_is_null"),
                "control_http_status": probe.details.get("control_http_status"),
            },
        )


@register_rule
class ErrorDataLeakRule(BaseRule):
    """Check if error responses leak sensitive data.

    Error messages should not contain sensitive information like:
    - File paths
    - Stack traces
    - Credentials
    - API keys or tokens

    Scoring: 5 points (MEDIUM)
    """

    rule_id = "security_error_data_leak"
    basis = "MCP 2025-11-25 Tools §Security Considerations (sanitize outputs); error-hygiene best practice"
    group_name = "security"
    group_order = 3
    rule_order = 3

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when there is no remote error response whose contents can be judged.

        Unlike malformed-request behavior, content leakage can be judged from
        an observed response even when the exact remote transport is unknown.
        """
        if audit_data.transport_type == MCPTransportType.STDIO:
            return SKIP_REASON_NOT_APPLICABLE
        if audit_data.error_response is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    # Patterns that indicate sensitive data leakage
    SENSITIVE_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (r"/home/\w+", "file path"),
        (r"/usr/\w+", "file path"),
        (r"C:\\Users\\", "file path"),
        (r"Traceback \(most recent call last\)", "stack trace"),
        (r"at \w+\.\w+ \([^)]+:\d+:\d+\)", "stack trace"),  # JavaScript stack trace
        (r'password["\']?\s*[:=]\s*["\']?[\w!@#$%^&*]+', "password"),
        (r'secret["\']?\s*[:=]\s*["\']?[\w!@#$%^&*]+', "secret"),
        (r'api[_-]?key["\']?\s*[:=]\s*["\']?[\w-]+', "API key"),
        (r'token["\']?\s*[:=]\s*["\']?[\w-]+', "token"),
        (r"Bearer\s+[\w-]+", "auth token"),
    ]

    @property
    def rule_name(self) -> str:
        return "No Sensitive Data in Error Messages"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    @requires_fields("error_response")
    def check(self, error_response: str | None) -> RuleResult:  # type: ignore[override]
        """Check if error responses leak sensitive data.

        Args:
            error_response: Error response from server

        Returns:
            RuleResult indicating pass/fail

        """
        assert error_response is not None  # noqa: S101 — skip_reason guarantees a response to inspect

        # Check for sensitive data patterns
        leaks_found = []
        for pattern, leak_type in self.SENSITIVE_PATTERNS:
            matches = re.findall(pattern, error_response, re.IGNORECASE)
            if matches:
                leaks_found.append(
                    {
                        "type": leak_type,
                        "matches": matches[:3],  # Limit to first 3 matches
                    }
                )

        if leaks_found:
            leak_types = ", ".join({leak["type"] for leak in leaks_found})
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message=f"❌ Error messages leak sensitive data: {leak_types}",
                details={"leaks": leaks_found},
            )

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=True,
            message="✅ Error messages do not appear to leak sensitive data",
            details={"error_response_length": len(error_response)},
        )
