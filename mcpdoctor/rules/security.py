import re
from typing import ClassVar

from .base import BaseRule, RuleResult, RuleSeverity, requires_fields
from .registry import register_rule


@register_rule
class TLSEnabledRule(BaseRule):
    """Check if the server uses HTTPS with valid TLS.

    This is a critical security check ensuring that the connection is encrypted
    and the TLS certificate is properly verified.

    Scoring: 10 points (CRITICAL)
    """

    rule_id = "security_tls_enabled"
    group_name = "security"
    group_order = 3
    rule_order = 1

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
        # For stdio connections, TLS check is not applicable
        if url is None:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=True,
                message="✅ TLS check not applicable for stdio transport",
                details={"reason": "stdio_transport"},
            )

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
    """Check if the server handles malformed requests gracefully.

    A well-implemented server should return proper JSON-RPC error responses
    for malformed requests instead of crashing or hanging.

    Scoring: 5 points (MEDIUM)
    """

    rule_id = "security_malformed_request_handling"
    group_name = "security"
    group_order = 3
    rule_order = 2

    @property
    def rule_name(self) -> str:
        return "Malformed Request Handling"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    @requires_fields("error_response", "transport_type")
    def check(self, error_response: str | None, transport_type: str | None) -> RuleResult:  # type: ignore[override]
        """Check if server handles malformed requests properly.

        Args:
            error_response: Error response from malformed request test
            transport_type: The transport type used

        Returns:
            RuleResult indicating pass/fail

        """
        # For stdio, this test may not be applicable
        if transport_type == "stdio":
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=True,
                message="✅ Malformed request handling not tested for stdio transport",
                details={"reason": "stdio_transport"},
            )

        # If no error response was captured, we couldn't test this
        if error_response is None:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=True,
                message="[INFO] Malformed request handling test not performed",
                details={"reason": "test_not_performed"},
            )

        # Check if response looks like a proper JSON-RPC error
        # Expected format: {"jsonrpc": "2.0", "error": {...}, "id": ...}
        is_json_rpc_error = '"jsonrpc"' in error_response and '"error"' in error_response

        if is_json_rpc_error:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=True,
                message="✅ Server returns proper JSON-RPC errors for malformed requests",
                details={"error_response": error_response[:200]},  # Truncate for display
            )

        # Check for crash indicators
        crash_indicators = ["crash", "panic", "exception", "traceback", "fatal", "segfault"]
        has_crash = any(indicator in error_response.lower() for indicator in crash_indicators)

        if has_crash:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message="❌ Server appears to crash or panic on malformed requests",
                details={"error_response": error_response[:200]},
            )

        # Response exists but doesn't look like proper JSON-RPC error
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=False,
            message="⚠️ Server does not return proper JSON-RPC error format for malformed requests",
            details={"error_response": error_response[:200]},
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
    group_name = "security"
    group_order = 3
    rule_order = 3

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
        if error_response is None:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=True,
                message="[INFO] No error response to analyze",
                details={"reason": "no_error_response"},
            )

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
