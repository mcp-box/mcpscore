from .base import BaseRule, RuleResult, RuleSeverity, requires_fields
from .registry import register_rule


@register_rule
class SSETransportSupportRule(BaseRule):
    """Check if the server supports SSE (Server-Sent Events) transport.

    SSE transport provides better performance for real-time communication
    and is recommended for production MCP servers.

    Scoring: 5 points (LOW - nice to have but not critical)
    """

    rule_id = "transport_sse_support"
    group_name = "transport"
    group_order = 5
    rule_order = 1

    @property
    def rule_name(self) -> str:
        return "SSE Transport Support"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    @requires_fields("transport_type", "url")
    def check(self, transport_type: str | None, url: str | None) -> RuleResult:  # type: ignore[override]
        """Check if server supports SSE transport.

        Args:
            transport_type: The transport type used for connection
            url: The server URL (if applicable)

        Returns:
            RuleResult indicating pass/fail

        """
        # For stdio connections, SSE is not applicable
        if transport_type == "stdio" or url is None:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=True,
                message="[INFO] SSE transport not applicable for stdio connections",
                details={"transport_type": transport_type},
            )

        # Check if SSE transport was successfully used
        if transport_type == "sse":
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=True,
                message="✅ Server supports SSE transport",
                details={"transport_type": transport_type, "url": url},
            )

        # Server uses HTTP but not SSE
        if transport_type == "streamable-http":
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message="Server uses Streamable HTTP but not SSE. Consider adding SSE support for better performance.",
                details={"transport_type": transport_type, "url": url},
            )

        # Unknown transport type
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=False,
            message=f"[INFO] Unknown transport type: {transport_type}",
            details={"transport_type": transport_type, "url": url},
        )
