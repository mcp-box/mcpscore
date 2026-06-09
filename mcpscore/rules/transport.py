from ..enums import MCPTransportType
from .base import BaseRule, RuleResult, RuleSeverity, requires_fields
from .registry import register_rule


@register_rule
class StreamableHTTPTransportRule(BaseRule):
    """Check that a remote server uses the Streamable HTTP transport.

    Streamable HTTP is the current MCP standard for remote servers; the
    standalone SSE transport is deprecated by the specification. Servers
    still exposing only SSE should migrate.

    Scoring: 1 point (LOW - migration recommendation)
    """

    rule_id = "transport_streamable_http"
    group_name = "transport"
    group_order = 5
    rule_order = 1

    @property
    def rule_name(self) -> str:
        return "Streamable HTTP Transport"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    @requires_fields("transport_type", "url")
    def check(self, transport_type: MCPTransportType | None, url: str | None) -> RuleResult:  # type: ignore[override]
        """Check which remote transport the server was reached over.

        Args:
            transport_type: The transport type used for connection
            url: The server URL (if applicable)

        Returns:
            RuleResult indicating pass/fail

        """
        # For stdio connections, remote transport checks are not applicable
        if transport_type == MCPTransportType.STDIO or url is None:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=True,
                message="[INFO] Remote transport check not applicable for stdio connections",
                details={"transport_type": transport_type},
            )

        if transport_type == MCPTransportType.STREAMABLE_HTTP:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=True,
                message="✅ Server uses the Streamable HTTP transport (current MCP standard)",
                details={"transport_type": transport_type, "url": url},
            )

        if transport_type == MCPTransportType.SSE:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message=(
                    "❌ Server only supports the deprecated SSE transport. "
                    "Migrate to Streamable HTTP (MCP spec 2025-03-26+)."
                ),
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
