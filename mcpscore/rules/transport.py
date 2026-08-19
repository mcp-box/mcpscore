from ..enums import MCPTransportType
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
class StreamableHTTPTransportRule(BaseRule):
    """Check that a remote server uses the Streamable HTTP transport.

    Streamable HTTP is the current MCP standard for remote servers; the
    standalone SSE transport is deprecated by the specification. Servers
    still exposing only SSE should migrate.

    Scoring: 1 point (LOW - migration recommendation)
    """

    rule_id = "transport_streamable_http"
    basis = "MCP 2025-11-25 Transports §Streamable HTTP (replaces the deprecated HTTP+SSE transport from 2024-11-05)"
    group_name = "transport"
    group_order = 5
    rule_order = 1

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip in a partial audit where no transport was established.

        A partial audit reaches the server only over raw probe requests; it
        never confirms which MCP transport the server speaks, so the rule
        cannot judge (transport_type is None) and must not claim a pass.
        """
        if audit_data.transport_type == MCPTransportType.STDIO:
            return SKIP_REASON_NOT_APPLICABLE
        if audit_data.transport_type is None or audit_data.url is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

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
        assert transport_type is not None  # noqa: S101 — skip_reason guarantees transport data
        assert url is not None  # noqa: S101 — skip_reason guarantees a remote URL

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
