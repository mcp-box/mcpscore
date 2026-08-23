"""Rules for MCP cursor-pagination behavior."""

from typing import ClassVar

from mcpscore.probes import (
    PROBE_PROMPTS_INVALID_CURSOR,
    PROBE_RESOURCE_TEMPLATES_INVALID_CURSOR,
    PROBE_RESOURCES_INVALID_CURSOR,
    PROBE_TOOLS_INVALID_CURSOR,
    ProbeOutcome,
)

from .base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_NOT_APPLICABLE,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
)
from .registry import register_rule

PAGINATION_SPEC = "https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/pagination#error-handling"
"""Latest dated pagination error-handling section, used when no version was observed."""


def pagination_spec(protocol_version: str | None) -> str:
    """Link the rule evidence to the server's negotiated dated specification."""
    if protocol_version is None:
        return PAGINATION_SPEC
    return (
        f"https://modelcontextprotocol.io/specification/{protocol_version}/server/utilities/pagination#error-handling"
    )


class InvalidCursorRule(BaseRule):
    """Base rule requiring Invalid params for a fabricated pagination cursor."""

    basis = "MCP Pagination §Error Handling (invalid cursors SHOULD return -32602 in every dated revision)"
    group_name = "pagination"
    group_order = 9
    capability_name: ClassVar[str]
    probe_id: ClassVar[str]
    surface_label: ClassVar[str]

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip absent capabilities and unavailable probe evidence."""
        capabilities = audit_data.capabilities
        if capabilities is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        if getattr(capabilities, self.capability_name) is None:
            return SKIP_REASON_NOT_APPLICABLE

        probe = (audit_data.probes or {}).get(self.probe_id)
        if probe is None or probe.outcome is ProbeOutcome.ERROR:
            return SKIP_REASON_INSUFFICIENT_DATA
        if probe.outcome is ProbeOutcome.NOT_APPLICABLE:
            return SKIP_REASON_NOT_APPLICABLE
        return None

    def check(self, audit_data: AuditData) -> RuleResult:
        """Report whether the server returned JSON-RPC Invalid params."""
        probe = (audit_data.probes or {})[self.probe_id]
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=(
                f"✅ {self.surface_label} rejects invalid pagination cursors with JSON-RPC -32602"
                if passed
                else f"❌ {self.surface_label} does not reject invalid pagination cursors with JSON-RPC -32602"
            ),
            details={
                "spec": pagination_spec(audit_data.protocol_version),
                "error_code": probe.details.get("error_code"),
                "http_status": probe.details.get("http_status"),
            },
        )


@register_rule
class ToolsInvalidCursorRule(InvalidCursorRule):
    """Check invalid cursor handling for tools/list."""

    rule_id = "pagination_tools_invalid_cursor"
    rule_order = 1
    capability_name = "tools"
    probe_id = PROBE_TOOLS_INVALID_CURSOR
    surface_label = "tools/list"

    @property
    def rule_name(self) -> str:
        return "Tools Invalid Pagination Cursor"


@register_rule
class ResourcesInvalidCursorRule(InvalidCursorRule):
    """Check invalid cursor handling for resources/list."""

    rule_id = "pagination_resources_invalid_cursor"
    rule_order = 2
    capability_name = "resources"
    probe_id = PROBE_RESOURCES_INVALID_CURSOR
    surface_label = "resources/list"

    @property
    def rule_name(self) -> str:
        return "Resources Invalid Pagination Cursor"


@register_rule
class ResourceTemplatesInvalidCursorRule(InvalidCursorRule):
    """Check invalid cursor handling for resources/templates/list."""

    rule_id = "pagination_resource_templates_invalid_cursor"
    rule_order = 3
    capability_name = "resources"
    probe_id = PROBE_RESOURCE_TEMPLATES_INVALID_CURSOR
    surface_label = "resources/templates/list"

    @property
    def rule_name(self) -> str:
        return "Resource Templates Invalid Pagination Cursor"


@register_rule
class PromptsInvalidCursorRule(InvalidCursorRule):
    """Check invalid cursor handling for prompts/list."""

    rule_id = "pagination_prompts_invalid_cursor"
    rule_order = 4
    capability_name = "prompts"
    probe_id = PROBE_PROMPTS_INVALID_CURSOR
    surface_label = "prompts/list"

    @property
    def rule_name(self) -> str:
        return "Prompts Invalid Pagination Cursor"
