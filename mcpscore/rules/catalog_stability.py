"""Rules requiring modern catalogs to remain stable across connections."""

from typing import ClassVar

from mcpscore.probes import (
    PROBE_PROMPTS_CATALOG_CONNECTION_INDEPENDENT,
    PROBE_RESOURCES_CATALOG_CONNECTION_INDEPENDENT,
    PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT,
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


class CatalogConnectionIndependentRule(BaseRule):
    """Require one catalog set for the same authorization across connections."""

    min_spec_version = "2026-07-28"
    uses_modern_probe_evidence = True
    probe_id: ClassVar[str]
    surface_label: ClassVar[str]
    spec_url: ClassVar[str]

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip absent catalog capabilities and incomplete comparisons."""
        probe = (audit_data.probes or {}).get(self.probe_id)
        if probe is None or probe.outcome is ProbeOutcome.ERROR:
            return SKIP_REASON_INSUFFICIENT_DATA
        if probe.outcome is ProbeOutcome.NOT_APPLICABLE:
            return SKIP_REASON_NOT_APPLICABLE
        return None

    def check(self, audit_data: AuditData) -> RuleResult:
        """Report whether two independent connections returned one identity set."""
        probe = (audit_data.probes or {})[self.probe_id]
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=(
                f"✅ {self.surface_label} is independent of the client connection"
                if passed
                else f"❌ {self.surface_label} varies across client connections"
            ),
            details={
                **probe.details,
                "spec": self.spec_url,
            },
        )


@register_rule
class ToolsCatalogConnectionIndependentRule(CatalogConnectionIndependentRule):
    """Require the tools catalog to remain stable across connections."""

    rule_id = "tools_catalog_connection_independent"
    basis = "MCP 2026-07-28 Tools §Capabilities (tool set MUST NOT vary per-connection)"
    group_name = "pagination"
    group_order = 9
    rule_order = 6
    probe_id = PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT
    surface_label = "Tools catalog"
    spec_url = "https://modelcontextprotocol.io/specification/2026-07-28/server/tools#capabilities"

    @property
    def rule_name(self) -> str:
        return "Tools Catalog Connection Independent"


@register_rule
class ResourcesCatalogConnectionIndependentRule(CatalogConnectionIndependentRule):
    """Require the resources catalog to remain stable across connections."""

    rule_id = "resources_catalog_connection_independent"
    basis = "MCP 2026-07-28 Resources §Capabilities (resource set MUST NOT vary per-connection)"
    group_name = "pagination"
    group_order = 9
    rule_order = 7
    probe_id = PROBE_RESOURCES_CATALOG_CONNECTION_INDEPENDENT
    surface_label = "Resources catalog"
    spec_url = "https://modelcontextprotocol.io/specification/2026-07-28/server/resources#capabilities"

    @property
    def rule_name(self) -> str:
        return "Resources Catalog Connection Independent"


@register_rule
class PromptsCatalogConnectionIndependentRule(CatalogConnectionIndependentRule):
    """Require the prompts catalog to remain stable across connections."""

    rule_id = "prompts_catalog_connection_independent"
    basis = "MCP 2026-07-28 Prompts §Capabilities (prompt set MUST NOT vary per-connection)"
    group_name = "pagination"
    group_order = 9
    rule_order = 8
    probe_id = PROBE_PROMPTS_CATALOG_CONNECTION_INDEPENDENT
    surface_label = "Prompts catalog"
    spec_url = "https://modelcontextprotocol.io/specification/2026-07-28/server/prompts#capabilities"

    @property
    def rule_name(self) -> str:
        return "Prompts Catalog Connection Independent"
