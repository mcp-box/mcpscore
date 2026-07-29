"""Rules over the server's declared capabilities.

Two kinds of rule live here, and the distinction is deliberate:

- **Consistency rules** (CRITICAL) enforce a real spec MUST — "servers that
  support tools/resources/prompts MUST declare the corresponding capability".
  They compare what the server *declares* against what it actually *serves*,
  so a server that legitimately offers no resources is not penalized for the
  capability being absent; only a mismatch fails.
- **Advisory rules** (LOW) cover `listChanged`, which the spec calls optional
  ("servers can support neither, either, or both"). They are mcpscore quality
  opinions — an agent holding a stale tool list is a real UX problem — and
  their severity says so rather than dressing a recommendation as a
  requirement.
"""

from abc import abstractmethod

from mcp_types import ServerCapabilities
from pydantic import BaseModel

from .base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_NOT_APPLICABLE,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
    requires_capabilities,
    requires_fields,
)
from .registry import register_rule


def _wire_str(capability: object | None) -> str | None:
    """Render a capability model using MCP wire field names (spec casing).

    Report messages and details are public output and must show the spec's
    field names (e.g. ``listChanged``), not the SDK's Python attribute names.
    """
    if not isinstance(capability, BaseModel):
        return None if capability is None else str(capability)
    fields = type(capability).model_fields
    return " ".join(f"{field.alias or name}={getattr(capability, name)}" for name, field in fields.items())


class CapabilityBaseRule(BaseRule):
    """Base class for all capabilities related audit rules.

    This abstract base class provides common functionality for rules that
    validate MCP server capabilities compliance. It handles the case where
    no capabilities info is available and delegates the actual validation
    to subclasses via the _check_capabilities method.
    """

    group_name = "capabilities"
    group_order = 3

    @requires_capabilities
    def check(self, capabilities: ServerCapabilities | None) -> RuleResult:
        """Execute the capabilities rule check.

        Args:
            capabilities: The capabilities info to validate

        Returns:
            RuleResult indicating whether the capabilities check passed

        """
        if capabilities is None:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message="❌ Capabilities object is not available",
                details={"capabilities": None},
            )

        return self._check_capabilities(capabilities)

    @abstractmethod
    def _check_capabilities(self, capabilities: ServerCapabilities) -> RuleResult:
        """Perform the actual capabilities' validation.

        Args:
            capabilities: The capabilities to validate

        Returns:
            RuleResult with the validation outcome

        Note:
            This method must be implemented by subclasses to define
            the specific validation logic for each rule type.

        """
        ...


class CapabilityDeclarationRule(BaseRule):
    """Base class for the declared-vs-served consistency rules.

    The spec requires the *declaration* of a feature the server supports, never
    the feature itself: "Servers that support resources MUST declare the
    resources capability". A server that neither declares nor serves the
    feature passes, because that is a legitimate design choice (most MCP
    servers are tools-only).

    **Only judges a listing the auditor actually attempted.** `items is None`
    does not mean "the listing failed": the session path lists a feature only
    when the server declares it, and the modern-only probe path collects tools
    alone. Reading that silence as failure cost a modern server declaring
    resources and prompts 10 CRITICAL points for nothing. Rules whose listing
    was never attempted skip as insufficient-data — see `listings_attempted`.

    That gating also bounds what the rule can detect: serving a feature without
    declaring it is caught only when something else caused the listing to run.
    """

    group_name = "capabilities"
    group_order = 3

    feature: str = ""
    """Capability attribute name on ServerCapabilities (e.g. "resources")."""

    method: str = ""
    """The listing method this feature is served over (e.g. "resources/list")."""

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when this feature's listing was never attempted — silence is not evidence."""
        if self.feature not in audit_data.listings_attempted:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def _evaluate(self, capabilities: ServerCapabilities | None, items: list | None) -> RuleResult:
        """Compare the declared capability against what the server served."""
        declared = getattr(capabilities, self.feature, None) is not None if capabilities is not None else False
        served = items is not None

        if declared and served:
            passed = True
            message = f"✅ Declares the {self.feature} capability and serves {len(items or [])} via {self.method}"
        elif not declared and not served:
            passed = True
            message = (
                f"✅ Server offers no {self.feature} and declares none — "
                f"the {self.feature} capability is only required of servers that support it"
            )
        elif served and not declared:
            passed = False
            message = (
                f"❌ Server serves {len(items or [])} {self.feature} but does not declare the "
                f"{self.feature} capability — servers that support {self.feature} MUST declare it"
            )
        else:
            passed = False
            message = (
                f"❌ Server declares the {self.feature} capability but {self.method} did not answer — "
                "clients will call it and fail"
            )

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                f"capability_{self.feature}": _wire_str(getattr(capabilities, self.feature, None)),
                "declared": declared,
                "served": served,
            },
        )


@register_rule
class CapabilityToolsPresentRule(CapabilityDeclarationRule):
    """Critical check: the declared tools capability matches what the server serves."""

    rule_id = "capability_tools_present"
    basis = "MCP 2025-11-25 Tools §Capabilities (servers supporting tools MUST declare the capability)"
    rule_order = 1
    feature = "tools"
    method = "tools/list"

    @property
    def rule_name(self) -> str:
        return "Capabilities - Tools Declared Consistently"

    @requires_fields("capabilities", "tools")
    def check(self, capabilities: ServerCapabilities | None, items: list | None) -> RuleResult:  # type: ignore[override]
        """Compare the declared tools capability against the served tools."""
        return self._evaluate(capabilities, items)


class CapabilityListChangedRule(CapabilityBaseRule):
    """Base class for the advisory `listChanged` rules.

    `listChanged` is optional per the spec; these rules are mcpscore quality
    opinions, scored LOW — an agent that caches a tool list and never hears
    about changes silently works from a stale copy.

    **Only judges a feature the server actually offers.** A tools-only server
    has nothing to say about `prompts.listChanged`, and failing it for that was
    the same optionality error the presence rules carried until 1.1.0: the
    2026-07-29 registry sweep found 2,798 servers failing
    `capability_prompts_list_changed` with no prompts at all, and 2,582 the
    same for resources. Undeclared feature -> the advisory skips.
    """

    feature: str = ""
    """Capability attribute this advisory is about (e.g. "prompts")."""

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when the server does not offer this feature at all."""
        capabilities = audit_data.capabilities
        if capabilities is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        if getattr(capabilities, self.feature, None) is None:
            return SKIP_REASON_NOT_APPLICABLE
        return None


@register_rule
class CapabilityToolsListChangedRule(CapabilityListChangedRule):
    """Advisory: the tools capability declares listChanged so clients can refresh a stale list.

    Optional per the spec — an mcpscore quality opinion, scored LOW: without
    it an agent caches the tools list and silently works from a stale copy.
    """

    rule_id = "capability_tools_list_changed"
    basis = "mcpscore recommendation; MCP 2025-11-25 Tools §Capabilities defines listChanged as optional"
    rule_order = 2
    feature = "tools"

    @property
    def rule_name(self) -> str:
        return "Capabilities - Tools listChanged Implemented"

    def _check_capabilities(self, capabilities: ServerCapabilities) -> RuleResult:
        """Advisory check: verify that capabilities.tools declares listChanged.

        Args:
            capabilities: Server capabilities to check

        Returns:
            RuleResult with the check outcome

        """
        if not hasattr(capabilities, "tools") or not capabilities.tools:
            passed = False
            message = "❌ Tools is not present in capabilities"
        elif not capabilities.tools.list_changed:
            passed = False
            message = "❌ listChanged is not supported by Tools"
        else:
            passed = True
            message = f"✅ Tools support listChanged: '{_wire_str(capabilities.tools)}'"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"capability_tools": _wire_str(getattr(capabilities, "tools", None))},
        )


@register_rule
class CapabilityPromptsPresentRule(CapabilityDeclarationRule):
    """Critical check: the declared prompts capability matches what the server serves."""

    rule_id = "capability_prompts_present"
    basis = "MCP 2025-11-25 Prompts §Capabilities (servers supporting prompts MUST declare the capability)"
    rule_order = 3
    feature = "prompts"
    method = "prompts/list"

    @property
    def rule_name(self) -> str:
        return "Capabilities - Prompts Declared Consistently"

    @requires_fields("capabilities", "prompts")
    def check(self, capabilities: ServerCapabilities | None, items: list | None) -> RuleResult:  # type: ignore[override]
        """Compare the declared prompts capability against the served prompts."""
        return self._evaluate(capabilities, items)


@register_rule
class CapabilityPromptsListChangedRule(CapabilityListChangedRule):
    """Advisory: the prompts capability declares listChanged so clients can refresh a stale list.

    Optional per the spec — an mcpscore quality opinion, scored LOW: without
    it an agent caches the prompts list and silently works from a stale copy.
    """

    rule_id = "capability_prompts_list_changed"
    basis = "mcpscore recommendation; MCP 2025-11-25 Prompts §Capabilities defines listChanged as optional"
    rule_order = 4
    feature = "prompts"

    @property
    def rule_name(self) -> str:
        return "Capabilities - Prompts listChanged Implemented"

    def _check_capabilities(self, capabilities: ServerCapabilities) -> RuleResult:
        """Advisory check: verify that capabilities.prompts declares listChanged.

        Args:
            capabilities: Server capabilities to check

        Returns:
            RuleResult with the check outcome

        """
        if not hasattr(capabilities, "prompts") or not capabilities.prompts:
            passed = False
            message = "❌ Prompts is not present in capabilities"
        elif not capabilities.prompts.list_changed:
            passed = False
            message = "❌ listChanged is not supported by Prompts"
        else:
            passed = True
            message = f"✅ Prompts support listChanged: '{_wire_str(capabilities.prompts)}'"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"capability_prompts": _wire_str(getattr(capabilities, "prompts", None))},
        )


@register_rule
class CapabilityResourcesPresentRule(CapabilityDeclarationRule):
    """Critical check: the declared resources capability matches what the server serves."""

    rule_id = "capability_resources_present"
    basis = "MCP 2025-11-25 Resources §Capabilities (servers supporting resources MUST declare the capability)"
    rule_order = 5
    feature = "resources"
    method = "resources/list"

    @property
    def rule_name(self) -> str:
        return "Capabilities - Resources Declared Consistently"

    @requires_fields("capabilities", "resources")
    def check(self, capabilities: ServerCapabilities | None, items: list | None) -> RuleResult:  # type: ignore[override]
        """Compare the declared resources capability against the served resources."""
        return self._evaluate(capabilities, items)


@register_rule
class CapabilityResourcesListChangedRule(CapabilityListChangedRule):
    """Advisory: the resources capability declares listChanged so clients can refresh a stale list.

    Optional per the spec — an mcpscore quality opinion, scored LOW: without
    it an agent caches the resources list and silently works from a stale copy.
    """

    rule_id = "capability_resources_list_changed"
    basis = "mcpscore recommendation; MCP 2025-11-25 Resources §Capabilities defines listChanged as optional"
    rule_order = 6
    feature = "resources"

    @property
    def rule_name(self) -> str:
        return "Capabilities - Resources listChanged Implemented"

    def _check_capabilities(self, capabilities: ServerCapabilities) -> RuleResult:
        """Advisory check: verify that capabilities.resources declares listChanged.

        Args:
            capabilities: Server capabilities to check

        Returns:
            RuleResult with the check outcome

        """
        if not hasattr(capabilities, "resources") or not capabilities.resources:
            passed = False
            message = "❌ Resources is not present in capabilities"
        elif not capabilities.resources.list_changed:
            passed = False
            message = "❌ listChanged is not supported by Resources"
        else:
            passed = True
            message = f"✅ Resources support listChanged: '{_wire_str(capabilities.resources)}'"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"capability_resources": _wire_str(getattr(capabilities, "resources", None))},
        )


# Retired in 1.1.0 — `capability_resources_subscribe` (HIGH) and
# `capability_logging_present` (MEDIUM). Both scored the *absence* of a
# capability the spec section they cited calls optional:
#
#   "Both `subscribe` and `listChanged` are optional — servers can support
#    neither, either, or both." (2025-11-25 Resources §Capabilities)
#
# and the 2026-07-28 revision goes further: SEP-2575 removes
# `resources/subscribe`/`unsubscribe` in favour of `subscriptions/listen`, and
# SEP-2577 deprecates Logging with the guidance that new implementations should
# not adopt it. `capability_logging_present` also directly contradicted
# `readiness_2026_deprecated_features`, which fails a server for *declaring*
# `logging` — with readiness promoted into the main score for modern/dual-era
# servers, no server could pass both.
#
# Their rule_ids are retired, never reused (rule_id is a public contract).
