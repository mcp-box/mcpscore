from abc import abstractmethod

from mcp_types import ServerCapabilities
from pydantic import BaseModel

from .base import BaseRule, RuleResult, RuleSeverity, requires_capabilities
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


@register_rule
class CapabilityToolsPresentRule(CapabilityBaseRule):
    """Critical check: Verify that capabilities.tools is present."""

    rule_id = "capability_tools_present"
    basis = "MCP 2025-11-25 Tools §Capabilities (servers supporting tools MUST declare the capability)"
    rule_order = 1

    @property
    def rule_name(self) -> str:
        return "Capabilities - Tools Present"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    def _check_capabilities(self, capabilities: ServerCapabilities) -> RuleResult:
        """Critical check: Verify that capabilities.tools is present.

        Args:
            capabilities: Server capabilities to check

        Returns:
            RuleResult with the check outcome

        """
        if not hasattr(capabilities, "tools") or not capabilities.tools:
            passed = False
            message = "❌ Tools is not present in capabilities"
        else:
            passed = True
            message = "✅ Tools capability is present"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"capability_tools": _wire_str(getattr(capabilities, "tools", None))},
        )


@register_rule
class CapabilityToolsListChangedRule(CapabilityBaseRule):
    """High check: Verify that capabilities.tools has listChanged implemented."""

    rule_id = "capability_tools_list_changed"
    basis = "MCP 2025-11-25 Tools §Capabilities (listChanged)"
    rule_order = 2

    @property
    def rule_name(self) -> str:
        return "Capabilities - Tools listChanged Implemented"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_capabilities(self, capabilities: ServerCapabilities) -> RuleResult:
        """High check: Verify that capabilities.tools has listChanged implemented.

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
class CapabilityPromptsPresentRule(CapabilityBaseRule):
    """Critical check: Verify that capabilities.prompts is present."""

    rule_id = "capability_prompts_present"
    basis = "MCP 2025-11-25 Prompts §Capabilities (servers supporting prompts MUST declare the capability)"
    rule_order = 3

    @property
    def rule_name(self) -> str:
        return "Capabilities - Prompts Present"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    def _check_capabilities(self, capabilities: ServerCapabilities) -> RuleResult:
        """Critical check: Verify that capabilities.prompts is present.

        Args:
            capabilities: Server capabilities to check

        Returns:
            RuleResult with the check outcome

        """
        if not hasattr(capabilities, "prompts") or not capabilities.prompts:
            passed = False
            message = "❌ Prompts is not present in capabilities"
        else:
            passed = True
            message = "✅ Prompts capability is present"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"capability_prompts": _wire_str(getattr(capabilities, "prompts", None))},
        )


@register_rule
class CapabilityPromptsListChangedRule(CapabilityBaseRule):
    """High check: Verify that capabilities.prompts has listChanged implemented."""

    rule_id = "capability_prompts_list_changed"
    basis = "MCP 2025-11-25 Prompts §Capabilities (listChanged)"
    rule_order = 4

    @property
    def rule_name(self) -> str:
        return "Capabilities - Prompts listChanged Implemented"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_capabilities(self, capabilities: ServerCapabilities) -> RuleResult:
        """High check: Verify that capabilities.prompts has listChanged implemented.

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
class CapabilityResourcesPresentRule(CapabilityBaseRule):
    """Critical check: Verify that capabilities.resources is present."""

    rule_id = "capability_resources_present"
    basis = "MCP 2025-11-25 Resources §Capabilities (servers supporting resources MUST declare the capability)"
    rule_order = 5

    @property
    def rule_name(self) -> str:
        return "Capabilities - Resources Present"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    def _check_capabilities(self, capabilities: ServerCapabilities) -> RuleResult:
        """Critical check: Verify that capabilities.resources is present.

        Args:
            capabilities: Server capabilities to check

        Returns:
            RuleResult with the check outcome

        """
        if not hasattr(capabilities, "resources") or not capabilities.resources:
            passed = False
            message = "❌ Resources is not present in capabilities"
        else:
            passed = True
            message = "✅ Resources capability is present"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"capability_resources": _wire_str(getattr(capabilities, "resources", None))},
        )


@register_rule
class CapabilityResourcesListChangedRule(CapabilityBaseRule):
    """High check: Verify that capabilities.resources has listChanged implemented."""

    rule_id = "capability_resources_list_changed"
    basis = "MCP 2025-11-25 Resources §Capabilities (listChanged)"
    rule_order = 6

    @property
    def rule_name(self) -> str:
        return "Capabilities - Resources listChanged Implemented"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_capabilities(self, capabilities: ServerCapabilities) -> RuleResult:
        """High check: Verify that capabilities.resources has listChanged implemented.

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


@register_rule
class CapabilityResourcesSubscribeRule(CapabilityBaseRule):
    """High check: Verify that capabilities.resources has subscribe implemented."""

    rule_id = "capability_resources_subscribe"
    basis = "MCP 2025-11-25 Resources §Capabilities (subscribe)"
    rule_order = 7

    @property
    def rule_name(self) -> str:
        return "Capabilities - Resources subscribe Implemented"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_capabilities(self, capabilities: ServerCapabilities) -> RuleResult:
        """High check: Verify that capabilities.resources has subscribe implemented.

        Args:
            capabilities: Server capabilities to check

        Returns:
            RuleResult with the check outcome

        """
        if not hasattr(capabilities, "resources") or not capabilities.resources:
            passed = False
            message = "❌ Resources is not present in capabilities"
        elif not capabilities.resources.subscribe:
            passed = False
            message = "❌ subscribe is not supported by Resources"
        else:
            passed = True
            message = f"✅ Resources support subscribe: '{_wire_str(capabilities.resources)}'"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"capability_resources": _wire_str(getattr(capabilities, "resources", None))},
        )


@register_rule
class CapabilityLoggingPresentRule(CapabilityBaseRule):
    """Medium check: Verify that capabilities.logging is present."""

    rule_id = "capability_logging_present"
    basis = "MCP 2025-11-25 Lifecycle §Capability Negotiation (logging)"
    rule_order = 8

    @property
    def rule_name(self) -> str:
        return "Capabilities - Logging Present"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_capabilities(self, capabilities: ServerCapabilities) -> RuleResult:
        """Medium check: Verify that capabilities.logging is present.

        Args:
            capabilities: Server capabilities to check

        Returns:
            RuleResult with the check outcome

        """
        if not hasattr(capabilities, "logging") or not capabilities.logging:
            passed = False
            message = "❌ Logging is not present in capabilities"
        else:
            passed = True
            message = f"✅ Logging capability is present: '{_wire_str(capabilities.logging)}'"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"capability_logging": _wire_str(getattr(capabilities, "logging", None))},
        )
