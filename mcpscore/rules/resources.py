from abc import abstractmethod

from mcp_types import Resource

from .base import BaseRule, RuleResult, RuleSeverity, requires_fields
from .registry import register_rule


class ResourcesBaseRule(BaseRule):
    """Base class for resource-quality audit rules.

    Resources are an optional MCP capability, so these rules never penalize a
    server that offers none: with no resources there is nothing to evaluate and
    the check passes as not-applicable. They grade only the *quality* of
    resources that are actually declared. (Whether a server *should* offer
    resources at all is handled by the capability-presence rules.)
    """

    group_name = "resources"
    group_order = 6

    @requires_fields("resources")
    def check(self, resources: list[Resource] | None) -> RuleResult:  # type: ignore[override]
        """Execute the resource rule check, skipping servers with no resources.

        Args:
            resources: The declared resources, or None if unsupported

        Returns:
            RuleResult indicating whether the resource check passed

        """
        if not resources:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=True,
                message="✅ No resources to evaluate",
                details={"resources_count": 0},
            )
        return self._check_resources(resources)

    @abstractmethod
    def _check_resources(self, resources: list[Resource]) -> RuleResult:
        """Perform the actual resource validation.

        Args:
            resources: The declared resources to validate

        Returns:
            RuleResult with the validation outcome

        """
        ...


@register_rule
class ResourcesDescriptionPresentRule(ResourcesBaseRule):
    """Medium check: Verify that all declared resources have a description."""

    rule_id = "resources_description_present"
    rule_order = 1

    @property
    def rule_name(self) -> str:
        return "Resources - All resources should have a description"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_resources(self, resources: list[Resource]) -> RuleResult:
        """Medium check: Verify that every resource has a non-empty description.

        Args:
            resources: The declared resources to validate

        Returns:
            RuleResult with the check outcome

        """
        resources_without_description: list[str] = [
            resource.name for resource in resources if not (resource.description and resource.description.strip())
        ]

        passed = len(resources_without_description) == 0

        message = (
            "✅ All resources have a description"
            if passed
            else f"❌ Number of resources without a description: {len(resources_without_description)}"
        )

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"resources_without_description": resources_without_description},
        )
