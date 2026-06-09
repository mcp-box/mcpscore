from abc import abstractmethod
from typing import ClassVar

from mcpscore.enums import MCPProtocolVersion

from .base import BaseRule, RuleResult, RuleSeverity, requires_protocol_version
from .registry import register_rule


class ProtocolVersionBaseRule(BaseRule):
    """Base class for all protocol version related audit rules.

    This abstract base class provides common functionality for rules that
    validate MCP protocol version compliance. It handles the case where
    no protocol version is available and delegates the actual validation
    to subclasses via the _check_protocol_version method.
    """

    group_name = "protocol_version"
    group_order = 1

    @requires_protocol_version
    def check(self, protocol_version: str) -> RuleResult:
        """Execute the protocol version rule check.

        Args:
            protocol_version: The protocol version string to validate

        Returns:
            RuleResult indicating whether the protocol version check passed

        """
        if not protocol_version:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message="❌ Protocol version is not available",
                details={"protocol_version": None},
            )

        return self._check_protocol_version(protocol_version)

    @abstractmethod
    def _check_protocol_version(self, protocol_version: str) -> RuleResult:
        """Perform the actual protocol version validation.

        Args:
            protocol_version: The protocol version string to validate

        Returns:
            RuleResult with the validation outcome

        Note:
            This method must be implemented by subclasses to define
            the specific validation logic for each rule type.

        """
        ...


@register_rule
class AllowedVersionRule(ProtocolVersionBaseRule):
    """Critical check: Verify the MCP protocol version is one of the allowed versions."""

    rule_id = "protocol_version_allowed"
    rule_order = 1

    @property
    def rule_name(self) -> str:
        return "MCP Protocol Version - Allowed Versions"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    def _check_protocol_version(self, protocol_version: str) -> RuleResult:
        """Critical check: Verify the MCP protocol version is one of the allowed versions.

        Args:
            protocol_version: The protocol version string to check
        Returns:
            RuleResult with the check outcome

        """
        # Check if the version is in our allowed list
        allowed_versions = [v.value for v in MCPProtocolVersion]
        passed = protocol_version in allowed_versions

        message = (
            f"✅ Protocol version '{protocol_version}' is one of the allowed versions"
            if passed
            else f"❌ Protocol version '{protocol_version}' is not in the allowed versions list"
        )

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"version": protocol_version, "allowed_versions": allowed_versions},
        )


@register_rule
class LatestVersionRule(ProtocolVersionBaseRule):
    """Medium check: Verify the MCP protocol version is the latest available version."""

    rule_id = "protocol_version_latest"
    rule_order = 3

    @property
    def rule_name(self) -> str:
        return "MCP Protocol Version - Latest Version"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_protocol_version(self, protocol_version: str) -> RuleResult:
        """Medium check: Verify the MCP protocol version is the latest available version.

        Args:
            protocol_version: The protocol version string to check

        Returns:
            RuleResult with the check outcome

        """
        # Check if the version is the most recent version
        passed: bool = protocol_version == MCPProtocolVersion.Latest
        if passed:
            message: str = f"✅ Protocol version '{protocol_version}' is the latest version"
        else:
            message: str = f"❌ Not using the latest protocol version. Current: '{protocol_version}'"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"version": protocol_version, "latest_version": MCPProtocolVersion.Latest},
        )


@register_rule
class DeprecatedVersionRule(ProtocolVersionBaseRule):
    """High check: Verify the MCP protocol version is not deprecated."""

    rule_id = "protocol_version_not_deprecated"
    rule_order = 2

    deprecated_versions: ClassVar[list[str]] = [
        # Add versions here as the MCP spec deprecates them
    ]
    """Protocol versions deprecated by the MCP specification."""

    @property
    def rule_name(self) -> str:
        return "MCP Protocol Version - Deprecated Version"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_protocol_version(self, protocol_version: str) -> RuleResult:
        """High check: Verify the MCP protocol version is not deprecated.

        Args:
            protocol_version: The protocol version string to check

        Returns:
            RuleResult with the check outcome

        """
        passed: bool = protocol_version not in self.deprecated_versions
        if passed:
            message: str = f"✅ Protocol version '{protocol_version}' is not deprecated"
        else:
            message: str = f"❌ Protocol version '{protocol_version}' is deprecated"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"version": protocol_version, "deprecated_versions": list(self.deprecated_versions)},
        )
