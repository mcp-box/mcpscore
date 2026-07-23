from abc import abstractmethod

from mcp_types import Implementation

from .base import BaseRule, RuleResult, RuleSeverity, requires_fields, requires_server_info
from .registry import register_rule


class ServerInfoBaseRule(BaseRule):
    """Base class for all server information related audit rules.

    This abstract base class provides common functionality for rules that
    validate MCP server information compliance. It handles the case where
    no server info is available and delegates the actual validation
    to subclasses via the _check_server_info method.
    """

    group_name = "server_info"
    group_order = 2

    @requires_server_info
    def check(self, server_info: Implementation | None) -> RuleResult:
        """Execute the server info rule check.

        Args:
            server_info: The server implementation info to validate

        Returns:
            RuleResult indicating whether the server info check passed

        """
        if server_info is None:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message="❌ Server info is not available",
                details={"server_info": None},
            )

        return self._check_server_info(server_info)

    @abstractmethod
    def _check_server_info(self, server_info: Implementation) -> RuleResult:
        """Perform the actual server information validation.

        Args:
            server_info: The server implementation info to validate

        Returns:
            RuleResult with the validation outcome

        Note:
            This method must be implemented by subclasses to define
            the specific validation logic for each rule type.

        """
        ...


@register_rule
class ServerNamePresentRule(ServerInfoBaseRule):
    """Critical check: Verify that serverInfo.name is present."""

    rule_id = "server_name_present"
    rule_order = 1

    @property
    def rule_name(self) -> str:
        return "Server Info - Name Present"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    def _check_server_info(self, server_info: Implementation) -> RuleResult:
        """Critical check: Verify that serverInfo.name is present.

        Args:
            server_info: Server implementation info to check

        Returns:
            RuleResult with the check outcome

        """
        if not hasattr(server_info, "name") or not server_info.name:
            passed = False
            message = "❌ Server name is not present in server info"
        else:
            passed = True
            message = f"✅ Server name is present: '{server_info.name}'"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"server_name": getattr(server_info, "name", None)},
        )


@register_rule
class ServerTitlePresentRule(ServerInfoBaseRule):
    """Medium check: Verify that serverInfo.title is present."""

    rule_id = "server_title_present"
    rule_order = 3

    @property
    def rule_name(self) -> str:
        return "Server Info - Title Present"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_server_info(self, server_info: Implementation) -> RuleResult:
        """Medium check: Verify that serverInfo.title is present.

        Args:
            server_info: Server implementation info to check

        Returns:
            RuleResult with the check outcome

        """
        if not hasattr(server_info, "title") or server_info.title is None:
            passed = False
            message = "❌ Server title is not present in server info"
        else:
            passed = True
            message = f"✅ Server title is present: '{server_info.title}'"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"server_title": getattr(server_info, "title", None)},
        )


@register_rule
class ServerVersionPresentRule(ServerInfoBaseRule):
    """High check: Verify that serverInfo.version is present."""

    rule_id = "server_version_present"
    rule_order = 2

    @property
    def rule_name(self) -> str:
        return "Server Info - Version Present"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_server_info(self, server_info: Implementation) -> RuleResult:
        """High check: Verify that serverInfo.version is present.

        Args:
            server_info: Server implementation info to check

        Returns:
            RuleResult with the check outcome

        """
        if not hasattr(server_info, "version") or not server_info.version:
            passed = False
            message = "❌ Server version is not present in server info"
        else:
            passed = True
            message = f"✅ Server version is present: '{server_info.version}'"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"server_version": getattr(server_info, "version", None)},
        )


@register_rule
class ServerInstructionsPresentRule(BaseRule):
    """Low check: Verify the server provides `instructions`.

    The `instructions` field from the initialize result tells a client (and its
    LLM) how to use the server effectively. It is optional but recommended for
    every server, so a missing one is a completeness gap.
    """

    group_name = "server_info"
    group_order = 2
    rule_id = "server_instructions_present"
    rule_order = 4

    @property
    def rule_name(self) -> str:
        return "Server Info - Instructions Present"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    @requires_fields("instructions")
    def check(self, instructions: str | None) -> RuleResult:  # type: ignore[override]
        """Low check: Verify the server provides non-empty instructions.

        Args:
            instructions: The server's instructions string, if any

        Returns:
            RuleResult with the check outcome

        """
        passed = bool(instructions and instructions.strip())
        message = (
            "✅ Server provides instructions"
            if passed
            else "❌ Server does not provide instructions (optional but recommended)"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"has_instructions": passed},
        )


@register_rule
class ServerWebsiteUrlPresentRule(ServerInfoBaseRule):
    """Low check: Verify that serverInfo.websiteUrl is present.

    The ``websiteUrl`` field (2025-11-25) gives clients and registries a
    human-facing home for the server; a missing one is a completeness gap.
    """

    rule_id = "server_websiteurl_present"
    rule_order = 5
    min_spec_version = "2025-11-25"

    @property
    def rule_name(self) -> str:
        return "Server Info - Website URL Present"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def _check_server_info(self, server_info: Implementation) -> RuleResult:
        """Low check: Verify that serverInfo.websiteUrl is present.

        Args:
            server_info: Server implementation info to check

        Returns:
            RuleResult with the check outcome

        """
        website_url = getattr(server_info, "website_url", None)
        if website_url:
            passed = True
            message = f"✅ Server website URL is present: '{website_url}'"
        else:
            passed = False
            message = "❌ Server website URL (websiteUrl) is not present in server info"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"website_url": website_url},
        )


@register_rule
class ServerIconsPresentRule(ServerInfoBaseRule):
    """Low check: Verify that serverInfo declares valid icons.

    Icons (2025-11-25) are what registries and client directories render next
    to the server's name; each declared icon must carry a usable ``src``
    (an https:// or data: URI) — declaring none, or declaring broken ones,
    lists the server worse than its peers.
    """

    rule_id = "server_icons_present"
    rule_order = 6
    min_spec_version = "2025-11-25"

    @property
    def rule_name(self) -> str:
        return "Server Info - Icons Present and Valid"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def _check_server_info(self, server_info: Implementation) -> RuleResult:
        """Low check: Verify that serverInfo declares icons with valid sources.

        Args:
            server_info: Server implementation info to check

        Returns:
            RuleResult with the check outcome

        """
        icons = getattr(server_info, "icons", None) or []
        invalid = [
            icon.src for icon in icons if not (isinstance(icon.src, str) and icon.src.startswith(("https://", "data:")))
        ]
        if not icons:
            passed = False
            message = "❌ Server declares no icons in server info"
        elif invalid:
            passed = False
            message = f"❌ Number of icons without a valid https/data src: {len(invalid)}"
        else:
            passed = True
            message = f"✅ Server declares {len(icons)} icon(s) with valid sources"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"icon_count": len(icons), "invalid_srcs": invalid},
        )
