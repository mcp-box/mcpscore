from abc import abstractmethod

from mcp_types import Implementation

from .base import BaseRule, RuleResult, RuleSeverity, requires_fields, requires_server_info
from .catalog_diagnostics import catalog_result, field_issue
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
                suggested_fix=(
                    "Check the lifecycle response and connection in server logs, then retry the audit. "
                    "Server metadata was unavailable, so individual fields could not be assessed."
                ),
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
    basis = "MCP 2025-11-25 Lifecycle §Initialization (serverInfo.name)"
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
            message = "✅ serverInfo.name is present."

        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"server_name": getattr(server_info, "name", None)},
            suggested_fix=(
                "Set serverInfo.name to a non-empty identifier in the server metadata returned by the "
                "applicable lifecycle."
            ),
            issues=[field_issue("server", None, "/serverInfo/name", "missing_metadata", "a non-empty identifier")],
            recommendation=False,
        )


@register_rule
class ServerTitlePresentRule(ServerInfoBaseRule):
    """Medium check: Verify that serverInfo.title is present."""

    rule_id = "server_title_present"
    basis = "MCP 2025-11-25 Lifecycle §Initialization (serverInfo.title)"
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
            message = "✅ serverInfo.title is present (presence checked only)."

        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"server_title": getattr(server_info, "title", None)},
            suggested_fix="Add a human-readable serverInfo.title so clients can display a recognizable server name.",
            issues=[field_issue("server", None, "/serverInfo/title", "missing_metadata", "a display title")],
            recommendation=True,
        )


@register_rule
class ServerVersionPresentRule(ServerInfoBaseRule):
    """High check: Verify that serverInfo.version is present."""

    rule_id = "server_version_present"
    basis = "MCP 2025-11-25 Lifecycle §Initialization (serverInfo.version)"
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
            message = "✅ serverInfo.version is present (format not checked)."

        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"server_version": getattr(server_info, "version", None)},
            suggested_fix=(
                "Set serverInfo.version to a non-empty implementation version in server metadata. "
                "This check does not require semantic versioning."
            ),
            issues=[
                field_issue(
                    "server", None, "/serverInfo/version", "missing_metadata", "a non-empty implementation version"
                )
            ],
            recommendation=False,
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
    basis = "MCP 2025-11-25 Lifecycle §Initialization (instructions)"
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
        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"has_instructions": passed},
            suggested_fix=(
                "Add instructions describing when to use this server, important limitations and the intended workflow."
            ),
            issues=[field_issue("server", None, "/instructions", "missing_metadata", "nonblank usage instructions")],
            recommendation=True,
        )


@register_rule
class ServerWebsiteUrlPresentRule(ServerInfoBaseRule):
    """Low check: Verify that serverInfo.websiteUrl is present.

    The ``websiteUrl`` field (2025-11-25) gives clients and registries a
    human-facing home for the server; a missing one is a completeness gap.
    """

    rule_id = "server_websiteurl_present"
    basis = "MCP 2025-11-25 Lifecycle §Initialization (serverInfo.websiteUrl; 2025-11-25 field)"
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
            message = "✅ serverInfo.websiteUrl is present (URL not fetched or validated)."
        else:
            passed = False
            message = "❌ Server websiteUrl is not present in server info"

        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"website_url": website_url},
            suggested_fix="Add serverInfo.websiteUrl pointing to the server's documentation or project homepage.",
            issues=[
                field_issue(
                    "server", None, "/serverInfo/websiteUrl", "missing_metadata", "a project or documentation URL"
                )
            ],
            recommendation=True,
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
    basis = "MCP 2025-11-25 Lifecycle §Initialization (serverInfo.icons; 2025-11-25 field)"
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
            message = "❌ serverInfo.icons is absent or empty"
        elif invalid:
            passed = False
            message = f"❌ Number of server icons whose src lacks an https:// or data: prefix: {len(invalid)}"
        else:
            passed = True
            message = (
                f"✅ Server declares {len(icons)} icon(s) with an https:// or data: src prefix (content not checked)."
            )

        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"icon_count": len(icons), "invalid_srcs": invalid},
            suggested_fix=(
                (
                    "Consider adding a serverInfo.icons entry for recognition in clients, using an HTTPS "
                    "image URL or a base64 image data URI."
                )
                if not icons
                else (
                    "Set each reported serverInfo.icons src to an HTTPS image URL or a base64 image data "
                    "URI. Verify the image separately; this check only tests the URI prefix."
                )
            ),
            recommendation=not icons,
            issues=(
                [field_issue("server", None, "/serverInfo/icons", "missing_icons", "an optional display icon")]
                if not icons
                else [
                    field_issue(
                        "server",
                        None,
                        f"/serverInfo/icons/{index}/src",
                        "unsupported_icon_prefix",
                        "an https:// or data: prefix",
                    )
                    for index, icon in enumerate(icons)
                    if not (isinstance(icon.src, str) and icon.src.startswith(("https://", "data:")))
                ]
            ),
        )
