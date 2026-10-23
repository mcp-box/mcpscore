from abc import abstractmethod
from typing import Any

from mcp_types import Implementation

from mcpscore.diagnostics import quoted_preview
from mcpscore.probes import PROBE_STATELESS_LIST, ProbeOutcome
from mcpscore.skills import SKILLS_EXTENSION

from .base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
    requires_fields,
    requires_server_info,
)
from .catalog_diagnostics import catalog_result, field_issue
from .registry import register_rule
from .skills import declares_skills, discover_capabilities


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
            message = f"✅ Server name is present: {quoted_preview(server_info.name)}."

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
            message = f"✅ Server title is present: {quoted_preview(server_info.title)} (presence checked only)."

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
            message = f"✅ Server version is present: {quoted_preview(server_info.version)} (format not checked)."

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


_PRIMITIVE_LISTINGS = {
    "tools": "tools",
    "resources": "resources",
    "resource_templates": "resources",
    "prompts": "prompts",
}
"""Each primitive listing the auditor collects, and the capability that declares it."""


def _stateless_tools(audit_data: AuditData) -> int | None:
    """Count the tools the stateless ``tools/list`` probe received; None when it received no tools array."""
    probe = (audit_data.probes or {}).get(PROBE_STATELESS_LIST)
    if probe is None or probe.outcome is not ProbeOutcome.SUPPORTED or not isinstance(probe.payload, dict):
        return None
    tools = probe.payload.get("tools")
    return len(tools) if isinstance(tools, list) else None


def _stateless_tools_unfinished(audit_data: AuditData) -> bool:
    """Whether the stateless ``tools/list`` probe received an empty page that is not the whole catalog.

    Without ``resultType: "complete"`` (SEP-2322), or with a next cursor, an empty page proves nothing.
    """
    probe = (audit_data.probes or {}).get(PROBE_STATELESS_LIST)
    if probe is None or probe.outcome is not ProbeOutcome.SUPPORTED or not isinstance(probe.payload, dict):
        return False
    payload = probe.payload
    unfinished = payload.get("resultType") != "complete" or payload.get("nextCursor") is not None
    return payload.get("tools") == [] and unfinished


def _exposed_counts(audit_data: AuditData) -> dict[str, int | None]:
    """Count what each primitive listing collected; None when the listing has no result.

    Tools the stateless lifecycle served count when the session catalog has none: either lifecycle exposes them.
    """
    counts: dict[str, int | None] = {
        listing: None if getattr(audit_data, listing) is None else len(getattr(audit_data, listing))
        for listing in _PRIMITIVE_LISTINGS
    }
    if not counts["tools"]:
        counts["tools"] = _stateless_tools(audit_data) or counts["tools"]
    skills = audit_data.skills
    counts["skills"] = None if skills is None or skills.entries is None else len(skills.entries)
    return counts


def _unproven_listings(audit_data: AuditData) -> list[str]:
    """Return the listings that cannot show the server serves nothing: declared or attempted but not collected whole.

    A declaration counts from either lifecycle: the session's capabilities or ``server/discover``.
    """
    discovered = discover_capabilities(audit_data)
    unproven = []
    for listing, capability in _PRIMITIVE_LISTINGS.items():
        declared = getattr(audit_data.capabilities, capability, None) is not None or capability in discovered
        collected = getattr(audit_data, listing)
        if collected is None and listing == "tools" and listing not in audit_data.listings_attempted:
            # The session never listed tools: a whole stateless page is the evidence.
            whole_empty = _stateless_tools(audit_data) == 0 and not _stateless_tools_unfinished(audit_data)
            collected = [] if whole_empty else None
        missing = collected is None and (declared or listing in audit_data.listings_attempted)
        unfinished = listing in audit_data.incomplete_listings or (
            listing == "tools" and _stateless_tools_unfinished(audit_data)
        )
        if missing or (not collected and unfinished):
            unproven.append(listing)
    extensions = discovered.get("extensions")
    discover_skills = isinstance(extensions, dict) and SKILLS_EXTENSION in extensions
    skills = audit_data.skills
    listed = skills is not None and skills.entries is not None and (skills.entries or not skills.list_incomplete)
    if (declares_skills(audit_data) or discover_skills) and not listed:
        unproven.append("skills")
    return unproven


@register_rule
class ServerExposesPrimitiveRule(BaseRule):
    """Medium check: the server exposes at least one tool, resource, resource template, prompt or skill.

    Every server primitive is optional, so no single one is required; a server that serves none of them gives a
    client nothing to use.
    """

    group_name = "server_info"
    group_order = 2
    rule_id = "server_exposes_primitive"
    basis = (
        "MCP 2025-11-25 Server Features §Overview (tools, resources and prompts are each optional); "
        "SEP-2640 Skills extension (skills/list)"
    )
    rule_order = 7

    @property
    def rule_name(self) -> str:
        return "Server Info - Exposes at least one tool, resource, prompt or skill"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip unless the audit either collected a primitive or saw every declared listing come back whole and empty.

        A failed or incomplete listing is never read as empty, and a partial audit has no session to list with.
        """
        if audit_data.partial or audit_data.capabilities is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        if any(_exposed_counts(audit_data).values()):
            return None
        return SKIP_REASON_INSUFFICIENT_DATA if _unproven_listings(audit_data) else None

    def check(self, audit_data: AuditData) -> RuleResult:
        """Pass when any primitive listing collected at least one item."""
        counts = _exposed_counts(audit_data)
        passed = any(counts.values())
        checked = [name for name, count in counts.items() if count is not None]
        if passed:
            exposed = ", ".join(f"{name}: {count}" for name, count in counts.items() if count)
            message = f"✅ Server exposes at least one primitive ({exposed})"
        elif checked:
            message = f"❌ Server exposes nothing: every listing it serves came back empty ({', '.join(checked)})"
        else:
            message = "❌ Server exposes nothing: it declares no tools, resources, prompts or skills"
        details: dict[str, Any] = {"exposed": counts, "checked": checked}
        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details=details,
            suggested_fix=(
                "Expose at least one tool, resource, prompt or skill, declare its capability in the initialize "
                "result, and check that its list method returns it."
            ),
            issues=[field_issue("catalog", None, "", "empty_catalog", "at least one tool, resource, prompt or skill")],
        )
