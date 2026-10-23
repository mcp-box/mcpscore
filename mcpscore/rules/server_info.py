from abc import abstractmethod
from dataclasses import dataclass
from typing import Any

from mcp_types import Implementation

from mcpscore.diagnostics import quoted_preview
from mcpscore.probes import (
    ERROR_METHOD_NOT_FOUND,
    PROBE_PROMPTS_CATALOG_CONNECTION_INDEPENDENT,
    PROBE_RESOURCES_CATALOG_CONNECTION_INDEPENDENT,
    PROBE_STATELESS_LIST,
    PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT,
    ProbeOutcome,
    has_modern_support,
)
from mcpscore.skills import declared_settings

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
from .skills import discover_capabilities, discover_declares_skills


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

_IDENTITY_FIELDS = {"tools": "name", "resources": "uri", "resource_templates": "uri_template", "prompts": "name"}
"""The field that identifies an item of each catalog."""

_CONNECTION_PROBES = {
    "tools": PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT,
    "resources": PROBE_RESOURCES_CATALOG_CONNECTION_INDEPENDENT,
    "prompts": PROBE_PROMPTS_CATALOG_CONNECTION_INDEPENDENT,
}
"""Probes that list a catalog on two fresh connections; their item counts show what the server serves."""


@dataclass
class _Catalog:
    """What each lifecycle showed about one primitive catalog."""

    items: int | None = None
    """The most items any source observed; None when no source returned a listing."""
    legacy_needed: bool = False
    """The legacy session declared the catalog or tried to list it."""
    legacy_empty: bool = False
    """The session's listing was whole (complete, every page read) and empty."""
    modern_needed: bool = False
    """The stateless lifecycle declared the catalog."""
    modern_empty: bool = False
    """A whole stateless listing came back empty."""

    @property
    def declared(self) -> bool:
        return self.legacy_needed or self.modern_needed

    @property
    def proven_empty(self) -> bool:
        """Every lifecycle that declared the catalog listed it whole and empty."""
        legacy = self.legacy_empty or not self.legacy_needed
        return self.declared and legacy and (self.modern_empty or not self.modern_needed)

    def observe(self, count: int) -> None:
        self.items = max(self.items or 0, count)


def _stateless_tools_page(audit_data: AuditData) -> dict[str, Any] | None:
    """Return the stateless ``tools/list`` result the probe received, or None."""
    probe = (audit_data.probes or {}).get(PROBE_STATELESS_LIST)
    payload = probe.payload if probe is not None else None
    return payload if isinstance(payload, dict) and isinstance(payload.get("tools"), list) else None


def _identified(entries: list[Any], key: str) -> int | None:
    """Count the entries that carry an identity (a non-empty string *key*), as the catalog probes do.

    Returns None for a non-empty list with no identified entry: it shows no item, and does not prove the
    catalog empty. Whether an identified entry is otherwise valid is for the validity rules to judge.
    """
    count = sum(1 for entry in entries if isinstance(entry, dict) and isinstance(entry.get(key), str) and entry[key])
    return count if count or not entries else None


def _catalogs(audit_data: AuditData) -> dict[str, _Catalog]:
    """Reconcile the session listings, the stateless lifecycle and the catalog probes into one view per catalog.

    A catalog is empty only when each lifecycle that declared it listed it whole and empty. On the legacy
    session that is a complete listing; on the stateless lifecycle, a ``tools/list`` page with
    ``resultType: "complete"`` (SEP-2322) and no next cursor, or a catalog probe that read every page on two
    connections, each page with ``resultType: "complete"``, and found nothing. No probe lists resource
    templates on the stateless lifecycle, so templates that ``server/discover`` declares stay unproven.
    """
    discovered = discover_capabilities(audit_data)
    probes = audit_data.probes or {}
    has_session = audit_data.session_protocol_version is not None
    page = _stateless_tools_page(audit_data)
    stateless_probe = probes.get(PROBE_STATELESS_LIST)
    error_code = stateless_probe.details.get("error_code") if stateless_probe is not None else None
    # An explicit Method not found for tools/list says the server serves no tools catalog at all.
    tools_refused = error_code == ERROR_METHOD_NOT_FOUND
    # Any other answer from a modern server, a malformed result or an error, leaves its tools catalog to settle.
    answered = stateless_probe is not None and (isinstance(stateless_probe.payload, dict) or error_code is not None)
    tools_answered = answered and not tools_refused and has_modern_support(probes)
    catalogs: dict[str, _Catalog] = {}
    for listing, capability in _PRIMITIVE_LISTINGS.items():
        attempted = listing in audit_data.listings_attempted and not (listing == "tools" and tools_refused)
        session_declares = getattr(audit_data.capabilities, capability, None) is not None
        modern_declares = capability in discovered
        catalog = catalogs[listing] = _Catalog(
            legacy_needed=has_session and (session_declares or attempted),
            modern_needed=modern_declares or (not has_session and (session_declares or attempted)),
        )
        collected = getattr(audit_data, listing)
        if collected is not None:
            # Items without an identity show nothing, and do not prove the catalog empty either.
            named = sum(1 for item in collected if str(getattr(item, _IDENTITY_FIELDS[listing], None) or ""))
            if named or not collected:
                catalog.observe(named)
        # A catalog recovered from the stateless lifecycle replaced a session listing that failed or broke off.
        failed = (
            listing in audit_data.catalog_versions
            or listing in audit_data.incomplete_listings
            or listing in audit_data.listing_errors
        )
        catalog.legacy_empty = has_session and collected == [] and not failed
        probe = probes.get(_CONNECTION_PROBES.get(listing, ""))
        if probe is not None and probe.outcome in (ProbeOutcome.SUPPORTED, ProbeOutcome.UNSUPPORTED):
            counts = [probe.details.get(key) for key in ("first_count", "second_count")]
            counts = [count for count in counts if isinstance(count, int)]
            catalog.observe(max(counts, default=0))
            # SUPPORTED: both connections read every page and found the same catalog.
            whole = probe.outcome is ProbeOutcome.SUPPORTED and probe.details.get("results_complete") is True
            catalog.modern_empty = whole and counts == [0, 0]
        if listing == "tools":
            catalog.modern_needed = catalog.modern_needed or tools_answered
        if listing == "tools" and page is not None:
            named = _identified(page["tools"], "name")
            if named is not None:
                catalog.observe(named)
            whole = page.get("resultType") == "complete" and page.get("nextCursor") is None
            catalog.modern_empty = catalog.modern_empty or (whole and not page["tools"])
    skills = audit_data.skills
    session_skills = declared_settings(audit_data.capabilities) is not None
    catalog = catalogs["skills"] = _Catalog(
        legacy_needed=has_session and session_skills,
        modern_needed=discover_declares_skills(audit_data) or (not has_session and session_skills),
    )
    if skills is not None:
        listed_whole = (
            skills.entries == [] and not skills.list_incomplete and not skills.list_malformed and not skills.list_error
        )
        listed = None if skills.entries is None else _identified(skills.entries, "uri")
        if listed is not None:
            catalog.observe(listed)
        if skills.stateless:
            catalog.modern_empty = listed_whole
        else:
            catalog.legacy_empty = listed_whole
            # The first stateless page the readiness check reads covers the other lifecycle.
            if skills.stateless_count is not None:
                catalog.observe(skills.stateless_count)
            catalog.modern_empty = skills.stateless_count == 0 and skills.stateless_whole
    return catalogs


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
        """Skip unless some source observed a primitive, or every declared catalog was listed whole and empty.

        A failed or incomplete listing is never read as empty, and a partial audit has no session to list with.
        """
        if audit_data.partial or audit_data.capabilities is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        catalogs = _catalogs(audit_data).values()
        if any(catalog.items for catalog in catalogs):
            return None
        settled = all(catalog.proven_empty for catalog in catalogs if catalog.declared)
        return None if settled else SKIP_REASON_INSUFFICIENT_DATA

    def check(self, audit_data: AuditData) -> RuleResult:
        """Pass when any source observed at least one tool, resource, resource template, prompt or skill."""
        catalogs = _catalogs(audit_data)
        counts = {name: catalog.items for name, catalog in catalogs.items()}
        passed = any(counts.values())
        checked = [name for name, catalog in catalogs.items() if catalog.declared]
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
