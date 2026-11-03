"""MCP Apps extension rules (``io.modelcontextprotocol/ui``, ext-apps specification 2026-01-26).

A server delivers an MCP App by pointing a tool at a ``ui://`` resource holding an HTML document. These rules
judge only servers that expose such metadata: a tool with ``_meta.ui`` (or the deprecated flat pointer key) or a
listed ``ui://`` resource. Every other server skips them as not-applicable. The specification defines no server
capability declaration, so none is required here.
"""

from typing import Any, ClassVar

from mcp_types import Tool

from ..apps import (
    FLAT_POINTER_KEY,
    UI_MIME_TYPE,
    UI_SCHEME,
    VISIBILITY_VALUES,
    AppsEvidence,
    UiRead,
    flat_pointer,
    nested_pointer,
    pointer_targets,
    tool_meta,
    ui_meta,
    ui_tools,
    uses_apps,
)
from .base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_NOT_APPLICABLE,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
)
from .catalog_diagnostics import catalog_result, field_issue
from .registry import register_rule

APPS_GROUP = "apps"
SPEC = "MCP Apps extension (ext-apps specification 2026-01-26)"


def _issue(index: int | None, path: str, reason: str, expected: str, kind: str = "tool") -> dict[str, Any]:
    return field_issue(kind, index, path, reason, expected)


class AppsBaseRule(BaseRule):
    """Base for rules that judge a server exposing MCP Apps metadata."""

    group_name = APPS_GROUP
    group_order = 11
    needs_pointers: ClassVar[bool] = True
    """The rule judges tools' UI pointers, so it skips a server whose tools carry none."""
    needs_reads: ClassVar[bool] = False
    """The rule judges ``resources/read`` answers for the pointer targets."""

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip unless the server exposes MCP Apps metadata and the evidence this rule needs was collected."""
        if audit_data.capabilities is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        if not uses_apps(audit_data.tools, audit_data.resources):
            return SKIP_REASON_NOT_APPLICABLE
        if self.needs_pointers and not ui_tools(audit_data.tools):
            return SKIP_REASON_NOT_APPLICABLE
        if self.needs_reads:
            if not pointer_targets(audit_data.tools):
                return SKIP_REASON_NOT_APPLICABLE
            if audit_data.apps is None or not self._judged_reads(audit_data.apps):
                return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def _judged_reads(self, evidence: AppsEvidence) -> list[UiRead]:
        """Return the reads this rule judges; it skips when there are none."""
        return list(evidence.reads.values())

    def _result(
        self,
        *,
        passed: bool,
        message: str,
        details: dict[str, Any],
        fix: str,
        issues: list[dict[str, Any]],
    ) -> RuleResult:
        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details=details,
            suggested_fix=fix,
            issues=issues,
        )


def _ui_tools(audit_data: AuditData) -> list[tuple[int, Tool]]:
    return ui_tools(audit_data.tools)


def _evidence(audit_data: AuditData) -> AppsEvidence:
    assert audit_data.apps is not None  # noqa: S101 — guaranteed by skip_reason
    return audit_data.apps


def _answered(evidence: AppsEvidence) -> list[UiRead]:
    return [read for read in evidence.reads.values() if read.answered]


def _successful(evidence: AppsEvidence) -> list[UiRead]:
    return [read for read in evidence.reads.values() if read.error is None and read.contents]


@register_rule
class AppsToolUiMetaWellFormedRule(AppsBaseRule):
    """Medium check: a tool's ``_meta.ui`` has the shape the extension defines."""

    rule_id = "apps_tool_ui_meta_well_formed"
    basis = f'{SPEC} §Resource Discovery (McpUiToolMeta: resourceUri string, visibility array of "model"/"app")'
    rule_order = 1

    @property
    def rule_name(self) -> str:
        return "Apps - Tool UI Metadata Well-Formed"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: ``_meta.ui`` is an object, ``resourceUri`` a string and ``visibility`` valid values."""
        issues: list[dict[str, Any]] = []
        for index, tool in _ui_tools(audit_data):
            ui = ui_meta(tool)
            if "ui" in tool_meta(tool) and not isinstance(ui, dict):
                issues.append(_issue(index, "/_meta/ui", "not_an_object", "an object"))
                continue
            if isinstance(ui, dict):
                if "resourceUri" in ui and not isinstance(ui["resourceUri"], str):
                    issues.append(_issue(index, "/_meta/ui/resourceUri", "not_a_string", "a ui:// URI string"))
                if "visibility" in ui:
                    visibility = ui["visibility"]
                    valid = isinstance(visibility, list) and all(
                        isinstance(value, str) and value in VISIBILITY_VALUES for value in visibility
                    )
                    if not valid:
                        issues.append(
                            _issue(index, "/_meta/ui/visibility", "invalid_visibility", 'an array of "model", "app"')
                        )
            if FLAT_POINTER_KEY in tool_meta(tool) and not isinstance(flat_pointer(tool), str):
                issues.append(_issue(index, "/_meta/ui~1resourceUri", "not_a_string", "a ui:// URI string"))
        passed = not issues
        return self._result(
            passed=passed,
            message="✅ Every tool's UI metadata is well-formed"
            if passed
            else f"❌ Number of malformed UI metadata fields: {len(issues)}",
            details={},
            fix=(
                "Give each UI tool `_meta.ui` as an object: `resourceUri` a `ui://` URI string and `visibility`, "
                'if set, an array of "model" and/or "app".'
            ),
            issues=issues,
        )


@register_rule
class AppsUiResourceUriSchemeRule(AppsBaseRule):
    """Medium check: every tool UI pointer names a ``ui://`` resource."""

    rule_id = "apps_ui_resource_uri_scheme"
    basis = f"{SPEC} §UI Resource Format, Content Requirements (URI MUST start with the ui:// scheme)"
    rule_order = 2

    @property
    def rule_name(self) -> str:
        return "Apps - UI Resources Use ui://"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when no tool carries a string UI pointer."""
        reason = super().skip_reason(audit_data)
        if reason is not None:
            return reason
        if not any(isinstance(uri, str) for uri in self._pointers(audit_data)):
            return SKIP_REASON_NOT_APPLICABLE
        return None

    @staticmethod
    def _pointers(audit_data: AuditData) -> list[Any]:
        return [value for _, tool in _ui_tools(audit_data) for value in (nested_pointer(tool), flat_pointer(tool))]

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: both pointer keys, where present, start with ``ui://``."""
        issues: list[dict[str, Any]] = []
        for index, tool in _ui_tools(audit_data):
            for path, value in (
                ("/_meta/ui/resourceUri", nested_pointer(tool)),
                ("/_meta/ui~1resourceUri", flat_pointer(tool)),
            ):
                if isinstance(value, str) and not value.startswith(UI_SCHEME):
                    issues.append(_issue(index, path, "not_ui_scheme", "a URI starting with ui://"))
        passed = not issues
        return self._result(
            passed=passed,
            message="✅ Every tool UI pointer names a ui:// resource"
            if passed
            else f"❌ Number of UI pointers outside the ui:// scheme: {len(issues)}",
            details={},
            fix="Serve the tool's UI as a resource whose URI starts with `ui://`; point `_meta.ui.resourceUri` at it.",
            issues=issues,
        )


@register_rule
class AppsUiResourceResolvesRule(AppsBaseRule):
    """Medium check: every ``ui://`` resource a tool points at can be read."""

    rule_id = "apps_ui_resource_resolves"
    basis = f"{SPEC} §Resource Discovery, Behavior (the resource MUST exist on the server; hosts use resources/read)"
    rule_order = 3
    needs_reads = True

    def _judged_reads(self, evidence: AppsEvidence) -> list[UiRead]:
        return _answered(evidence)

    @property
    def rule_name(self) -> str:
        return "Apps - UI Resources Resolve"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: ``resources/read`` of each pointer target returns content."""
        evidence = _evidence(audit_data)
        issues: list[dict[str, Any]] = []
        judged = 0
        for index, read in enumerate(evidence.reads.values()):
            if not read.answered:
                continue
            judged += 1
            if read.error is not None:
                issues.append(
                    {
                        **_issue(index, "", "read_failed", "resources/read returns the resource", "ui_resource"),
                        "outcome": read.error.get("outcome"),
                        **({"error_code": read.error["error_code"]} if "error_code" in read.error else {}),
                    }
                )
            elif not read.contents:
                issues.append(_issue(index, "/contents", "empty", "at least one content item", "ui_resource"))
            elif not read.returns_requested:
                issues.append(
                    _issue(index, "/contents", "other_resource", "a content item with the requested URI", "ui_resource")
                )
        passed = not issues
        return self._result(
            passed=passed,
            message=f"✅ Every UI resource the tools point at can be read ({judged} read)"
            if passed
            else f"❌ Number of UI resources that could not be read: {len(issues)}",
            details={"read": judged, "unanswered": len(evidence.reads) - judged, "unread": evidence.unread},
            fix="Serve each `ui://` resource a tool points at from `resources/read`, with its HTML as content.",
            issues=issues,
        )


@register_rule
class AppsUiResourceMimeTypeRule(AppsBaseRule):
    """Medium check: UI resource content carries the MCP Apps MIME type."""

    rule_id = "apps_ui_resource_mime_type"
    basis = f"{SPEC} §UI Resource Format, Content Requirements (mimeType MUST be {UI_MIME_TYPE})"
    rule_order = 4
    needs_reads = True

    def _judged_reads(self, evidence: AppsEvidence) -> list[UiRead]:
        return _successful(evidence)

    @property
    def rule_name(self) -> str:
        return "Apps - UI Resource MIME Type"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: every content item of every UI resource read has ``mimeType`` exactly as specified."""
        issues: list[dict[str, Any]] = []
        for index, read in enumerate(_evidence(audit_data).reads.values()):
            if read.error is not None:
                continue
            for item, content in enumerate(read.contents):
                if content.mime_type != UI_MIME_TYPE:
                    issues.append(
                        _issue(index, f"/contents/{item}/mimeType", "wrong_mime_type", UI_MIME_TYPE, "ui_resource")
                    )
        passed = not issues
        return self._result(
            passed=passed,
            message=f"✅ Every UI resource is served as {UI_MIME_TYPE}"
            if passed
            else f"❌ Number of UI resource contents with another MIME type: {len(issues)}",
            details={},
            fix=f"Set `mimeType` to exactly `{UI_MIME_TYPE}` on the UI resource's content.",
            issues=issues,
        )


@register_rule
class AppsUiResourceHtmlDocumentRule(AppsBaseRule):
    """Medium check: UI resource content is an HTML document, as ``text`` or base64 ``blob``."""

    rule_id = "apps_ui_resource_html_document"
    basis = (
        f"{SPEC} §UI Resource Format, Content Requirements (content MUST be provided via text or blob and MUST be "
        "a valid HTML5 document)"
    )
    rule_order = 5
    needs_reads = True

    def _judged_reads(self, evidence: AppsEvidence) -> list[UiRead]:
        return _successful(evidence)

    @property
    def rule_name(self) -> str:
        return "Apps - UI Resources Are HTML Documents"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: content opens with an HTML doctype or ``html`` root; fragments and plain text fail."""
        issues: list[dict[str, Any]] = []
        for index, read in enumerate(_evidence(audit_data).reads.values()):
            if read.error is not None:
                continue
            for item, content in enumerate(read.contents):
                path = f"/contents/{item}"
                if not (content.has_text or content.has_blob):
                    issues.append(_issue(index, path, "no_text_or_blob", "text or a base64 blob", "ui_resource"))
                elif not content.blob_valid:
                    issues.append(_issue(index, f"{path}/blob", "invalid_base64", "base64-encoded HTML", "ui_resource"))
                elif not content.html_document:
                    issues.append(
                        _issue(index, path, "not_html_document", "an HTML document (<!DOCTYPE html>)", "ui_resource")
                    )
        passed = not issues
        return self._result(
            passed=passed,
            message="✅ Every UI resource is an HTML document"
            if passed
            else f"❌ Number of UI resource contents that are not HTML documents: {len(issues)}",
            details={
                "note": "Only the document's opening (doctype and root element) is checked, not full HTML5 validity."
            },
            fix="Serve a complete HTML document starting with `<!DOCTYPE html>`, as `text` or a base64 `blob`.",
            issues=issues,
        )


@register_rule
class AppsToolUiPointerNestedRule(AppsBaseRule):
    """Low check: UI tools use ``_meta.ui.resourceUri``, not only the deprecated flat key."""

    rule_id = "apps_tool_ui_pointer_nested"
    basis = (
        f'{SPEC} §Resource Discovery (the flat _meta["ui/resourceUri"] is deprecated; use _meta.ui.resourceUri, '
        "the deprecated form will be removed)"
    )
    rule_order = 6

    @property
    def rule_name(self) -> str:
        return "Apps - Current UI Pointer Key"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when no tool uses the flat key."""
        reason = super().skip_reason(audit_data)
        if reason is not None:
            return reason
        if not any(flat_pointer(tool) is not None for _, tool in _ui_tools(audit_data)):
            return SKIP_REASON_NOT_APPLICABLE
        return None

    def check(self, audit_data: AuditData) -> RuleResult:
        """Low check: a tool sending the flat key also sends the nested one; sending both is backward compatible."""
        issues = [
            _issue(index, "/_meta/ui/resourceUri", "flat_key_only", "_meta.ui.resourceUri alongside the flat key")
            for index, tool in _ui_tools(audit_data)
            if flat_pointer(tool) is not None and nested_pointer(tool) is None
        ]
        passed = not issues
        return self._result(
            passed=passed,
            message="✅ Every UI tool sends _meta.ui.resourceUri"
            if passed
            else f"❌ Number of tools pointing at their UI only through the deprecated key: {len(issues)}",
            details={},
            fix='Add `_meta.ui.resourceUri`; keep `_meta["ui/resourceUri"]` only for hosts that still read it.',
            issues=issues,
        )
