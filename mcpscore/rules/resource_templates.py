from abc import abstractmethod
from collections import Counter
import re

from mcp_types import ResourceTemplate

from .base import SKIP_REASON_INSUFFICIENT_DATA, AuditData, BaseRule, RuleResult, RuleSeverity, requires_fields
from .catalog_validation import is_iso_8601, is_valid_media_type
from .icon_validation import find_invalid_icons
from .registry import register_rule

_PCT_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_VARNAME_RE = re.compile(r"(?:[A-Za-z0-9_]|%[0-9A-Fa-f]{2})+(?:\.(?:[A-Za-z0-9_]|%[0-9A-Fa-f]{2})+)*")
_OPERATORS = "+#./;?&=,!@|"


def is_valid_uri_template(value: str) -> bool:
    """Return whether a string satisfies the RFC 6570 Level 4 grammar."""
    if not value:
        # The empty string is grammar-vacuous but identifies nothing — reject
        # it like resources_uris_valid rejects an empty URI.
        return False
    index = 0
    while index < len(value):
        character = value[index]
        if character == "{":
            closing = value.find("}", index + 1)
            if closing < 0 or not _is_valid_expression(value[index + 1 : closing]):
                return False
            index = closing + 1
            continue
        if character == "}" or not _is_valid_literal(value, index):
            return False
        index += 3 if character == "%" else 1
    return True


def _is_valid_expression(expression: str) -> bool:
    if not expression:
        return False
    variables = expression[1:] if expression[0] in _OPERATORS else expression
    if not variables:
        return False
    return all(_is_valid_varspec(varspec) for varspec in variables.split(","))


def _is_valid_varspec(varspec: str) -> bool:
    if varspec.endswith("*"):
        varname = varspec[:-1]
    elif ":" in varspec:
        varname, separator, prefix = varspec.partition(":")
        if not separator or re.fullmatch(r"[1-9][0-9]{0,3}", prefix) is None:
            return False
    else:
        varname = varspec
    return _VARNAME_RE.fullmatch(varname) is not None


def _is_valid_literal(value: str, index: int) -> bool:
    codepoint = ord(value[index])
    if value[index] == "%":
        return _PCT_ENCODED_RE.match(value, index) is not None
    return (
        codepoint == 0x21
        or 0x23 <= codepoint <= 0x24
        or codepoint == 0x26
        or 0x28 <= codepoint <= 0x3B
        or codepoint == 0x3D
        or 0x3F <= codepoint <= 0x5B
        or codepoint in (0x5D, 0x5F)
        or 0x61 <= codepoint <= 0x7A
        or codepoint == 0x7E
        or 0xA0 <= codepoint <= 0xD7FF
        or 0xE000 <= codepoint <= 0xF8FF
        or 0xF900 <= codepoint <= 0xFDCF
        or 0xFDF0 <= codepoint <= 0xFFEF
        or any(start <= codepoint <= end for start, end in _SUPPLEMENTARY_RANGES)
    )


_SUPPLEMENTARY_RANGES = tuple(
    [(plane << 16, (plane << 16) + 0xFFFD) for plane in range(1, 14)]
    + [(0xE1000, 0xEFFFD), (0xF0000, 0xFFFFD), (0x100000, 0x10FFFD)]
)


class ResourceTemplatesBaseRule(BaseRule):
    """Base class for rules that validate the collected template catalog.

    Per-item rules judge partial evidence too — a bad template on page one is
    bad regardless of what an unfetched page holds. Only completeness-dependent
    verdicts (uniqueness) skip on an incomplete listing, on the subclass.
    """

    group_name = "resource_templates"
    group_order = 7

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when an attempted listing produced no evidence to judge."""
        listing = "resource_templates"
        unavailable = audit_data.resource_templates is None and listing in audit_data.listings_attempted
        empty_partial = not audit_data.resource_templates and listing in audit_data.incomplete_listings
        return SKIP_REASON_INSUFFICIENT_DATA if unavailable or empty_partial else None

    @requires_fields("resource_templates")
    def check(self, templates: list[ResourceTemplate] | None) -> RuleResult:  # type: ignore[override]
        """Execute the rule, treating an absent optional catalog as not applicable."""
        if not templates:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=True,
                message="✅ No resource templates to evaluate",
                details={"resource_templates_count": 0},
            )
        return self._check_templates(templates)

    @abstractmethod
    def _check_templates(self, templates: list[ResourceTemplate]) -> RuleResult:
        """Validate the collected resource templates."""
        raise NotImplementedError


@register_rule
class ResourceTemplatesUriTemplatesValidRule(ResourceTemplatesBaseRule):
    """High check: Verify that each uriTemplate follows RFC 6570 syntax."""

    rule_id = "resource_templates_uri_templates_valid"
    basis = "MCP 2026-07-28 Resources §Resource Templates (uriTemplate); RFC 6570 §2"
    rule_order = 20

    @property
    def rule_name(self) -> str:
        return "Resource Templates - URI templates must be valid"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_templates(self, templates: list[ResourceTemplate]) -> RuleResult:
        invalid = [
            {"name": template.name, "uri_template": template.uri_template}
            for template in templates
            if not is_valid_uri_template(template.uri_template)
        ]
        passed = not invalid
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=(
                "✅ All resource URI templates are valid"
                if passed
                else f"❌ Number of invalid resource URI templates: {len(invalid)}"
            ),
            details={"invalid_uri_templates": invalid},
        )


@register_rule
class ResourceTemplatesUniqueRule(ResourceTemplatesBaseRule):
    """High check: Verify that uriTemplate identifiers are unique."""

    rule_id = "resource_templates_unique"
    basis = "MCP 2026-07-28 Resources §Resource Templates (uriTemplate identifies the template)"
    rule_order = 21

    @property
    def rule_name(self) -> str:
        return "Resource Templates - URI templates must be unique"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when pagination did not produce the complete catalog.

        Uniqueness judged on a partial listing can produce a false pass — the
        duplicate may live on a page that was never fetched.
        """
        return (
            SKIP_REASON_INSUFFICIENT_DATA
            if super().skip_reason(audit_data) is not None or "resource_templates" in audit_data.incomplete_listings
            else None
        )

    def _check_templates(self, templates: list[ResourceTemplate]) -> RuleResult:
        counts = Counter(template.uri_template for template in templates)
        duplicates = sorted(value for value, count in counts.items() if count > 1)
        passed = not duplicates
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=(
                "✅ All resource URI templates are unique"
                if passed
                else f"❌ Number of duplicate resource URI templates: {len(duplicates)}"
            ),
            details={"duplicate_uri_templates": duplicates},
        )


@register_rule
class ResourceTemplatesNamesPresentRule(ResourceTemplatesBaseRule):
    """Medium check: Verify that each template has a non-blank name."""

    rule_id = "resource_templates_names_present"
    basis = "MCP 2026-07-28 Resources §Resource Templates (name)"
    rule_order = 22

    @property
    def rule_name(self) -> str:
        return "Resource Templates - All templates must have a name"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_templates(self, templates: list[ResourceTemplate]) -> RuleResult:
        unnamed = [template.uri_template for template in templates if not template.name.strip()]
        passed = not unnamed
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=(
                "✅ All resource templates have a name"
                if passed
                else f"❌ Number of resource templates without a name: {len(unnamed)}"
            ),
            details={"templates_without_name": unnamed},
        )


@register_rule
class ResourceTemplatesIconsValidRule(ResourceTemplatesBaseRule):
    """Low check: validate every declared resource-template icon."""

    rule_id = "resource_templates_icons_valid"
    basis = "MCP 2026-07-28 Schema Reference §Common Types (Icon); Resources §Resource Templates (icons)"
    min_spec_version = "2025-11-25"
    rule_order = 23

    @property
    def rule_name(self) -> str:
        return "Resource Templates - Declared icons must be valid"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def _check_templates(self, templates: list[ResourceTemplate]) -> RuleResult:
        invalid_icons = find_invalid_icons([(template.uri_template, template) for template in templates])
        passed = not invalid_icons
        message = (
            "✅ All declared resource-template icons are valid"
            if passed
            else f"❌ Number of invalid resource-template icons: {len(invalid_icons)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"invalid_icons": invalid_icons},
        )


@register_rule
class ResourceTemplatesMimeTypesValidRule(ResourceTemplatesBaseRule):
    """Medium check: validate every declared resource-template MIME type."""

    rule_id = "resource_templates_mime_types_valid"
    basis = "MCP 2026-07-28 Resources §Resource Templates (mimeType)"
    rule_order = 24

    @property
    def rule_name(self) -> str:
        return "Resource Templates - Declared MIME types must be valid"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_templates(self, templates: list[ResourceTemplate]) -> RuleResult:
        invalid = [
            {"name": template.name, "mime_type": template.mime_type}
            for template in templates
            if template.mime_type is not None and not is_valid_media_type(template.mime_type)
        ]
        passed = not invalid
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=(
                "✅ All declared resource-template MIME types are valid"
                if passed
                else f"❌ Number of resource templates with invalid MIME types: {len(invalid)}"
            ),
            details={"templates_with_invalid_mime_type": invalid},
        )


@register_rule
class ResourceTemplatesAnnotationsValidRule(ResourceTemplatesBaseRule):
    """Medium check: validate every declared resource-template annotation."""

    rule_id = "resource_templates_annotations_valid"
    basis = "MCP 2026-07-28 Resources §Resource Templates (annotations); Schema Reference §Annotations"
    rule_order = 25

    @property
    def rule_name(self) -> str:
        return "Resource Templates - Declared annotations must be valid"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_templates(self, templates: list[ResourceTemplate]) -> RuleResult:
        invalid = [
            template.uri_template
            for template in templates
            if template.annotations is not None
            and template.annotations.last_modified is not None
            and not is_iso_8601(template.annotations.last_modified)
        ]
        passed = not invalid
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=(
                "✅ All declared resource-template annotations are valid"
                if passed
                else f"❌ Number of resource templates with invalid annotations: {len(invalid)}"
            ),
            details={"templates_with_invalid_annotations": invalid},
        )


@register_rule
class ResourceTemplatesDescriptionPresentRule(ResourceTemplatesBaseRule):
    """Medium check: require a useful description for every resource template."""

    rule_id = "resource_templates_description_present"
    basis = "MCP 2026-07-28 Resources §Resource Templates (description improves the LLM's understanding)"
    rule_order = 26

    @property
    def rule_name(self) -> str:
        return "Resource Templates - All templates should have a description"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_templates(self, templates: list[ResourceTemplate]) -> RuleResult:
        missing = [
            template.uri_template
            for template in templates
            if not (template.description and template.description.strip())
        ]
        passed = not missing
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=(
                "✅ All resource templates have a description"
                if passed
                else f"❌ Number of resource templates without a description: {len(missing)}"
            ),
            details={"templates_without_description": missing},
        )


@register_rule
class ResourceTemplatesTitlesPresentRule(ResourceTemplatesBaseRule):
    """Low check: encourage human-readable display titles for resource templates."""

    rule_id = "resource_templates_titles_present"
    basis = "MCP 2026-07-28 Resources §Resource Templates (title: optional human-readable name for display)"
    # `title` was introduced in the 2025-06-18 revision — earlier servers
    # cannot declare one and must not be penalized for its absence. (The
    # basis cites the revision the rule was verified against, per repo
    # policy — intentionally not the introduction revision.)
    min_spec_version = "2025-06-18"
    rule_order = 27

    @property
    def rule_name(self) -> str:
        return "Resource Templates - All templates should have a display title"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def _check_templates(self, templates: list[ResourceTemplate]) -> RuleResult:
        missing = [template.uri_template for template in templates if not (template.title and template.title.strip())]
        passed = not missing
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=(
                "✅ All resource templates have a display title"
                if passed
                else f"❌ Number of resource templates without a display title: {len(missing)}"
            ),
            details={"templates_without_title": missing},
        )
