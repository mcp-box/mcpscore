from abc import abstractmethod
from collections import Counter
from datetime import datetime
import re
from urllib.parse import urlsplit

from mcp_types import Resource

from .base import SKIP_REASON_INSUFFICIENT_DATA, AuditData, BaseRule, RuleResult, RuleSeverity, requires_fields
from .registry import register_rule

_URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")
_URI_CHARACTER_RE = re.compile(r"^[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$")
_INVALID_PERCENT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_MEDIA_TYPE_ATOM_PATTERN = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_MEDIA_TYPE_QUOTED_VALUE = r'"(?:[\t !#-\[\]-~]|\\[\t -~])*"'
_MEDIA_TYPE_RE = re.compile(
    rf"^{_MEDIA_TYPE_ATOM_PATTERN}/{_MEDIA_TYPE_ATOM_PATTERN}"
    rf"(?:[ \t]*;[ \t]*{_MEDIA_TYPE_ATOM_PATTERN}="
    rf"(?:{_MEDIA_TYPE_ATOM_PATTERN}|{_MEDIA_TYPE_QUOTED_VALUE}))*$"
)


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
class ResourcesUrisValidRule(ResourcesBaseRule):
    """High check: Verify that every resource has a valid absolute URI."""

    rule_id = "resources_uris_valid"
    basis = "MCP 2026-07-28 Resources §Resource (uri is the resource's unique identifier)"
    rule_order = 1

    @property
    def rule_name(self) -> str:
        return "Resources - All resource URIs must be valid"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_resources(self, resources: list[Resource]) -> RuleResult:
        """Verify that every resource URI is absolute and syntactically valid."""
        invalid_resource_uris = [
            {"name": resource.name, "uri": resource.uri}
            for resource in resources
            if not _is_valid_absolute_uri(resource.uri)
        ]
        passed = not invalid_resource_uris
        message = (
            "✅ All resource URIs are valid"
            if passed
            else f"❌ Number of resources with invalid URIs: {len(invalid_resource_uris)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"invalid_resource_uris": invalid_resource_uris},
        )


def _is_valid_absolute_uri(value: str) -> bool:
    """Return whether a value is an absolute URI with a valid scheme."""
    # urlsplit accepts almost any string, so the character regex does the real
    # RFC 3986 charset enforcement (spaces, control chars, raw non-ASCII).
    if not value or _URI_CHARACTER_RE.fullmatch(value) is None or _INVALID_PERCENT_ESCAPE_RE.search(value) is not None:
        return False
    try:
        parsed = urlsplit(value)
        _ = parsed.port  # urlsplit is lazy: only this access validates the port
    except ValueError:
        return False
    return bool(parsed.scheme and _URI_SCHEME_RE.fullmatch(parsed.scheme))


@register_rule
class ResourcesNamesPresentRule(ResourcesBaseRule):
    """Medium check: Verify that every resource has a non-blank name."""

    rule_id = "resources_names_present"
    basis = "MCP 2026-07-28 Resources §Resource (name)"
    rule_order = 2

    @property
    def rule_name(self) -> str:
        return "Resources - All resources must have a name"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_resources(self, resources: list[Resource]) -> RuleResult:
        """Verify that every resource name contains visible text."""
        resources_without_name = [resource.uri for resource in resources if not resource.name.strip()]
        passed = not resources_without_name
        message = (
            "✅ All resources have a name"
            if passed
            else f"❌ Number of resources without a name: {len(resources_without_name)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"resources_without_name": resources_without_name},
        )


@register_rule
class ResourcesSizesValidRule(ResourcesBaseRule):
    """Medium check: Verify that supplied resource sizes are non-negative."""

    rule_id = "resources_sizes_valid"
    basis = "MCP 2026-07-28 Resources §Resource (size is the optional size in bytes)"
    rule_order = 3

    @property
    def rule_name(self) -> str:
        return "Resources - Declared sizes must be valid"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_resources(self, resources: list[Resource]) -> RuleResult:
        """Verify that every supplied byte size is non-negative."""
        resources_with_invalid_size = [
            {"name": resource.name, "size": resource.size}
            for resource in resources
            if resource.size is not None and resource.size < 0
        ]
        passed = not resources_with_invalid_size
        message = (
            "✅ All declared resource sizes are valid"
            if passed
            else f"❌ Number of resources with invalid sizes: {len(resources_with_invalid_size)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"resources_with_invalid_size": resources_with_invalid_size},
        )


@register_rule
class ResourcesMimeTypesValidRule(ResourcesBaseRule):
    """Medium check: Verify that supplied resource MIME types are valid."""

    rule_id = "resources_mime_types_valid"
    basis = "MCP 2026-07-28 Resources §Resource (mimeType)"
    rule_order = 4

    @property
    def rule_name(self) -> str:
        return "Resources - Declared MIME types must be valid"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_resources(self, resources: list[Resource]) -> RuleResult:
        """Verify that every supplied MIME type has a type and subtype."""
        resources_with_invalid_mime_type = [
            {"name": resource.name, "mime_type": resource.mime_type}
            for resource in resources
            if resource.mime_type is not None and _MEDIA_TYPE_RE.fullmatch(resource.mime_type) is None
        ]
        passed = not resources_with_invalid_mime_type
        message = (
            "✅ All declared resource MIME types are valid"
            if passed
            else f"❌ Number of resources with invalid MIME types: {len(resources_with_invalid_mime_type)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"resources_with_invalid_mime_type": resources_with_invalid_mime_type},
        )


@register_rule
class ResourcesAnnotationsValidRule(ResourcesBaseRule):
    """Medium check: Verify that resource annotations are valid."""

    rule_id = "resources_annotations_valid"
    basis = "MCP 2026-07-28 Resources §Annotations (audience, priority, lastModified)"
    rule_order = 5

    @property
    def rule_name(self) -> str:
        return "Resources - Declared annotations must be valid"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_resources(self, resources: list[Resource]) -> RuleResult:
        """Verify annotation values not already constrained by the SDK model."""
        resources_with_invalid_annotations = [
            resource.name
            for resource in resources
            if resource.annotations is not None
            and resource.annotations.last_modified is not None
            and not _is_iso_8601(resource.annotations.last_modified)
        ]
        passed = not resources_with_invalid_annotations
        message = (
            "✅ All declared resource annotations are valid"
            if passed
            else f"❌ Number of resources with invalid annotations: {len(resources_with_invalid_annotations)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"resources_with_invalid_annotations": resources_with_invalid_annotations},
        )


def _is_iso_8601(value: str) -> bool:
    """Return whether a value is a non-blank ISO 8601 date or timestamp."""
    if not value or value != value.strip():
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


@register_rule
class ResourcesDescriptionPresentRule(ResourcesBaseRule):
    """Medium check: Verify that all declared resources have a description."""

    rule_id = "resources_description_present"
    basis = "MCP 2025-11-25 Resources §Resource (description)"
    rule_order = 6

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


@register_rule
class ResourcesUrisUniqueRule(ResourcesBaseRule):
    """High check: Verify that each listed resource has a unique URI."""

    rule_id = "resources_uris_unique"
    basis = "MCP 2026-07-28 Resources §Resource (uri: Unique identifier for the resource)"
    rule_order = 7

    @property
    def rule_name(self) -> str:
        return "Resources - Resource URIs must be unique"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when pagination did not produce the complete resource list."""
        return SKIP_REASON_INSUFFICIENT_DATA if "resources" in audit_data.incomplete_listings else None

    def _check_resources(self, resources: list[Resource]) -> RuleResult:
        """Find resource URIs declared more than once."""
        counts = Counter(resource.uri for resource in resources)
        duplicate_uris = sorted(uri for uri, count in counts.items() if count > 1)
        passed = not duplicate_uris
        message = (
            "✅ All resource URIs are unique"
            if passed
            else f"❌ Number of duplicate resource URIs: {len(duplicate_uris)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"duplicate_uris": duplicate_uris},
        )
