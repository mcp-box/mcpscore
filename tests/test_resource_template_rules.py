from mcp_types import Annotations, ResourceTemplate

from mcpscore.rules import (
    AuditData,
    ResourceTemplatesAnnotationsValidRule,
    ResourceTemplatesDescriptionPresentRule,
    ResourceTemplatesMimeTypesValidRule,
    ResourceTemplatesNamesPresentRule,
    ResourceTemplatesTitlesPresentRule,
    ResourceTemplatesUniqueRule,
    ResourceTemplatesUriTemplatesValidRule,
    RuleSeverity,
)
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE
from mcpscore.rules.resource_templates import is_valid_uri_template


def _template(
    name: str,
    uri_template: str,
    *,
    description: str | None = "Description",
    mime_type: str | None = None,
    annotations: Annotations | None = None,
    title: str | None = "Display title",
) -> ResourceTemplate:
    return ResourceTemplate(
        name=name,
        uriTemplate=uri_template,
        description=description,
        mime_type=mime_type,
        annotations=annotations,
        title=title,
    )


def test_uri_template_validator_accepts_rfc_6570_levels() -> None:
    valid = [
        "https://example.com/~{username}/",
        "https://example.com/{+path}/here",
        "https://example.com{/segments*}{?query,limit:3}",
        "file:///{folder.name}/{file%2Did}",
    ]
    assert all(is_valid_uri_template(value) for value in valid)


def test_uri_template_validator_rejects_invalid_grammar() -> None:
    invalid = [
        "",  # grammar-vacuous but identifies nothing
        "https://example.com/{",
        "https://example.com/}",
        "https://example.com/{}",
        "https://example.com/{+}",
        "https://example.com/{name:0}",
        "https://example.com/{name:10000}",
        "https://example.com/{name**}",
        "https://example.com/{bad-name}",
        "https://example.com/{one,,two}",
        "https://example.com/%GG",
        "https://example.com/a b",
    ]
    assert not any(is_valid_uri_template(value) for value in invalid)


def test_uri_template_rule_reports_invalid_templates() -> None:
    result = ResourceTemplatesUriTemplatesValidRule().check(
        AuditData(
            resource_templates=[
                _template("users", "https://example.com/users/{id}"),
                _template("broken", "https://example.com/{bad-name}"),
            ]
        )
    )
    assert not result.passed
    assert result.details == {
        "invalid_uri_templates": [{"name": "broken", "uri_template": "https://example.com/{bad-name}"}]
    }


def test_unique_rule_reports_duplicate_identifiers() -> None:
    duplicate = "https://example.com/users/{id}"
    result = ResourceTemplatesUniqueRule().check(
        AuditData(resource_templates=[_template("one", duplicate), _template("two", duplicate)])
    )
    assert not result.passed
    assert result.details == {"duplicate_uri_templates": [duplicate]}


def test_names_rule_rejects_blank_names() -> None:
    result = ResourceTemplatesNamesPresentRule().check(
        AuditData(resource_templates=[_template("users", "users/{id}"), _template("  ", "files/{id}")])
    )
    assert not result.passed
    assert result.details == {"templates_without_name": ["files/{id}"]}


def test_mime_types_rule_accepts_absent_and_valid_values() -> None:
    templates = [
        _template("unknown", "unknown/{id}"),
        _template("text", "text/{id}", mime_type="text/plain"),
        _template("parameter", "parameter/{id}", mime_type='text/plain; charset="utf-8"'),
    ]
    result = ResourceTemplatesMimeTypesValidRule().check(AuditData(resource_templates=templates))
    assert result.passed
    assert result.details == {"templates_with_invalid_mime_type": []}


def test_mime_types_rule_reports_invalid_values() -> None:
    templates = [
        _template("missing-subtype", "one/{id}", mime_type="text"),
        _template("blank", "two/{id}", mime_type=""),
    ]
    result = ResourceTemplatesMimeTypesValidRule().check(AuditData(resource_templates=templates))
    assert not result.passed
    assert result.details == {
        "templates_with_invalid_mime_type": [
            {"name": "missing-subtype", "mime_type": "text"},
            {"name": "blank", "mime_type": ""},
        ]
    }


def test_annotations_rule_accepts_absent_and_iso_8601_values() -> None:
    templates = [
        _template("none", "none/{id}"),
        _template("date", "date/{id}", annotations=Annotations(last_modified="2026-08-03")),
        _template("timestamp", "timestamp/{id}", annotations=Annotations(last_modified="2026-08-03T12:30:00Z")),
    ]
    result = ResourceTemplatesAnnotationsValidRule().check(AuditData(resource_templates=templates))
    assert result.passed
    assert result.details == {"templates_with_invalid_annotations": []}


def test_annotations_rule_reports_invalid_last_modified() -> None:
    template = _template("bad", "bad/{id}", annotations=Annotations(last_modified="3 August 2026"))
    result = ResourceTemplatesAnnotationsValidRule().check(AuditData(resource_templates=[template]))
    assert not result.passed
    assert result.details == {"templates_with_invalid_annotations": ["bad/{id}"]}


def test_description_rule_reports_missing_and_blank_descriptions() -> None:
    templates = [
        _template("good", "good/{id}", description="Fetch an item"),
        _template("missing", "missing/{id}", description=None),
        _template("blank", "blank/{id}", description="  "),
    ]
    result = ResourceTemplatesDescriptionPresentRule().check(AuditData(resource_templates=templates))
    assert not result.passed
    assert result.details == {"templates_without_description": ["missing/{id}", "blank/{id}"]}


def test_titles_rule_is_scoped_to_revisions_that_define_title() -> None:
    rule = ResourceTemplatesTitlesPresentRule()
    assert rule.rule_id == "resource_templates_titles_present"
    assert rule.severity == RuleSeverity.LOW
    assert rule.min_spec_version == "2025-06-18"
    assert not rule.applies_to("2025-03-26")
    assert rule.applies_to("2025-06-18")


def test_titles_rule_accepts_non_blank_titles() -> None:
    templates = [
        _template("users", "users/{id}", title="User profile"),
        _template("files", "files/{path}", title="Project file"),
    ]
    result = ResourceTemplatesTitlesPresentRule().check(AuditData(resource_templates=templates))
    assert result.passed
    assert result.details == {"templates_without_title": []}


def test_titles_rule_reports_missing_and_blank_titles() -> None:
    templates = [
        _template("missing", "missing/{id}", title=None),
        _template("blank", "blank/{id}", title="  "),
    ]
    result = ResourceTemplatesTitlesPresentRule().check(AuditData(resource_templates=templates))
    assert not result.passed
    assert result.details == {"templates_without_title": ["missing/{id}", "blank/{id}"]}


def test_template_rules_skip_when_capability_has_no_templates() -> None:
    for rule in (
        ResourceTemplatesUriTemplatesValidRule(),
        ResourceTemplatesUniqueRule(),
        ResourceTemplatesNamesPresentRule(),
        ResourceTemplatesMimeTypesValidRule(),
        ResourceTemplatesAnnotationsValidRule(),
        ResourceTemplatesDescriptionPresentRule(),
        ResourceTemplatesTitlesPresentRule(),
    ):
        assert rule.skip_reason(AuditData(resource_templates=[])) == SKIP_REASON_NOT_APPLICABLE
        assert rule.skip_reason(AuditData(resource_templates=None)) == SKIP_REASON_NOT_APPLICABLE


def test_template_rules_treat_unavailable_or_empty_partial_catalog_as_insufficient() -> None:
    rule = ResourceTemplatesUriTemplatesValidRule()
    unavailable = AuditData(resource_templates=None, listings_attempted=frozenset({"resource_templates"}))
    empty_partial = AuditData(resource_templates=[], incomplete_listings=frozenset({"resource_templates"}))

    assert rule.skip_reason(unavailable) == SKIP_REASON_INSUFFICIENT_DATA
    assert rule.skip_reason(empty_partial) == SKIP_REASON_INSUFFICIENT_DATA


def test_declared_resources_with_unobserved_templates_are_insufficient(capabilities_full) -> None:
    rule = ResourceTemplatesUriTemplatesValidRule()

    assert (
        rule.skip_reason(AuditData(resource_templates=None, capabilities=capabilities_full))
        == SKIP_REASON_INSUFFICIENT_DATA
    )


def test_only_the_uniqueness_rule_skips_incomplete_catalogs() -> None:
    """Per-item rules judge partial evidence; only uniqueness needs the full catalog."""
    data = AuditData(
        resource_templates=[_template("users", "users/{bad-name}")],
        incomplete_listings=frozenset({"resource_templates"}),
    )
    assert ResourceTemplatesUniqueRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA
    assert ResourceTemplatesUriTemplatesValidRule().skip_reason(data) is None
    assert ResourceTemplatesNamesPresentRule().skip_reason(data) is None
    assert ResourceTemplatesMimeTypesValidRule().skip_reason(data) is None
    assert ResourceTemplatesAnnotationsValidRule().skip_reason(data) is None
    assert ResourceTemplatesDescriptionPresentRule().skip_reason(data) is None
    assert ResourceTemplatesTitlesPresentRule().skip_reason(data) is None
    # A bad template on a fetched page is a finding even when pages are missing.
    assert ResourceTemplatesUriTemplatesValidRule().check(data).passed is False


def test_all_template_rules_skip_when_listing_produced_no_evidence() -> None:
    """A failed listing is unavailable, not an empty catalog that passes."""
    for templates in (None, []):
        data = AuditData(
            resource_templates=templates,
            listings_attempted=frozenset({"resource_templates"}),
            incomplete_listings=frozenset({"resource_templates"}),
        )
        for rule in (
            ResourceTemplatesUriTemplatesValidRule(),
            ResourceTemplatesUniqueRule(),
            ResourceTemplatesNamesPresentRule(),
            ResourceTemplatesMimeTypesValidRule(),
            ResourceTemplatesAnnotationsValidRule(),
            ResourceTemplatesDescriptionPresentRule(),
            ResourceTemplatesTitlesPresentRule(),
        ):
            assert rule.skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA
