from mcp_types import ResourceTemplate

from mcpscore.rules import (
    AuditData,
    ResourceTemplatesNamesPresentRule,
    ResourceTemplatesUniqueRule,
    ResourceTemplatesUriTemplatesValidRule,
)
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA
from mcpscore.rules.resource_templates import is_valid_uri_template


def _template(name: str, uri_template: str) -> ResourceTemplate:
    return ResourceTemplate(name=name, uriTemplate=uri_template)


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


def test_template_rules_pass_when_capability_has_no_templates() -> None:
    for rule in (
        ResourceTemplatesUriTemplatesValidRule(),
        ResourceTemplatesUniqueRule(),
        ResourceTemplatesNamesPresentRule(),
    ):
        assert rule.check(AuditData(resource_templates=[])).passed
        assert rule.check(AuditData(resource_templates=None)).passed


def test_only_the_uniqueness_rule_skips_incomplete_catalogs() -> None:
    """Per-item rules judge partial evidence; only uniqueness needs the full catalog."""
    data = AuditData(
        resource_templates=[_template("users", "users/{bad-name}")],
        incomplete_listings=frozenset({"resource_templates"}),
    )
    assert ResourceTemplatesUniqueRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA
    assert ResourceTemplatesUriTemplatesValidRule().skip_reason(data) is None
    assert ResourceTemplatesNamesPresentRule().skip_reason(data) is None
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
        ):
            assert rule.skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA
