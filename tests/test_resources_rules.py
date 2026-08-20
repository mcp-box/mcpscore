"""Tests for resource-quality rules."""

from mcp_types import Annotations, Resource
import pytest

from mcpscore.rules import (
    AuditData,
    ResourcesAnnotationsValidRule,
    ResourcesDescriptionPresentRule,
    ResourcesMimeTypesValidRule,
    ResourcesNamesPresentRule,
    ResourcesSizesValidRule,
    ResourcesTitlesPresentRule,
    ResourcesUrisUniqueRule,
    ResourcesUrisValidRule,
    RuleSeverity,
)
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE


def _resource(
    name: str,
    description: str | None = "Description",
    *,
    uri: str | None = None,
    size: int | None = None,
    mime_type: str | None = None,
    annotations: Annotations | None = None,
) -> Resource:
    return Resource(
        name=name,
        uri=uri if uri is not None else f"file:///{name}",
        description=description,
        size=size,
        mime_type=mime_type,
        annotations=annotations,
    )


class TestResourcesUrisValidRule:
    def test_rule_properties(self) -> None:
        rule = ResourcesUrisValidRule()
        assert rule.rule_id == "resources_uris_valid"
        assert rule.severity == RuleSeverity.HIGH
        assert rule.group_name == "resources"

    def test_absolute_standard_and_custom_uris_pass(self) -> None:
        result = ResourcesUrisValidRule().check(
            AuditData(
                resources=[
                    _resource("file", uri="file:///project/readme.md"),
                    _resource("web", uri="https://example.com/resource"),
                    _resource("custom", uri="example+db:records/42"),
                ]
            )
        )
        assert result.passed is True
        assert result.details == {"invalid_resource_uris": []}

    def test_relative_malformed_and_unescaped_character_uris_fail(self) -> None:
        result = ResourcesUrisValidRule().check(
            AuditData(
                resources=[
                    _resource("relative", uri="docs/readme.md"),
                    _resource("port", uri="https://example.com:bad/resource"),
                    _resource("control", uri="file:///readme\n.md"),
                    _resource("space", uri="file:///project/my file.md"),
                    _resource("escape", uri="file:///project/%ZZ"),
                ]
            )
        )
        assert result.passed is False
        assert result.details is not None
        assert {item["name"] for item in result.details["invalid_resource_uris"]} == {
            "relative",
            "port",
            "control",
            "space",
            "escape",
        }


class TestResourcesUrisUniqueRule:
    def test_unique_uris_pass(self) -> None:
        result = ResourcesUrisUniqueRule().check(AuditData(resources=[_resource("one"), _resource("two")]))
        assert result.passed is True
        assert result.details == {"duplicate_uris": []}

    def test_duplicate_uri_fails_once(self) -> None:
        result = ResourcesUrisUniqueRule().check(
            AuditData(
                resources=[
                    _resource("one", uri="file:///same"),
                    _resource("two", uri="file:///same"),
                    _resource("three", uri="file:///same"),
                ]
            )
        )
        assert result.passed is False
        assert result.details == {"duplicate_uris": ["file:///same"]}

    def test_incomplete_listing_skips(self) -> None:
        rule = ResourcesUrisUniqueRule()
        data = AuditData(resources=[_resource("one")], incomplete_listings=frozenset({"resources"}))
        assert rule.skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA


class TestResourcesTitlesPresentRule:
    def test_scoped_to_revisions_that_have_title(self) -> None:
        """`title` first appeared in 2025-06-18 — earlier servers cannot declare one."""
        rule = ResourcesTitlesPresentRule()
        assert rule.min_spec_version == "2025-06-18"
        assert not rule.applies_to("2025-03-26")
        assert rule.applies_to("2025-06-18")

    def test_non_blank_titles_pass(self) -> None:
        resources = [
            Resource(uri="file:///one", name="one", title="First resource"),
            Resource(uri="file:///two", name="two", title="Second resource"),
        ]
        result = ResourcesTitlesPresentRule().check(AuditData(resources=resources))
        assert result.passed is True
        assert result.details == {"resources_without_title": []}

    def test_missing_and_blank_titles_fail_with_uris(self) -> None:
        resources = [
            _resource("missing", uri="file:///missing"),
            Resource(uri="file:///blank", name="blank", title="   "),
        ]
        result = ResourcesTitlesPresentRule().check(AuditData(resources=resources))
        assert result.passed is False
        assert result.details == {"resources_without_title": ["file:///missing", "file:///blank"]}


class TestResourcesNamesPresentRule:
    def test_non_blank_names_pass(self) -> None:
        result = ResourcesNamesPresentRule().check(AuditData(resources=[_resource("README"), _resource("Schema")]))
        assert result.passed is True
        assert result.details == {"resources_without_name": []}

    def test_blank_names_fail_and_report_uris(self) -> None:
        result = ResourcesNamesPresentRule().check(
            AuditData(
                resources=[
                    _resource("", uri="file:///empty"),
                    _resource("   ", uri="file:///blank"),
                ]
            )
        )
        assert result.passed is False
        assert result.details == {"resources_without_name": ["file:///empty", "file:///blank"]}


class TestResourcesSizesValidRule:
    def test_absent_zero_and_positive_sizes_pass(self) -> None:
        result = ResourcesSizesValidRule().check(
            AuditData(resources=[_resource("unknown"), _resource("empty", size=0), _resource("data", size=42)])
        )
        assert result.passed is True
        assert result.details == {"resources_with_invalid_size": []}

    def test_negative_size_fails(self) -> None:
        result = ResourcesSizesValidRule().check(AuditData(resources=[_resource("bad", size=-1)]))
        assert result.passed is False
        assert result.details == {"resources_with_invalid_size": [{"name": "bad", "size": -1}]}


class TestResourcesMimeTypesValidRule:
    def test_absent_and_valid_mime_types_pass(self) -> None:
        result = ResourcesMimeTypesValidRule().check(
            AuditData(
                resources=[
                    _resource("unknown"),
                    _resource("text", mime_type="text/plain"),
                    _resource("vendor", mime_type="application/vnd.example+json"),
                    _resource("parameter", mime_type='text/plain; charset="utf-8"'),
                ]
            )
        )
        assert result.passed is True
        assert result.details == {"resources_with_invalid_mime_type": []}

    def test_invalid_mime_types_fail(self) -> None:
        result = ResourcesMimeTypesValidRule().check(
            AuditData(
                resources=[
                    _resource("missing-subtype", mime_type="text"),
                    _resource("parameter", mime_type="text/plain; charset"),
                    _resource("blank", mime_type=""),
                ]
            )
        )
        assert result.passed is False
        assert result.details is not None
        assert {item["name"] for item in result.details["resources_with_invalid_mime_type"]} == {
            "missing-subtype",
            "parameter",
            "blank",
        }


class TestResourcesAnnotationsValidRule:
    def test_absent_and_iso_8601_last_modified_pass(self) -> None:
        result = ResourcesAnnotationsValidRule().check(
            AuditData(
                resources=[
                    _resource("none"),
                    _resource("date", annotations=Annotations(last_modified="2026-07-30")),
                    _resource("timestamp", annotations=Annotations(last_modified="2026-07-30T10:15:30Z")),
                ]
            )
        )
        assert result.passed is True
        assert result.details == {"resources_with_invalid_annotations": []}

    def test_invalid_last_modified_fails(self) -> None:
        result = ResourcesAnnotationsValidRule().check(
            AuditData(resources=[_resource("bad", annotations=Annotations(last_modified="30 July 2026"))])
        )
        assert result.passed is False
        assert result.details == {"resources_with_invalid_annotations": ["bad"]}

    @pytest.mark.parametrize("value", ["", " 2026-07-30T10:15:30Z "])
    def test_blank_or_padded_last_modified_fails(self, value: str) -> None:
        """Whitespace padding is not tolerated — the value must be exactly the timestamp."""
        result = ResourcesAnnotationsValidRule().check(
            AuditData(resources=[_resource("bad", annotations=Annotations(last_modified=value))])
        )
        assert result.passed is False


class TestResourcesDescriptionPresentRule:
    def test_rule_properties(self) -> None:
        rule = ResourcesDescriptionPresentRule()
        assert rule.rule_id == "resources_description_present"
        assert rule.severity == RuleSeverity.MEDIUM
        assert rule.group_name == "resources"

    def test_no_resources_is_not_applicable_and_skips(self) -> None:
        """Optional capability: a server with no resources is not penalized."""
        rule = ResourcesDescriptionPresentRule()
        assert rule.skip_reason(AuditData(resources=None)) == SKIP_REASON_NOT_APPLICABLE
        assert rule.skip_reason(AuditData(resources=[])) == SKIP_REASON_NOT_APPLICABLE

    def test_unavailable_or_empty_partial_resources_are_insufficient_data(self) -> None:
        rule = ResourcesDescriptionPresentRule()
        unavailable = AuditData(resources=None, listings_attempted=frozenset({"resources"}))
        empty_partial = AuditData(resources=[], incomplete_listings=frozenset({"resources"}))

        assert rule.skip_reason(unavailable) == SKIP_REASON_INSUFFICIENT_DATA
        assert rule.skip_reason(empty_partial) == SKIP_REASON_INSUFFICIENT_DATA

    def test_all_described_passes(self) -> None:
        rule = ResourcesDescriptionPresentRule()
        result = rule.check(AuditData(resources=[_resource("a", "An A"), _resource("b", "A B")]))
        assert result.passed is True
        assert result.details is not None
        assert result.details["resources_without_description"] == []

    def test_missing_description_fails(self) -> None:
        rule = ResourcesDescriptionPresentRule()
        result = rule.check(
            AuditData(resources=[_resource("good", "desc"), _resource("bad", None), _resource("blank", "  ")])
        )
        assert result.passed is False
        assert result.details is not None
        assert set(result.details["resources_without_description"]) == {"bad", "blank"}
