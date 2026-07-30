"""Tests for resource-quality rules."""

from mcp_types import Resource

from mcpscore.rules import (
    AuditData,
    ResourcesDescriptionPresentRule,
    ResourcesNamesPresentRule,
    ResourcesSizesValidRule,
    ResourcesUrisValidRule,
    RuleSeverity,
)


def _resource(
    name: str,
    description: str | None = "Description",
    *,
    uri: str | None = None,
    size: int | None = None,
) -> Resource:
    return Resource(name=name, uri=uri if uri is not None else f"file:///{name}", description=description, size=size)


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


class TestResourcesDescriptionPresentRule:
    def test_rule_properties(self) -> None:
        rule = ResourcesDescriptionPresentRule()
        assert rule.rule_id == "resources_description_present"
        assert rule.severity == RuleSeverity.MEDIUM
        assert rule.group_name == "resources"

    def test_no_resources_is_not_applicable_and_passes(self) -> None:
        """Optional capability: a server with no resources is not penalized."""
        rule = ResourcesDescriptionPresentRule()
        assert rule.check(AuditData(resources=None)).passed
        assert rule.check(AuditData(resources=[])).passed

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
