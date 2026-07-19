"""Tests for resource-quality rules."""

from mcp_types import Resource

from mcpscore.rules import AuditData, ResourcesDescriptionPresentRule, RuleSeverity


def _resource(name: str, description: str | None) -> Resource:
    # model_validate coerces the str uri to AnyUrl (the constructor wants AnyUrl).
    return Resource.model_validate({"name": name, "uri": f"file:///{name}", "description": description})


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
