from dataclasses import replace

from mcp_types import ResourcesCapability
from pydantic import BaseModel

from mcpscore.rules import AuditData, RuleSeverity
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA
from mcpscore.rules.capabilities import (
    CapabilityPromptsListChangedRule,
    CapabilityPromptsPresentRule,
    CapabilityResourcesListChangedRule,
    CapabilityResourcesPresentRule,
    CapabilityToolsListChangedRule,
    CapabilityToolsPresentRule,
    _wire_str,
)


class TestWireStr:
    """The report must always show MCP wire field names, never SDK attribute names."""

    def test_none_stays_none(self):
        assert _wire_str(None) is None

    def test_non_model_falls_back_to_str(self):
        assert _wire_str("already a string") == "already a string"

    def test_model_renders_wire_aliases(self):
        capability = ResourcesCapability(subscribe=False, list_changed=True)
        assert _wire_str(capability) == "subscribe=False listChanged=True"

    def test_field_without_alias_uses_python_name(self):
        class Plain(BaseModel):
            flag: bool = True

        assert _wire_str(Plain()) == "flag=True"


DECLARATION_RULES = (
    (CapabilityToolsPresentRule, "tools"),
    (CapabilityPromptsPresentRule, "prompts"),
    (CapabilityResourcesPresentRule, "resources"),
)
"""Each consistency rule with the AuditData field carrying what the server served."""


def _audit_data(capabilities, feature, items):
    return AuditData(capabilities=capabilities, **{feature: items})


def test_declared_and_served_passes(capabilities_full):
    for rule_cls, feature in DECLARATION_RULES:
        result = rule_cls().check(_audit_data(capabilities_full, feature, [object()]))
        assert result.passed, feature


def test_neither_declared_nor_served_passes(capabilities_missing):
    """A tools-only server must not lose points for having no resources or prompts.

    The spec requires the declaration only of servers that *support* the
    feature; scoring its absence penalized the majority of real servers for a
    legitimate design choice.
    """
    for rule_cls, feature in DECLARATION_RULES:
        result = rule_cls().check(_audit_data(capabilities_missing, feature, None))
        assert result.passed, feature
        assert "only required of servers that support it" in result.message


def test_served_without_being_declared_fails(capabilities_missing):
    """The actual spec MUST: serving the feature obliges declaring it."""
    for rule_cls, feature in DECLARATION_RULES:
        result = rule_cls().check(_audit_data(capabilities_missing, feature, [object(), object()]))
        assert not result.passed, feature
        assert "MUST declare it" in result.message
        details = result.details or {}
        assert details["served"] is True
        assert details["declared"] is False


def test_declared_but_listing_does_not_answer_fails(capabilities_full):
    """Advertising a feature whose listing method fails is a broken promise."""
    for rule_cls, feature in DECLARATION_RULES:
        result = rule_cls().check(_audit_data(capabilities_full, feature, None))
        assert not result.passed, feature
        assert "did not answer" in result.message


def test_declared_and_served_empty_passes(capabilities_full):
    """An empty list is a valid answer — a server may declare a feature it has none of yet."""
    for rule_cls, feature in DECLARATION_RULES:
        assert rule_cls().check(_audit_data(capabilities_full, feature, [])).passed, feature


def test_list_changed_rules_are_advisory():
    """The listChanged rules are optional per spec, so they may only ever cost a LOW point."""
    for rule in (
        CapabilityToolsListChangedRule(),
        CapabilityPromptsListChangedRule(),
        CapabilityResourcesListChangedRule(),
    ):
        assert rule.severity is RuleSeverity.LOW
        assert rule.basis is not None
        assert "optional" in rule.basis


def test_capabilities_feature_rules(capabilities_full, capabilities_missing):
    """Test that capability feature rules correctly validate advanced capabilities.

    This test verifies that rules for list_changed and subscribe features
    properly detect when these advanced capabilities are supported or missing
    in the server's capability declaration.
    """
    feature_rules = [
        CapabilityToolsListChangedRule(),
        CapabilityPromptsListChangedRule(),
        CapabilityResourcesListChangedRule(),
    ]

    for rule in feature_rules:
        assert rule.check(AuditData(capabilities=capabilities_full)).passed
        assert not rule.check(AuditData(capabilities=capabilities_missing)).passed


def test_capabilities_feature_rules_declared_but_disabled(capabilities_full):
    """A capability that is declared but has the feature flag off must fail with 'not supported'.

    Distinct from the capability being absent: this exercises the middle arm
    (present, flag false) of each feature rule.
    """
    caps = replace(
        capabilities_full,
        tools=replace(capabilities_full.tools, list_changed=False),
        prompts=replace(capabilities_full.prompts, list_changed=False),
        resources=replace(capabilities_full.resources, list_changed=False),
    )
    feature_rules = [
        CapabilityToolsListChangedRule(),
        CapabilityPromptsListChangedRule(),
        CapabilityResourcesListChangedRule(),
    ]

    for rule in feature_rules:
        result = rule.check(AuditData(capabilities=caps))
        assert result.passed is False
        assert "not supported" in result.message


class TestListingNeverAttempted:
    """A listing the auditor never ran must not be scored as a failed listing.

    Regression for the review finding on PR #57: the session path lists a
    feature only when the server declares it, and `audit_modern_only` collects
    tools alone from the stateless probe. Treating `items is None` as "the
    listing did not answer" failed a modern server that declares resources and
    prompts for 10 CRITICAL points it had done nothing to deserve.
    """

    def test_modern_only_shape_skips_uncollected_listings(self, capabilities_full):
        """Modern probe path: tools observed, resources/prompts never listed."""
        data = AuditData(
            capabilities=capabilities_full,
            tools=[object()],
            listings_attempted=frozenset({"tools"}),
        )

        assert CapabilityToolsPresentRule().skip_reason(data) is None
        assert CapabilityToolsPresentRule().check(data).passed
        for rule_cls in (CapabilityResourcesPresentRule, CapabilityPromptsPresentRule):
            assert rule_cls().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_attempted_listing_is_judged(self, capabilities_full):
        """Once a listing ran, silence really does mean it did not answer."""
        data = AuditData(
            capabilities=capabilities_full,
            resources=None,
            listings_attempted=frozenset({"resources"}),
        )

        rule = CapabilityResourcesPresentRule()
        assert rule.skip_reason(data) is None
        result = rule.check(data)
        assert not result.passed
        assert "did not answer" in result.message

    def test_default_audit_data_attempts_nothing(self):
        """The default is 'not attempted', so no rule can fail on absent data."""
        for rule_cls, _ in DECLARATION_RULES:
            assert rule_cls().skip_reason(AuditData()) == SKIP_REASON_INSUFFICIENT_DATA
