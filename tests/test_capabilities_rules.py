from mcpscore.rules import (
    AuditData,
    CapabilityLoggingPresentRule,
)
from mcpscore.rules.capabilities import (
    CapabilityPromptsListChangedRule,
    CapabilityPromptsPresentRule,
    CapabilityResourcesListChangedRule,
    CapabilityResourcesPresentRule,
    CapabilityResourcesSubscribeRule,
    CapabilityToolsListChangedRule,
    CapabilityToolsPresentRule,
)


def test_capabilities_presence_rules(capabilities_full, capabilities_missing):
    """Test that capability presence rules correctly identify missing capabilities.

    This test verifies that rules for tools, prompts, resources, and logging
    capabilities properly detect when these capabilities are present or missing
    in the server's capability declaration.
    """
    presence_rules = [
        CapabilityToolsPresentRule(),
        CapabilityPromptsPresentRule(),
        CapabilityResourcesPresentRule(),
        CapabilityLoggingPresentRule(),
    ]

    for rule in presence_rules:
        assert rule.check(AuditData(capabilities=capabilities_full)).passed
        assert not rule.check(AuditData(capabilities=capabilities_missing)).passed


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
        CapabilityResourcesSubscribeRule(),
    ]

    for rule in feature_rules:
        assert rule.check(AuditData(capabilities=capabilities_full)).passed
        assert not rule.check(AuditData(capabilities=capabilities_missing)).passed
