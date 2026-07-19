from mcp_types import ResourcesCapability
from pydantic import BaseModel

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
