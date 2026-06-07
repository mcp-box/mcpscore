from mcpdoctor.rules import (
    AllowedVersionRule,
    CapabilityLoggingPresentRule,
    RuleRegistry,
    create_all_rules,
)


def test_registry_creates_all_rules():
    rules = list(create_all_rules())
    # ensure at least a couple of known rules are included
    assert any(isinstance(r, AllowedVersionRule) for r in rules)
    assert any(isinstance(r, CapabilityLoggingPresentRule) for r in rules)


def test_registry_unique_ids():
    registry = RuleRegistry()

    # re-registering the same class should raise after first register
    registry.register_type(AllowedVersionRule)
    try:
        registry.register_type(AllowedVersionRule)
        raised = False
    except ValueError:
        raised = True
    assert raised
