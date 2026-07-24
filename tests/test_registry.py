from mcpscore.rules import (
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


def test_every_rule_cites_its_basis():
    """Every rule carries a primary-source citation (launch claim: "each citing the spec").

    Non-readiness rules cite via the class-level ``basis`` attribute (injected
    into result details by the auditor) or inline in their result details (the
    auth rules). Readiness rules cite via their ``details["sep"]`` keys, which
    their own tests assert.
    """
    from mcpscore.rules.auth import AuthPostureBaseRule
    from mcpscore.rules.base import READINESS_GROUP

    for rule in create_all_rules():
        if rule.group_name == READINESS_GROUP:
            continue  # cite via details["sep"], asserted in test_readiness_rules
        if isinstance(rule, AuthPostureBaseRule):
            continue  # cite inline in details["basis"], asserted in test_auth_rules
        # Substantive citation required; the format is deliberately not
        # constrained to a source vocabulary (MCP/RFC/SEP/best-practice all
        # valid) — only emptiness and throwaway strings are rejected.
        assert rule.basis, f"{rule.rule_id} has no basis citation"
        assert len(rule.basis.strip()) >= 15, f"{rule.rule_id} basis citation is not substantive: {rule.basis!r}"
