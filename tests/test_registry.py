import pytest

from mcpscore.rules import (
    AllowedVersionRule,
    CapabilityToolsPresentRule,
    RuleRegistry,
    create_all_rules,
)


def test_registry_creates_all_rules():
    rules = list(create_all_rules())
    # ensure at least a couple of known rules are included
    assert any(isinstance(r, AllowedVersionRule) for r in rules)
    assert any(isinstance(r, CapabilityToolsPresentRule) for r in rules)


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


def test_registry_rejects_an_empty_rule_id():
    """Reject the empty rule_id inherited from BaseRule.

    BaseRule defaults rule_id to "", so hasattr can never fail — the registry
    must reject the empty default explicitly, or a rule that forgot its id
    registers fine until a second one collides on "".
    """
    from mcpscore.rules.base import BaseRule

    class ForgotItsId(BaseRule):
        pass

    registry = RuleRegistry()
    with pytest.raises(TypeError, match="non-empty"):
        registry.register_type(ForgotItsId)


def test_registry_rejects_a_retired_rule_id():
    """Refuse to register a retired rule_id.

    Retired ids are never reused: a waiver in someone's CI would silently
    start matching a check they never agreed to.
    """
    from mcpscore.rules.base import BaseRule
    from mcpscore.rules.retired import RETIRED_RULES

    assert RETIRED_RULES, "test needs at least one retired rule to exercise the check"

    class Imposter(BaseRule):
        rule_id = RETIRED_RULES[0].rule_id

    registry = RuleRegistry()
    with pytest.raises(ValueError, match="retired"):
        registry.register_type(Imposter)


def test_sort_order_implements_the_documented_ordering():
    """Sorted rules follow the documented ordering with contiguous groups.

    The attribute docstrings promise: lower group_order first, same
    group_order -> alphabetical group_name, within a group rule_order then
    rule_id. The old integer encoding had no tie-breakers, so `capabilities`
    and `security` (both group_order 3) interleaved by import order.
    """
    ordered = sorted(create_all_rules(), key=lambda r: r.sort_order)

    # Groups must be contiguous: once a group ends, it never reappears.
    seen_groups: list[str] = []
    for rule in ordered:
        if not seen_groups or seen_groups[-1] != rule.group_name:
            assert rule.group_name not in seen_groups, (
                f"group {rule.group_name!r} is not contiguous in the sorted order"
            )
            seen_groups.append(rule.group_name)

    # Groups sharing a group_order appear alphabetically (the real case:
    # capabilities before security, both group_order 3).
    assert seen_groups.index("capabilities") < seen_groups.index("security")

    # Full determinism: no two rules share a complete sort key (rule_id is
    # unique, so this holds by construction — pin it anyway).
    keys = [r.sort_order for r in ordered]
    assert len(keys) == len(set(keys))


def test_sort_order_is_independent_of_registration_order():
    """Sorting is independent of registration order.

    Reversing creation order must not change the sorted result — the old
    encoding leaned on Python's stable sort, i.e. on import order.
    """
    forward = sorted(create_all_rules(), key=lambda r: r.sort_order)
    reversed_creation = list(create_all_rules())
    reversed_creation.reverse()
    reversed_creation.sort(key=lambda r: r.sort_order)
    assert [r.rule_id for r in forward] == [r.rule_id for r in reversed_creation]


def test_every_concrete_rule_module_class_is_registered():
    """Every concrete rule class in the package is registered.

    A decorated rule whose module is never imported from rules/__init__.py
    silently vanishes from audits. Walk the rules package and assert every
    concrete BaseRule subclass is actually in the registry.
    """
    import importlib
    import inspect
    import pkgutil

    import mcpscore.rules as rules_pkg
    from mcpscore.rules.base import BaseRule
    from mcpscore.rules.registry import _registry

    registered = set(_registry._types.values())
    missing: list[str] = []
    for module_info in pkgutil.iter_modules(rules_pkg.__path__):
        module = importlib.import_module(f"mcpscore.rules.{module_info.name}")
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if not issubclass(cls, BaseRule) or cls.__module__ != module.__name__:
                continue
            # Base/abstract helpers legitimately carry no rule_id of their own.
            if not cls.rule_id:
                continue
            if cls not in registered:
                missing.append(f"{module.__name__}.{cls.__name__} ({cls.rule_id})")
    assert not missing, f"rules defined but not registered (module not imported?): {missing}"
