import pytest

import mcpscore.rules as rules_pkg
from mcpscore.rules import (
    AllowedVersionRule,
    CapabilityToolsPresentRule,
    RuleRegistry,
    create_all_rules,
)
from mcpscore.rules.base import AuditData, BaseRule, RuleResult, RuleSeverity, rule_sort_key
from mcpscore.rules.registry import _registry, all_rule_ids
from mcpscore.rules.retired import RETIRED_RULES


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


class _ConcreteRule(BaseRule):
    """Concrete, unregistered rule body; subclasses vary one registration attribute."""

    group_name = "tools"

    @property
    def rule_name(self) -> str:
        return "test rule"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def check(self, audit_data: AuditData) -> RuleResult:
        return RuleResult(rule_name=self.rule_name, severity=self.severity, passed=True, message="ok")


def test_registry_accepts_a_well_formed_rule():
    class WellFormed(_ConcreteRule):
        rule_id = "test_well_formed"

    registry = RuleRegistry()
    registry.register_type(WellFormed)
    assert isinstance(registry.create_rule("test_well_formed"), WellFormed)


def test_registry_rejects_a_non_rule_class():
    registry = RuleRegistry()
    with pytest.raises(TypeError, match="must subclass BaseRule"):
        registry.register_type(object)  # type: ignore[arg-type]


def test_registry_rejects_an_abstract_rule():
    class StillAbstract(BaseRule):
        rule_id = "test_still_abstract"
        group_name = "tools"

    registry = RuleRegistry()
    with pytest.raises(TypeError, match="abstract"):
        registry.register_type(StillAbstract)


def test_registry_rejects_an_empty_rule_id():
    """Reject the empty rule_id inherited from BaseRule, which a hasattr check cannot catch."""

    class ForgotItsId(_ConcreteRule):
        pass

    registry = RuleRegistry()
    with pytest.raises(TypeError, match="non-empty"):
        registry.register_type(ForgotItsId)


def test_registry_rejects_a_rule_id_inherited_from_a_parent_rule():
    """A subclass of a real rule that forgets its own id must not register under the parent's."""

    class Parent(_ConcreteRule):
        rule_id = "test_parent"

    class Child(Parent):
        pass

    registry = RuleRegistry()
    registry.register_type(Parent)
    with pytest.raises(TypeError, match="inherits `rule_id`"):
        registry.register_type(Child)
    assert all_ids(registry) == ("test_parent",)


def test_registry_rejects_the_placeholder_group():
    class NoGroup(_ConcreteRule):
        rule_id = "test_no_group"
        group_name = BaseRule.group_name

    registry = RuleRegistry()
    with pytest.raises(TypeError, match="group_name"):
        registry.register_type(NoGroup)


def test_registry_rejects_an_empty_group():
    class EmptyGroup(_ConcreteRule):
        rule_id = "test_empty_group"
        group_name = ""

    registry = RuleRegistry()
    with pytest.raises(TypeError, match="group_name"):
        registry.register_type(EmptyGroup)


def test_registry_rejects_a_retired_rule_id():
    """Refuse to register a retired rule_id; a CI waiver would silently match a new check."""
    assert RETIRED_RULES, "test needs at least one retired rule to exercise the check"

    class Imposter(_ConcreteRule):
        rule_id = RETIRED_RULES[0].rule_id

    registry = RuleRegistry()
    with pytest.raises(ValueError, match="retired"):
        registry.register_type(Imposter)


def test_every_registered_rule_passes_registration_validation():
    """Re-register every live rule in a fresh registry: all checks pass, no active id is retired."""
    registered = list(_registry._types.values())
    assert registered

    fresh = RuleRegistry()
    for cls in registered:
        fresh.register_type(cls)

    assert all_ids(fresh) == all_rule_ids()
    assert not set(all_rule_ids()) & {retired.rule_id for retired in RETIRED_RULES}


def all_ids(registry: RuleRegistry) -> tuple[str, ...]:
    return tuple(registry._types)


def test_sort_order_implements_the_documented_ordering():
    """Sorted rules follow the documented ordering with contiguous groups.

    The attribute docstrings promise: lower group_order first, same
    group_order -> alphabetical group_name, within a group rule_order then
    rule_id. The old integer encoding had no tie-breakers, so `capabilities`
    and `security` (both group_order 3) interleaved by import order.
    """
    ordered = sorted(create_all_rules(), key=rule_sort_key)

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
    keys = [rule_sort_key(r) for r in ordered]
    assert len(keys) == len(set(keys))


def test_sort_order_is_independent_of_registration_order():
    """Sorting is independent of registration order.

    Reversing creation order must not change the sorted result — the old
    encoding leaned on Python's stable sort, i.e. on import order.
    """
    forward = sorted(create_all_rules(), key=rule_sort_key)
    reversed_creation = list(create_all_rules())
    reversed_creation.reverse()
    reversed_creation.sort(key=rule_sort_key)
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
