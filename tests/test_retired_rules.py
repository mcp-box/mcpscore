"""Regression tests for rules retired in 1.1.0.

`capability_logging_present` and `capability_resources_subscribe` scored the
*absence* of capabilities the spec sections they cited call optional, and the
logging rule directly contradicted `readiness_2026_deprecated_features` (which
fails a server for *declaring* `logging`, deprecated by SEP-2577). With
readiness promoted into the main score for modern/dual-era servers, no server
could pass both — every server in the acceptance corpus failed one of them.

These tests fail against the pre-retirement code, which is the point.
"""

from dataclasses import replace

from mcpscore.rules import AuditData, create_all_rules
from mcpscore.rules.base import READINESS_GROUP

RETIRED_RULE_IDS = frozenset({"capability_logging_present", "capability_resources_subscribe"})
"""rule_id is a public contract: these are retired, never reused."""


def _main_rules():
    """Every registered rule that scores on the main axis."""
    return [rule for rule in create_all_rules() if rule.group_name != READINESS_GROUP]


def _capability_score(capabilities) -> int:
    """Points a capabilities-shaped server earns from the main rules that can judge it."""
    total = 0
    audit_data = AuditData(capabilities=capabilities)
    for rule in _main_rules():
        if rule.skip_reason(audit_data) is not None:
            continue
        result = rule.check(audit_data)
        if result.passed:
            total += int(result.severity)  # RuleSeverity is an IntEnum of point weights
    return total


def test_retired_rule_ids_are_not_registered():
    assert RETIRED_RULE_IDS.isdisjoint({rule.rule_id for rule in create_all_rules()})


def test_omitting_the_deprecated_logging_capability_costs_nothing(capabilities_full):
    """SEP-2577 deprecates Logging: omitting it must not cost points.

    The contradiction this fixes: the retired rule failed a server for omitting
    `logging` while `readiness_2026_deprecated_features` fails it for declaring
    the same capability.
    """
    without_logging = replace(capabilities_full, logging=None)

    assert _capability_score(without_logging) == _capability_score(capabilities_full)


def test_omitting_the_optional_subscribe_capability_costs_nothing(capabilities_full):
    """Omitting the optional `subscribe` capability must not cost points.

    2025-11-25 Resources §Capabilities: "Both `subscribe` and `listChanged` are
    optional — servers can support neither, either, or both." SEP-2575 then
    removes `resources/subscribe` outright.
    """
    without_subscribe = replace(capabilities_full, resources=replace(capabilities_full.resources, subscribe=False))

    assert _capability_score(without_subscribe) == _capability_score(capabilities_full)
