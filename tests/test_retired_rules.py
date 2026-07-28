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
from mcpscore.rules.retired import RETIRED_RULES

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


class TestRetiredRegistry:
    """The registry is the public record of retired IDs — it must stay honest.

    It feeds the "Retired rules" table in docs/rules.mdx, which is what someone
    holding an old report or a stale CI waiver reads to find out what happened.
    """

    def test_registry_matches_the_ids_this_release_retired(self):
        assert {r.rule_id for r in RETIRED_RULES} == RETIRED_RULE_IDS

    def test_no_retired_id_is_ever_reused(self):
        """A new rule reusing a retired ID would silently match old CI waivers."""
        live = {rule.rule_id for rule in create_all_rules()}
        assert live.isdisjoint({r.rule_id for r in RETIRED_RULES})

    def test_entries_are_unique_and_explained(self):
        ids = [r.rule_id for r in RETIRED_RULES]
        assert len(ids) == len(set(ids)), "an ID may be retired only once"
        for entry in RETIRED_RULES:
            assert entry.version, entry.rule_id
            assert entry.severity, entry.rule_id
            # The reason is read by someone holding a report, not by us.
            assert len(entry.reason) > 40, entry.rule_id
