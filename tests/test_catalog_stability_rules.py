"""Tests for catalog connection-independence rules."""

import pytest

from mcpscore.probes import (
    PROBE_PROMPTS_CATALOG_CONNECTION_INDEPENDENT,
    PROBE_RESOURCES_CATALOG_CONNECTION_INDEPENDENT,
    PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT,
    ProbeOutcome,
    ProbeResult,
)
from mcpscore.rules import AuditData, RuleSeverity
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE
from mcpscore.rules.catalog_stability import (
    PromptsCatalogConnectionIndependentRule,
    ResourcesCatalogConnectionIndependentRule,
    ToolsCatalogConnectionIndependentRule,
)

RULES = (
    (ToolsCatalogConnectionIndependentRule, PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT, "Tools"),
    (
        ResourcesCatalogConnectionIndependentRule,
        PROBE_RESOURCES_CATALOG_CONNECTION_INDEPENDENT,
        "Resources",
    ),
    (PromptsCatalogConnectionIndependentRule, PROBE_PROMPTS_CATALOG_CONNECTION_INDEPENDENT, "Prompts"),
)


@pytest.mark.parametrize(("rule_cls", "probe_id", "surface"), RULES)
def test_connection_independence_rule_passes_equal_catalogs(rule_cls, probe_id, surface):
    probe = ProbeResult(
        probe_id,
        ProbeOutcome.SUPPORTED,
        {
            "first_count": 2,
            "second_count": 2,
            "only_first": [],
            "only_second": [],
            "differences_truncated": False,
        },
    )
    rule = rule_cls()

    assert rule.skip_reason(AuditData(probes={probe_id: probe})) is None
    result = rule.check(AuditData(probes={probe_id: probe}))

    assert result.passed
    assert result.severity is RuleSeverity.HIGH
    assert surface in result.message
    assert result.details["first_count"] == 2
    assert result.details["spec"].startswith("https://modelcontextprotocol.io/specification/2026-07-28/")


@pytest.mark.parametrize(("rule_cls", "probe_id", "surface"), RULES)
def test_connection_independence_rule_fails_and_reports_bounded_differences(rule_cls, probe_id, surface):
    probe = ProbeResult(
        probe_id,
        ProbeOutcome.UNSUPPORTED,
        {
            "first_count": 1,
            "second_count": 1,
            "only_first": ["before"],
            "only_second": ["after"],
            "differences_truncated": False,
        },
    )

    result = rule_cls().check(AuditData(probes={probe_id: probe}))

    assert not result.passed
    assert surface in result.message
    assert result.details["only_first"] == ["before"]
    assert result.details["only_second"] == ["after"]


def test_connection_independence_rule_preserves_capability_mismatch_evidence():
    probe = ProbeResult(
        PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT,
        ProbeOutcome.UNSUPPORTED,
        {
            "first_declares_capability": True,
            "second_declares_capability": False,
            "reason": "tools capability varies across client connections",
        },
    )

    result = ToolsCatalogConnectionIndependentRule().check(
        AuditData(probes={PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT: probe})
    )

    assert not result.passed
    assert result.details is not None
    assert result.details["first_declares_capability"] is True
    assert result.details["second_declares_capability"] is False
    assert result.details["reason"] == "tools capability varies across client connections"


@pytest.mark.parametrize(("rule_cls", "probe_id", "surface"), RULES)
def test_connection_independence_rule_skips_unobservable_comparisons(rule_cls, probe_id, surface):
    del surface
    rule = rule_cls()

    assert rule.skip_reason(AuditData()) == SKIP_REASON_INSUFFICIENT_DATA
    assert (
        rule.skip_reason(
            AuditData(probes={probe_id: ProbeResult(probe_id, ProbeOutcome.ERROR, {"exception": "TimeoutError"})})
        )
        == SKIP_REASON_INSUFFICIENT_DATA
    )
    assert (
        rule.skip_reason(AuditData(probes={probe_id: ProbeResult(probe_id, ProbeOutcome.NOT_APPLICABLE)}))
        == SKIP_REASON_NOT_APPLICABLE
    )


@pytest.mark.parametrize(("rule_cls", "probe_id", "surface"), RULES)
def test_connection_independence_rule_is_modern_only(rule_cls, probe_id, surface):
    del probe_id, surface
    rule = rule_cls()

    assert not rule.applies_to("2025-11-25")
    assert rule.applies_to("2026-07-28")
    assert rule.uses_modern_probe_evidence
