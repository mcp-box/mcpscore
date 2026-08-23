"""Tests for invalid-cursor pagination rules."""

import pytest

from mcpscore.probes import (
    ERROR_INVALID_PARAMS,
    PROBE_DISCOVER,
    PROBE_PAGINATION_CACHE_SCOPE,
    PROBE_PROMPTS_INVALID_CURSOR,
    PROBE_RESOURCE_TEMPLATES_INVALID_CURSOR,
    PROBE_RESOURCES_INVALID_CURSOR,
    PROBE_TOOLS_INVALID_CURSOR,
    ProbeOutcome,
    ProbeResult,
)
from mcpscore.rules import AuditData, RuleSeverity
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE
from mcpscore.rules.pagination import (
    CACHING_PAGINATION_SPEC,
    PAGINATION_SPEC,
    PaginationCacheScopeConsistentRule,
    PromptsInvalidCursorRule,
    ResourcesInvalidCursorRule,
    ResourceTemplatesInvalidCursorRule,
    ToolsInvalidCursorRule,
    pagination_spec,
)

RULES = (
    (ToolsInvalidCursorRule, PROBE_TOOLS_INVALID_CURSOR, "tools/list"),
    (ResourcesInvalidCursorRule, PROBE_RESOURCES_INVALID_CURSOR, "resources/list"),
    (
        ResourceTemplatesInvalidCursorRule,
        PROBE_RESOURCE_TEMPLATES_INVALID_CURSOR,
        "resources/templates/list",
    ),
    (PromptsInvalidCursorRule, PROBE_PROMPTS_INVALID_CURSOR, "prompts/list"),
)


@pytest.mark.parametrize(("rule_cls", "probe_id", "surface"), RULES)
def test_invalid_cursor_rule_passes_with_invalid_params(capabilities_full, rule_cls, probe_id, surface):
    probe = ProbeResult(probe_id, ProbeOutcome.SUPPORTED, {"error_code": ERROR_INVALID_PARAMS, "http_status": 400})
    data = AuditData(capabilities=capabilities_full, probes={probe_id: probe})
    rule = rule_cls()

    assert rule.skip_reason(data) is None
    result = rule.check(data)

    assert result.passed
    assert result.severity is RuleSeverity.LOW
    assert surface in result.message
    assert result.details == {
        "spec": PAGINATION_SPEC,
        "error_code": ERROR_INVALID_PARAMS,
        "http_status": 400,
    }


@pytest.mark.parametrize(("rule_cls", "probe_id", "surface"), RULES)
def test_invalid_cursor_rule_fails_other_behavior(capabilities_full, rule_cls, probe_id, surface):
    probe = ProbeResult(probe_id, ProbeOutcome.UNSUPPORTED, {"error_code": -32601})
    data = AuditData(capabilities=capabilities_full, probes={probe_id: probe})

    result = rule_cls().check(data)

    assert not result.passed
    assert surface in result.message


@pytest.mark.parametrize(("rule_cls", "probe_id", "surface"), RULES)
def test_invalid_cursor_rule_skips_missing_evidence(capabilities_full, rule_cls, probe_id, surface):
    del surface
    assert rule_cls().skip_reason(AuditData(capabilities=capabilities_full)) == SKIP_REASON_INSUFFICIENT_DATA
    errored = ProbeResult(probe_id, ProbeOutcome.ERROR, {"exception": "TimeoutError"})
    assert (
        rule_cls().skip_reason(AuditData(capabilities=capabilities_full, probes={probe_id: errored}))
        == SKIP_REASON_INSUFFICIENT_DATA
    )


@pytest.mark.parametrize(("rule_cls", "probe_id", "surface"), RULES)
def test_invalid_cursor_rule_skips_absent_capability(capabilities_missing, rule_cls, probe_id, surface):
    del probe_id, surface
    assert rule_cls().skip_reason(AuditData(capabilities=capabilities_missing)) == SKIP_REASON_NOT_APPLICABLE


def test_resources_capability_gates_both_resource_surfaces(capabilities_full):
    for rule_cls in (ResourcesInvalidCursorRule, ResourceTemplatesInvalidCursorRule):
        assert rule_cls().skip_reason(AuditData(capabilities=capabilities_full)) == SKIP_REASON_INSUFFICIENT_DATA


def test_unimplemented_optional_resource_template_surface_is_not_applicable(capabilities_full):
    probe = ProbeResult(PROBE_RESOURCE_TEMPLATES_INVALID_CURSOR, ProbeOutcome.NOT_APPLICABLE)
    data = AuditData(
        capabilities=capabilities_full,
        probes={PROBE_RESOURCE_TEMPLATES_INVALID_CURSOR: probe},
    )

    assert ResourceTemplatesInvalidCursorRule().skip_reason(data) == SKIP_REASON_NOT_APPLICABLE


def test_pagination_spec_uses_negotiated_version():
    assert pagination_spec("2025-11-25") == (
        "https://modelcontextprotocol.io/specification/2025-11-25/server/utilities/pagination#error-handling"
    )
    assert pagination_spec(None) == PAGINATION_SPEC


def _cache_scope_data(outcome: ProbeOutcome) -> AuditData:
    observations = {
        "tools": {
            "implemented": True,
            "complete": True,
            "pages": 2,
            "cache_scopes": ["public", "private"] if outcome is ProbeOutcome.UNSUPPORTED else ["public", "public"],
        }
    }
    return AuditData(
        probes={
            PROBE_DISCOVER: ProbeResult(PROBE_DISCOVER, ProbeOutcome.SUPPORTED),
            PROBE_PAGINATION_CACHE_SCOPE: ProbeResult(
                PROBE_PAGINATION_CACHE_SCOPE,
                outcome,
                {
                    "surfaces": observations,
                    "inconsistent_surfaces": ["tools"] if outcome is ProbeOutcome.UNSUPPORTED else [],
                },
            ),
        }
    )


def test_cache_scope_consistency_rule_passes_consistent_pages():
    rule = PaginationCacheScopeConsistentRule()
    data = _cache_scope_data(ProbeOutcome.SUPPORTED)

    assert rule.skip_reason(data) is None
    result = rule.check(data)

    assert result.passed
    assert result.severity is RuleSeverity.HIGH
    assert result.details["spec"] == CACHING_PAGINATION_SPEC


def test_cache_scope_consistency_rule_fails_and_names_surfaces():
    result = PaginationCacheScopeConsistentRule().check(_cache_scope_data(ProbeOutcome.UNSUPPORTED))

    assert not result.passed
    assert result.details["inconsistent_surfaces"] == ["tools"]
    assert "tools" in result.message


def test_cache_scope_consistency_rule_skips_unobservable_cases():
    rule = PaginationCacheScopeConsistentRule()
    assert rule.skip_reason(AuditData()) == SKIP_REASON_INSUFFICIENT_DATA

    for outcome, reason in (
        (ProbeOutcome.ERROR, SKIP_REASON_INSUFFICIENT_DATA),
        (ProbeOutcome.NOT_APPLICABLE, SKIP_REASON_NOT_APPLICABLE),
    ):
        data = _cache_scope_data(outcome)
        assert rule.skip_reason(data) == reason
