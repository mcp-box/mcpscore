"""Tests for the rules that judge a local server's Host validation and interface binding."""

import pytest

from mcpscore.enums import MCPTransportType
from mcpscore.probes import PROBE_HOST_VALIDATION, PROBE_LOCAL_BIND, ProbeOutcome, ProbeResult
from mcpscore.rules import AuditData, HostHeaderValidationRule, LocalBindLoopbackRule, RuleSeverity
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE

RULES = (HostHeaderValidationRule, LocalBindLoopbackRule)


def _audit(probe_id: str, outcome: ProbeOutcome | None, details: dict | None = None) -> AuditData:
    probes = {} if outcome is None else {probe_id: ProbeResult(probe_id, outcome, details or {})}
    return AuditData(protocol_version="2025-11-25", transport_type=MCPTransportType.STREAMABLE_HTTP, probes=probes)


@pytest.mark.parametrize(
    ("rule_class", "rule_id", "probe_id"),
    [
        (HostHeaderValidationRule, "security_host_header_validation", PROBE_HOST_VALIDATION),
        (LocalBindLoopbackRule, "security_local_bind_loopback", PROBE_LOCAL_BIND),
    ],
)
def test_identity(rule_class, rule_id: str, probe_id: str):
    rule = rule_class()
    assert rule.rule_id == rule_id
    assert rule.group_name == "security"
    assert rule.severity == RuleSeverity.MEDIUM
    assert rule.probe_id == probe_id
    assert rule.applies_to("2025-03-26")
    assert rule.applies_to("2026-07-28")
    assert not rule.applies_to("2024-11-05")


@pytest.mark.parametrize("rule_class", RULES)
def test_stdio_is_not_applicable(rule_class):
    assert rule_class().skip_reason(AuditData(transport_type=MCPTransportType.STDIO, probes={})) == (
        SKIP_REASON_NOT_APPLICABLE
    )


@pytest.mark.parametrize("rule_class", RULES)
def test_a_target_the_probe_could_not_judge_is_not_applicable(rule_class):
    rule = rule_class()
    data = _audit(rule.probe_id, ProbeOutcome.NOT_APPLICABLE, {"reason": "target is not a loopback address"})
    assert rule.skip_reason(data) == SKIP_REASON_NOT_APPLICABLE


@pytest.mark.parametrize("rule_class", RULES)
@pytest.mark.parametrize("outcome", [None, ProbeOutcome.ERROR])
def test_missing_or_errored_probe_is_insufficient_data(rule_class, outcome):
    rule = rule_class()
    assert rule.skip_reason(_audit(rule.probe_id, outcome)) == SKIP_REASON_INSUFFICIENT_DATA


def test_host_rule_passes_a_refused_foreign_host():
    rule = HostHeaderValidationRule()
    data = _audit(
        PROBE_HOST_VALIDATION,
        ProbeOutcome.SUPPORTED,
        {"http_status": 421, "control_http_status": 200, "control_shape": "modern"},
    )
    assert rule.skip_reason(data) is None
    result = rule.check(data)
    assert result.passed
    assert result.details["http_status"] == 421
    assert result.suggested_fix is None


def test_host_rule_fails_a_served_foreign_host():
    rule = HostHeaderValidationRule()
    data = _audit(
        PROBE_HOST_VALIDATION,
        ProbeOutcome.UNSUPPORTED,
        {"http_status": 200, "control_http_status": 200, "control_shape": "legacy-initialize"},
    )
    result = rule.check(data)
    assert not result.passed
    assert result.details["control_shape"] == "legacy-initialize"
    assert result.details["expected"] == {"http_status": "4xx"}
    assert "421 or 403" in (result.suggested_fix or "")


def test_bind_rule_passes_a_loopback_only_server():
    rule = LocalBindLoopbackRule()
    data = _audit(
        PROBE_LOCAL_BIND, ProbeOutcome.SUPPORTED, {"port": 8000, "interfaces_checked": 2, "interfaces_reachable": 0}
    )
    result = rule.check(data)
    assert result.passed
    assert result.details["interfaces_checked"] == 2
    assert result.suggested_fix is None


def test_bind_rule_fails_a_server_listening_on_every_interface():
    rule = LocalBindLoopbackRule()
    data = _audit(
        PROBE_LOCAL_BIND, ProbeOutcome.UNSUPPORTED, {"port": 8000, "interfaces_checked": 2, "interfaces_reachable": 1}
    )
    result = rule.check(data)
    assert not result.passed
    assert result.details["interfaces_reachable"] == 1
    assert result.details["expected"] == {"interfaces_reachable": 0}
    assert "127.0.0.1" in (result.suggested_fix or "")
