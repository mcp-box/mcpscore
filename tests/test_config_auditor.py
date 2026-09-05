"""Tests for applying a per-project rule configuration inside MCPAuditor."""

from mcpscore import AuditData, BaseRule, MCPAuditor, RuleConfig, RuleResult, RuleSeverity
from mcpscore.config import SKIP_REASON_DISABLED_BY_CONFIG
from mcpscore.mcp_auditor import READINESS_GROUP, Era
from mcpscore.rules.base import SKIP_REASON_NOT_APPLICABLE


def make_rule(
    rule_id: str,
    severity: RuleSeverity,
    *,
    passed: bool,
    group_name: str = "default",
    min_spec_version: str | None = None,
) -> BaseRule:
    """Build a rule with a fixed verdict, for driving the auditor's scoring directly."""
    fixed_severity, fixed_passed = severity, passed

    class Rule(BaseRule):
        pass

    Rule.rule_id = rule_id
    Rule.group_name = group_name
    Rule.min_spec_version = min_spec_version

    def rule_name(self: BaseRule) -> str:
        return rule_id

    def rule_severity(self: BaseRule) -> RuleSeverity:
        return fixed_severity

    def check(self: BaseRule, audit_data: AuditData) -> RuleResult:
        return RuleResult(
            rule_name=rule_id,
            severity=fixed_severity,
            passed=fixed_passed,
            message=f"{rule_id}: {'ok' if fixed_passed else 'no'}",
        )

    # Abstract members are resolved when the class is created, so build the
    # concrete class with them in its body rather than patching afterwards.
    concrete = type(
        "Rule",
        (Rule,),
        {"rule_name": property(rule_name), "severity": property(rule_severity), "check": check},
    )
    return concrete()


def config(**overrides: RuleSeverity | None) -> RuleConfig:
    return RuleConfig(source="mcpscore.toml", sha256="abc123", overrides=overrides)


def run(
    rules: list[BaseRule], cfg: RuleConfig | None = None, *, era: Era | None = None, partial: bool = False
) -> MCPAuditor:
    auditor = MCPAuditor(config=cfg)
    auditor.rules = rules
    auditor.audit_data = AuditData(protocol_version="2025-11-25", partial=partial)
    auditor.era = era
    auditor._run_all_rules()
    return auditor


def skip_reasons(auditor: MCPAuditor) -> dict[str, str]:
    return {s.rule_id: s.reason for s in auditor.skipped_rules}


# --- no configuration: nothing changes --------------------------------------


def test_report_has_no_config_block_without_a_configuration():
    rules = [make_rule("a", RuleSeverity.HIGH, passed=True)]

    assert "config" not in run(rules).get_audit_report()
    assert "config" not in run(rules, None).get_audit_report()


def test_unconfigured_scoring_is_unchanged():
    auditor = run([make_rule("a", RuleSeverity.HIGH, passed=True), make_rule("b", RuleSeverity.LOW, passed=False)])

    assert (auditor.score, auditor.max_score) == (3, 4)
    assert auditor.skipped_rules == []


# --- off ----------------------------------------------------------------------


def test_off_rule_does_not_run_and_is_a_config_skip():
    auditor = run(
        [make_rule("a", RuleSeverity.HIGH, passed=True), make_rule("b", RuleSeverity.CRITICAL, passed=False)],
        config(b=None),
    )

    assert (auditor.score, auditor.max_score) == (3, 3)  # b contributes to neither
    assert [r.rule_id for r in auditor.results] == ["a"]
    assert skip_reasons(auditor) == {"b": SKIP_REASON_DISABLED_BY_CONFIG}
    report = auditor.get_audit_report()
    assert report["config"]["disabled"] == ["b"]
    assert [s["reason"] for s in report["skipped_rules"]] == [SKIP_REASON_DISABLED_BY_CONFIG]


def test_canonical_skip_reason_wins_over_off():
    # A rule the engine could not judge anyway says why, rather than "disabled".
    rule = make_rule("future", RuleSeverity.HIGH, passed=False, min_spec_version="2026-07-28")

    auditor = run([rule], config(future=None))

    assert skip_reasons(auditor) == {"future": SKIP_REASON_NOT_APPLICABLE}


# --- re-rank ------------------------------------------------------------------


def test_reranked_rule_counts_at_the_configured_severity():
    auditor = run(
        [make_rule("a", RuleSeverity.LOW, passed=True), make_rule("b", RuleSeverity.LOW, passed=False)],
        config(a=RuleSeverity.CRITICAL, b=RuleSeverity.HIGH),
    )

    assert (auditor.score, auditor.max_score) == (5, 8)
    by_id = {r.rule_id: r for r in auditor.results}
    assert by_id["a"].severity is RuleSeverity.CRITICAL
    assert by_id["a"].details == {"severity_default": "LOW"}
    report = auditor.get_audit_report()
    assert report["results"][0]["severity"] == "CRITICAL"
    assert report["results"][0]["severity_value"] == 5
    assert report["config"]["reranked"] == {"a": {"from": "LOW", "to": "CRITICAL"}, "b": {"from": "LOW", "to": "HIGH"}}


def test_rerank_to_the_rules_own_severity_is_a_no_op():
    auditor = run([make_rule("a", RuleSeverity.HIGH, passed=True)], config(a=RuleSeverity.HIGH))

    assert auditor.results[0].details is None
    assert auditor.get_audit_report()["config"]["reranked"] == {"a": {"from": "HIGH", "to": "HIGH"}}


def test_rerank_keeps_existing_details_and_basis():
    rule = make_rule("a", RuleSeverity.LOW, passed=False)
    rule.basis = "MCP 2025-11-25 §Test"

    auditor = run([rule], config(a=RuleSeverity.MEDIUM))

    assert auditor.results[0].details == {"basis": "MCP 2025-11-25 §Test", "severity_default": "LOW"}


def test_reranked_rule_that_could_not_run_still_reports_its_default():
    rule = make_rule("future", RuleSeverity.LOW, passed=False, min_spec_version="2026-07-28")

    report = run([rule], config(future=RuleSeverity.CRITICAL)).get_audit_report()

    assert report["config"]["reranked"] == {"future": {"from": "LOW", "to": "CRITICAL"}}


# --- readiness axis -----------------------------------------------------------


def test_readiness_rerank_follows_the_promotion_rule():
    rules = [
        make_rule("main", RuleSeverity.HIGH, passed=True),
        make_rule("ready", RuleSeverity.LOW, passed=True, group_name=READINESS_GROUP),
    ]
    cfg = config(ready=RuleSeverity.CRITICAL)

    legacy = run(rules, cfg, era=Era.LEGACY)
    assert (legacy.score, legacy.max_score) == (3, 3)
    assert (legacy.readiness_score, legacy.readiness_max) == (5, 5)

    modern = run(rules, cfg, era=Era.MODERN)
    assert (modern.score, modern.max_score) == (8, 8)
    assert (modern.readiness_score, modern.readiness_max) == (5, 5)


def test_readiness_rule_can_be_turned_off():
    auditor = run([make_rule("ready", RuleSeverity.HIGH, passed=False, group_name=READINESS_GROUP)], config(ready=None))

    assert (auditor.readiness_score, auditor.readiness_max) == (0, 0)
    assert skip_reasons(auditor) == {"ready": SKIP_REASON_DISABLED_BY_CONFIG}
    assert auditor.get_audit_report()["readiness"]["skipped"] == 1


# --- gate ---------------------------------------------------------------------


def gated(fail_on: RuleSeverity, **overrides: RuleSeverity | None) -> RuleConfig:
    return RuleConfig(source="mcpscore.toml", sha256="abc123", overrides=overrides, fail_on=fail_on)


def test_gate_lists_failed_rules_at_or_above_the_threshold():
    rules = [
        make_rule("crit_fail", RuleSeverity.CRITICAL, passed=False),
        make_rule("high_fail", RuleSeverity.HIGH, passed=False),
        make_rule("high_pass", RuleSeverity.HIGH, passed=True),
        make_rule("low_fail", RuleSeverity.LOW, passed=False),
    ]

    auditor = run(rules, gated(RuleSeverity.HIGH))

    assert auditor.config_gate_failures() == ["crit_fail", "high_fail"]
    assert auditor.get_audit_report()["config"]["gate"] == {"fail_on": "HIGH", "failed": ["crit_fail", "high_fail"]}


def test_gate_sees_reranked_severities_and_ignores_off_rules():
    rules = [
        make_rule("promoted", RuleSeverity.LOW, passed=False),
        make_rule("silenced", RuleSeverity.CRITICAL, passed=False),
    ]

    auditor = run(rules, gated(RuleSeverity.HIGH, promoted=RuleSeverity.CRITICAL, silenced=None))

    assert auditor.config_gate_failures() == ["promoted"]


def test_gate_counts_readiness_only_when_promoted():
    rules = [make_rule("ready", RuleSeverity.CRITICAL, passed=False, group_name=READINESS_GROUP)]

    assert run(rules, gated(RuleSeverity.HIGH), era=Era.LEGACY).config_gate_failures() == []
    assert run(rules, gated(RuleSeverity.HIGH), era=Era.MODERN).config_gate_failures() == ["ready"]


def test_no_gate_means_no_failures_and_no_gate_block():
    auditor = run([make_rule("crit_fail", RuleSeverity.CRITICAL, passed=False)], config())

    assert auditor.config_gate_failures() == []
    assert "gate" not in auditor.get_audit_report()["config"]


# --- report block -------------------------------------------------------------


def test_config_block_records_identity_and_unknown_ids():
    cfg = RuleConfig(source="pyproject.toml", sha256="deadbeef", overrides={"a": None}, unknown=("nope", "old_rule"))

    report = run([make_rule("a", RuleSeverity.LOW, passed=True)], cfg).get_audit_report()

    assert report["config"] == {
        "source": "pyproject.toml",
        "sha256": "deadbeef",
        "disabled": ["a"],
        "reranked": {},
        "unknown": ["nope", "old_rule"],
    }


def test_config_applies_to_partial_audits_too():
    auditor = run([make_rule("a", RuleSeverity.HIGH, passed=True)], config(a=None), partial=True)

    assert skip_reasons(auditor) == {"a": SKIP_REASON_DISABLED_BY_CONFIG}
    assert auditor.get_audit_report()["partial"] is True
