"""Tests for spec-version rule applicability and auditor skip behavior."""

from mcpscore.mcp_auditor import MCPAuditor
from mcpscore.rules import AuditData, BaseRule, RuleResult, RuleSeverity
from mcpscore.rules.base import SKIP_REASON_NOT_APPLICABLE, SkippedRule


class VersionedRule(BaseRule):
    """Minimal always-passing rule with a configurable spec-version range."""

    rule_id = "versioned_rule"

    def __init__(
        self,
        min_spec_version: str | None = None,
        max_spec_version: str | None = None,
        rule_id: str = "versioned_rule",
    ) -> None:
        super().__init__()
        self.min_spec_version = min_spec_version
        self.max_spec_version = max_spec_version
        self.rule_id = rule_id

    @property
    def rule_name(self) -> str:
        return "versioned"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def check(self, audit_data: AuditData) -> RuleResult:
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=True,
            message="ok",
        )


class TestAppliesTo:
    def test_open_range_applies_to_everything(self):
        rule = VersionedRule()
        assert rule.applies_to("2024-11-05")
        assert rule.applies_to("2026-07-28")

    def test_none_version_always_applies(self):
        """A missing negotiated version must not silently skip rules."""
        rule = VersionedRule(min_spec_version="2026-07-28")
        assert rule.applies_to(None)

    def test_min_version_excludes_older_servers(self):
        rule = VersionedRule(min_spec_version="2026-07-28")
        assert not rule.applies_to("2025-11-25")
        assert rule.applies_to("2026-07-28")

    def test_max_version_excludes_newer_servers(self):
        rule = VersionedRule(max_spec_version="2025-11-25")
        assert rule.applies_to("2025-11-25")
        assert not rule.applies_to("2026-07-28")

    def test_bounds_are_inclusive(self):
        rule = VersionedRule(min_spec_version="2025-03-26", max_spec_version="2025-11-25")
        assert rule.applies_to("2025-03-26")
        assert rule.applies_to("2025-06-18")
        assert rule.applies_to("2025-11-25")
        assert not rule.applies_to("2024-11-05")
        assert not rule.applies_to("2026-07-28")


class TestAuditorSkipsNonApplicableRules:
    def _run(self, protocol_version: str | None, rules: list[BaseRule]) -> MCPAuditor:
        auditor = MCPAuditor()
        auditor.rules = rules
        auditor.audit_data = AuditData(protocol_version=protocol_version)
        auditor._run_all_rules()
        return auditor

    def test_non_applicable_rule_is_skipped_and_excluded_from_scores(self):
        auditor = self._run(
            "2025-11-25",
            [
                VersionedRule(rule_id="always_applies"),
                VersionedRule(min_spec_version="2026-07-28", rule_id="modern_only"),
            ],
        )

        assert [r.rule_id for r in auditor.results] == ["always_applies"]
        assert auditor.score == RuleSeverity.HIGH
        assert auditor.max_score == RuleSeverity.HIGH
        assert auditor.skipped_rules == [
            SkippedRule(rule_id="modern_only", rule_name="versioned", reason=SKIP_REASON_NOT_APPLICABLE)
        ]

    def test_applicable_rule_runs_on_matching_version(self):
        auditor = self._run("2026-07-28", [VersionedRule(min_spec_version="2026-07-28", rule_id="modern_only")])

        assert [r.rule_id for r in auditor.results] == ["modern_only"]
        assert auditor.skipped_rules == []

    def test_none_version_runs_all_rules(self):
        auditor = self._run(None, [VersionedRule(min_spec_version="2026-07-28", rule_id="modern_only")])

        assert [r.rule_id for r in auditor.results] == ["modern_only"]
        assert auditor.skipped_rules == []

    def test_report_includes_skipped_rules(self):
        auditor = self._run(
            "2025-11-25",
            [VersionedRule(min_spec_version="2026-07-28", rule_id="modern_only")],
        )

        report = auditor.get_audit_report()
        assert report["results"] == []
        assert report["skipped_rules"] == [
            {
                "rule_id": "modern_only",
                "rule_name": "versioned",
                "reason": SKIP_REASON_NOT_APPLICABLE,
                "group_name": "default",
            }
        ]
        assert report["summary"]["skipped"] == 1
        assert report["summary"]["total"] == 0

    def test_report_skipped_rules_empty_when_all_apply(self):
        auditor = self._run("2025-11-25", [VersionedRule(rule_id="always_applies")])

        report = auditor.get_audit_report()
        assert report["skipped_rules"] == []
        assert report["summary"]["skipped"] == 0
