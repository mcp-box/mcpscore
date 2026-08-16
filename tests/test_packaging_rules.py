"""Tests for the packaging rule pack and the ``audit_package`` entry point.

The pack's defining property is that it is a *different target type*, not a
different aspect of the same one: a package audit runs the packaging rules and
nothing else, and a server audit runs everything else and no packaging rules.
Several tests below exist only to pin that partition, because losing it would
silently add six not-applicable skips to every server report — and would churn
every acceptance snapshot and live baseline in the process.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from mcpscore.mcp_auditor import MCPAuditor
from mcpscore.packages import PackageCoordinate, PackageMetadata, PackageOutcome
from mcpscore.rules import AuditData, create_all_rules
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE
from mcpscore.rules.packaging import PACKAGING_GROUP

NPM_COORDINATE = PackageCoordinate.parse("npm:@scope/server")


def _metadata(**overrides) -> PackageMetadata:
    """Build a fully-populated, everything-passes package, minus any overrides."""
    defaults = {
        "coordinate": NPM_COORDINATE,
        "outcome": PackageOutcome.OK,
        "resolved_version": "2.0.0",
        "description": "An example MCP server",
        "license": "MIT",
        "repository_url": "https://github.com/example/server",
        "published_at": datetime(2026, 8, 1, tzinfo=UTC),
    }
    return PackageMetadata(**{**defaults, **overrides})


def _packaging_rules():
    return [rule for rule in create_all_rules() if rule.group_name == PACKAGING_GROUP]


def _run(package: PackageMetadata | None) -> dict[str, object]:
    """Run every packaging rule against one package; return rule_id -> passed/skip."""
    audit_data = AuditData(package=package)
    outcome: dict[str, object] = {}
    for rule in _packaging_rules():
        skip = rule.skip_reason(audit_data)
        outcome[rule.rule_id] = skip if skip is not None else rule.check(audit_data).passed
    return outcome


class TestRuleOutcomes:
    def test_a_well_published_package_passes_everything(self):
        assert _run(_metadata()) == {
            "package_resolves": True,
            "package_version_resolves": True,
            "package_not_withdrawn": True,
            "package_repository_declared": True,
            "package_license_declared": True,
            "package_description_present": True,
        }

    @pytest.mark.parametrize(
        ("field", "rule_id"),
        [
            ("repository_url", "package_repository_declared"),
            ("license", "package_license_declared"),
            ("description", "package_description_present"),
        ],
    )
    def test_each_missing_field_fails_exactly_its_own_rule(self, field, rule_id):
        results = _run(_metadata(**{field: None}))

        assert results[rule_id] is False
        # One missing field must cost one rule, not cascade into its neighbours.
        assert [k for k, v in results.items() if v is False] == [rule_id]

    def test_a_pinned_version_that_exists_passes(self):
        results = _run(
            _metadata(coordinate=PackageCoordinate.parse("npm:@scope/server@2.0.0"), resolved_version="2.0.0")
        )

        assert results["package_version_resolves"] is True

    def test_withdrawn_release_fails_only_the_withdrawal_rule(self):
        results = _run(_metadata(yanked=True))

        assert [k for k, v in results.items() if v is False] == ["package_not_withdrawn"]

    def test_missing_package_fails_resolution_and_skips_the_rest(self):
        results = _run(_metadata(outcome=PackageOutcome.NOT_FOUND, resolved_version=None))

        assert results["package_resolves"] is False
        # A package that does not exist must cost one rule, not six: the other
        # five have nothing to observe.
        assert results["package_version_resolves"] == SKIP_REASON_INSUFFICIENT_DATA
        assert results["package_license_declared"] == SKIP_REASON_INSUFFICIENT_DATA
        assert results["package_repository_declared"] == SKIP_REASON_INSUFFICIENT_DATA

    def test_missing_version_fails_only_the_version_rule(self):
        results = _run(
            _metadata(
                coordinate=PackageCoordinate.parse("npm:@scope/server@9.9.9"),
                outcome=PackageOutcome.VERSION_NOT_FOUND,
                resolved_version=None,
                description=None,
                license=None,
                repository_url=None,
            )
        )

        assert results["package_resolves"] is True
        assert results["package_version_resolves"] is False
        # The regression this pins: the descriptive rules must SKIP, not fail.
        # Their fields are empty because nothing was fetched for a version that
        # does not exist, which is not the publisher's fault.
        for rule_id in ("package_not_withdrawn", "package_repository_declared", "package_license_declared"):
            assert results[rule_id] == SKIP_REASON_INSUFFICIENT_DATA

    def test_fetch_error_skips_every_rule_including_resolution(self):
        results = _run(_metadata(outcome=PackageOutcome.ERROR, resolved_version=None))

        # A network failure is a finding about the network. Reporting "this
        # package does not exist" because npm was briefly unreachable would be
        # a false accusation against the publisher.
        assert set(results.values()) == {SKIP_REASON_INSUFFICIENT_DATA}


class TestTargetTypePartition:
    def test_packaging_rules_are_not_applicable_without_a_package(self):
        for rule in _packaging_rules():
            assert rule.skip_reason(AuditData()) == SKIP_REASON_NOT_APPLICABLE

    def test_a_server_audit_runs_no_packaging_rules(self):
        auditor = MCPAuditor()
        auditor.audit_data = AuditData(protocol_version="2025-11-25")

        selected = auditor._rules_for_target()

        assert selected, "a server audit must still run its own rules"
        assert not [rule for rule in selected if rule.group_name == PACKAGING_GROUP]

    def test_a_package_audit_runs_only_packaging_rules(self):
        auditor = MCPAuditor()
        auditor.audit_data = AuditData(package=_metadata())

        selected = auditor._rules_for_target()

        assert {rule.group_name for rule in selected} == {PACKAGING_GROUP}
        assert len(selected) == len(_packaging_rules())

    def test_the_two_rule_sets_are_disjoint_and_together_are_everything(self):
        all_rules = list(create_all_rules())
        packaging = {r.rule_id for r in all_rules if r.group_name == PACKAGING_GROUP}
        server = {r.rule_id for r in all_rules if r.group_name != PACKAGING_GROUP}

        assert packaging
        assert server
        assert packaging.isdisjoint(server)
        assert packaging | server == {r.rule_id for r in all_rules}


class TestAuditPackage:
    async def test_scores_and_reports_a_package(self, monkeypatch):
        async def fake_fetch(coordinate, client=None):
            return _metadata(coordinate=coordinate)

        monkeypatch.setattr("mcpscore.mcp_auditor.fetch_package_metadata", fake_fetch)
        auditor = MCPAuditor()

        score, max_score = await auditor.audit_package(NPM_COORDINATE)
        report = auditor.get_audit_report()

        assert (score, max_score) == (16, 16)
        assert report["package"] == {
            "registry": "npm",
            "identifier": "@scope/server",
            "requested_version": None,
            "resolved_version": "2.0.0",
            "outcome": "ok",
            "error": None,
            "repository_url": "https://github.com/example/server",
            "license": "MIT",
            "published_at": "2026-08-01T00:00:00+00:00",
            "withdrawn": False,
            # The load-bearing claim of this whole path.
            "executed": False,
        }
        assert len(report["results"]) == 6
        assert report["readiness"]["max_score"] == 0

    async def test_a_missing_package_scores_only_the_resolution_rule(self, monkeypatch):
        """Covers the no-resolved-version path through audit_package's logging."""

        async def fake_fetch(coordinate, client=None):
            return PackageMetadata(coordinate=coordinate, outcome=PackageOutcome.NOT_FOUND)

        monkeypatch.setattr("mcpscore.mcp_auditor.fetch_package_metadata", fake_fetch)
        auditor = MCPAuditor()

        score, max_score = await auditor.audit_package(NPM_COORDINATE)
        report = auditor.get_audit_report()

        # 0 of the 5-point CRITICAL resolution rule; the other five skipped, so
        # they are absent from the denominator entirely.
        assert (score, max_score) == (0, 5)
        assert report["package"]["outcome"] == "not-found"
        assert report["package"]["resolved_version"] is None
        assert len(report["skipped_rules"]) == 5

    async def test_server_audits_report_no_package_section(self, monkeypatch):
        auditor = MCPAuditor()
        auditor.audit_data = AuditData(protocol_version="2025-11-25")

        assert auditor.get_audit_report()["package"] is None

    async def test_a_reused_auditor_does_not_leak_a_package_into_a_server_audit(self, monkeypatch):
        async def fake_fetch(coordinate, client=None):
            return _metadata(coordinate=coordinate)

        monkeypatch.setattr("mcpscore.mcp_auditor.fetch_package_metadata", fake_fetch)
        auditor = MCPAuditor()
        await auditor.audit_package(NPM_COORDINATE)

        # _reset_run_state must clear audit_data, or the next server audit would
        # run the packaging rules against a stale package and none of its own.
        auditor._reset_run_state()

        assert auditor.audit_data.package is None
        assert not [r for r in auditor._rules_for_target() if r.group_name == PACKAGING_GROUP]
