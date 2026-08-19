from mcpscore.enums import MCPProtocolVersion
from mcpscore.probes import (
    GATEWAY_PROBE_IDS,
    PROBE_IDS,
    ProbeOutcome,
    ProbeResult,
    not_applicable_results,
)
from mcpscore.rules import (
    AllowedVersionRule,
    AuditData,
    DeprecatedVersionRule,
    LatestVersionRule,
)
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA


def test_allowed_version_rule_passes_for_known_versions():
    """Test that the allowed version rule passes for all supported MCP protocol versions.

    This test verifies that the AllowedVersionRule correctly identifies
    all versions defined in MCPProtocolVersion enum as valid.
    """
    rule = AllowedVersionRule()
    for version in MCPProtocolVersion:
        data = AuditData(protocol_version=version.value)
        res = rule.check(data)
        assert res.passed


def test_allowed_version_rule_fails_for_unknown_version():
    """Test that the allowed version rule fails for unsupported protocol versions.

    This test verifies that the AllowedVersionRule correctly rejects
    protocol versions that are not in the supported versions list.
    """
    rule = AllowedVersionRule()
    data = AuditData(protocol_version="1900-01-01")
    res = rule.check(data)
    assert not res.passed


def test_latest_version_rule_pass_fail():
    """Test that the latest version rule correctly identifies the most recent protocol version.

    This test verifies that the LatestVersionRule passes only for the latest
    protocol version and fails for older versions.
    """
    rule = LatestVersionRule()
    latest = MCPProtocolVersion.Latest.value
    not_latest = MCPProtocolVersion.v2024_11_05.value

    assert rule.check(AuditData(protocol_version=latest)).passed
    assert not rule.check(AuditData(protocol_version=not_latest)).passed


def test_deprecated_version_rule_default_none_deprecations():
    """Test that the deprecated version rule passes when no versions are marked as deprecated.

    This test verifies that the DeprecatedVersionRule correctly handles
    the default case where no protocol versions are currently deprecated.
    """
    rule = DeprecatedVersionRule()
    res = rule.check(AuditData(protocol_version=MCPProtocolVersion.v2024_11_05.value))
    assert res.passed  # none are deprecated by default


def test_deprecated_version_rule_fails_for_deprecated_version(monkeypatch):
    """A version listed in deprecated_versions must fail the rule."""
    monkeypatch.setattr(DeprecatedVersionRule, "deprecated_versions", ["2024-11-05"])
    rule = DeprecatedVersionRule()

    result = rule.check(AuditData(protocol_version="2024-11-05"))

    assert result.passed is False
    assert "deprecated" in result.message
    assert result.details is not None
    assert result.details["deprecated_versions"] == ["2024-11-05"]


def test_latest_version_rule_passes_for_newer_unreleased_version():
    """A server ahead of the latest final revision is not "behind".

    Uses a date past any published revision: 2026-07-28 became LATEST itself
    when it was published, so it no longer exercises this branch.
    """
    rule = LatestVersionRule()
    result = rule.check(AuditData(protocol_version="2099-01-01"))
    assert result.passed
    assert "newer" in result.message


class TestLatestVersionRuleJudgesEvidence:
    """`protocol_version_latest` asks what the server speaks, not what it negotiated.

    2026-07-28 removed the ``initialize`` handshake, so the latest revision is
    unreachable through version negotiation. Judging the negotiated version
    against it made the rule unpassable for every current server — a MEDIUM
    penalty nobody could avoid. The probes supply the missing evidence.
    """

    @staticmethod
    def _probes(*, modern: bool) -> dict[str, ProbeResult]:
        outcome = ProbeOutcome.SUPPORTED if modern else ProbeOutcome.UNSUPPORTED
        return {
            probe_id: ProbeResult(probe_id, outcome if probe_id in GATEWAY_PROBE_IDS else ProbeOutcome.UNSUPPORTED, {})
            for probe_id in PROBE_IDS
        }

    def test_passes_when_probes_show_modern_support(self):
        """The regression: a handshake-capped server that does speak the latest."""
        rule = LatestVersionRule()
        data = AuditData(protocol_version="2025-11-25", probes=self._probes(modern=True))

        assert rule.skip_reason(data) is None
        result = rule.check(data)
        assert result.passed
        assert result.details["modern_lifecycle_support"] is True

    def test_still_fails_a_server_with_no_modern_support(self):
        """The rule keeps its teeth: probes looked, and found nothing."""
        rule = LatestVersionRule()
        data = AuditData(protocol_version="2025-11-25", probes=self._probes(modern=False))

        assert rule.skip_reason(data) is None
        assert not rule.check(data).passed

    def test_skips_when_no_probe_observed_anything(self):
        """With no evidence either way the rule must not guess.

        Every probe NOT_APPLICABLE is the pre-fix stdio situation; scoring it
        as a failure is precisely the bug.
        """
        rule = LatestVersionRule()
        data = AuditData(
            protocol_version="2025-11-25",
            probes=not_applicable_results("probes did not run"),
        )

        assert rule.skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_a_latest_negotiation_needs_no_probes(self):
        """A server that negotiated the latest is judged without any probe data."""
        rule = LatestVersionRule()
        data = AuditData(protocol_version=MCPProtocolVersion.Latest.value)

        assert rule.skip_reason(data) is None
        assert rule.check(data).passed
