from mcpscore.enums import MCPProtocolVersion
from mcpscore.probes import (
    GATEWAY_PROBE_IDS,
    PROBE_DISCOVER,
    PROBE_IDS,
    PROBE_UNAUTHENTICATED,
    ProbeOutcome,
    ProbeResult,
    not_applicable_results,
)
from mcpscore.rules import (
    AllowedVersionRule,
    AuditData,
    DeprecatedVersionRule,
    LatestVersionRule,
    SupportedVersionsExhaustiveRule,
)
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE


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

    def test_skips_when_no_protocol_version_was_observed(self):
        """An unreachable target has no version to judge and must not fail."""
        data = AuditData(protocol_version=None)

        assert LatestVersionRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_defensive_check_result_when_protocol_version_is_missing(self):
        """Direct callers still receive a clear failure after bypassing applicability."""
        result = LatestVersionRule().check(AuditData(protocol_version=None))

        assert result.passed is False
        assert result.details == {"protocol_version": None}

    def test_unrelated_probe_does_not_make_the_gateway_observable(self):
        """An HTTP/auth observation cannot prove absence of modern support."""
        probes = not_applicable_results("not observed")
        probes[PROBE_UNAUTHENTICATED] = ProbeResult(
            PROBE_UNAUTHENTICATED,
            ProbeOutcome.SUPPORTED,
            {"http_status": 401},
        )
        data = AuditData(protocol_version="2025-11-25", probes=probes)

        assert LatestVersionRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_a_latest_negotiation_needs_no_probes(self):
        """A server that negotiated the latest is judged without any probe data."""
        rule = LatestVersionRule()
        data = AuditData(protocol_version=MCPProtocolVersion.Latest.value)

        assert rule.skip_reason(data) is None
        assert rule.check(data).passed


class TestSupportedVersionsExhaustiveRule:
    """Dual-era cross-check: discover's supportedVersions vs the legacy handshake."""

    @staticmethod
    def _data(
        session_version: str | None = "2025-11-25",
        discover: ProbeResult | None = None,
    ) -> AuditData:
        probes: dict[str, ProbeResult] | None = None
        if discover is not None:
            probes = {PROBE_DISCOVER: discover}
        return AuditData(
            protocol_version=session_version,
            session_protocol_version=session_version,
            probes=probes,
        )

    def test_passes_when_the_legacy_version_is_listed(self):
        """A discover list containing the handshake's version is exhaustive."""
        discover = ProbeResult(
            PROBE_DISCOVER,
            ProbeOutcome.SUPPORTED,
            {"supported_versions": ["2026-07-28", "2025-11-25"]},
        )
        rule = SupportedVersionsExhaustiveRule()
        data = self._data(discover=discover)

        assert rule.skip_reason(data) is None
        result = rule.check(data)
        assert result.passed
        assert result.details["supported_versions"] == ["2026-07-28", "2025-11-25"]

    def test_fails_when_a_served_legacy_version_is_omitted(self):
        """Serving initialize at a version discover omits is the finding (huggingface.co/mcp posture)."""
        discover = ProbeResult(
            PROBE_DISCOVER,
            ProbeOutcome.SUPPORTED,
            {"supported_versions": ["2026-07-28"]},
        )
        rule = SupportedVersionsExhaustiveRule()
        data = self._data(discover=discover)

        assert rule.skip_reason(data) is None
        result = rule.check(data)
        assert not result.passed
        assert "2025-11-25" in result.message
        assert result.details["session_protocol_version"] == "2025-11-25"

    def test_skips_modern_only_servers(self):
        """No legacy handshake -> nothing to cross-check (session provenance is the gate)."""
        discover = ProbeResult(
            PROBE_DISCOVER,
            ProbeOutcome.SUPPORTED,
            {"supported_versions": ["2026-07-28"]},
        )
        data = self._data(session_version=None, discover=discover)

        assert SupportedVersionsExhaustiveRule().skip_reason(data) == SKIP_REASON_NOT_APPLICABLE

    def test_skips_legacy_only_servers(self):
        """Discover UNSUPPORTED (or absent) means no modern surface to be inconsistent with."""
        rule = SupportedVersionsExhaustiveRule()

        assert rule.skip_reason(self._data(discover=None)) == SKIP_REASON_NOT_APPLICABLE
        unsupported = ProbeResult(PROBE_DISCOVER, ProbeOutcome.UNSUPPORTED, {"http_status": 404})
        assert rule.skip_reason(self._data(discover=unsupported)) == SKIP_REASON_NOT_APPLICABLE

    def test_discover_error_is_insufficient_data(self):
        """A network-failed discover cannot judge the list either way."""
        errored = ProbeResult(PROBE_DISCOVER, ProbeOutcome.ERROR, {"exception": "TimeoutError"})

        assert (
            SupportedVersionsExhaustiveRule().skip_reason(self._data(discover=errored)) == SKIP_REASON_INSUFFICIENT_DATA
        )
