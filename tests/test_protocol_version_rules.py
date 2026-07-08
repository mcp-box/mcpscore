from mcpscore.enums import MCPProtocolVersion
from mcpscore.rules import (
    AllowedVersionRule,
    AuditData,
    DeprecatedVersionRule,
    LatestVersionRule,
)


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


def test_latest_version_rule_passes_for_newer_draft_version():
    """A server on a spec revision newer than the latest final one is not "behind"."""
    rule = LatestVersionRule()
    result = rule.check(AuditData(protocol_version="2026-07-28"))
    assert result.passed
    assert "newer" in result.message
