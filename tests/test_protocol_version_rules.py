from mcpdoctor.enums import MCPProtocolVersion
from mcpdoctor.rules import (
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
