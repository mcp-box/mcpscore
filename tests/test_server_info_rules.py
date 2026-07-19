from dataclasses import replace

from mcpscore.rules import (
    AuditData,
    RuleSeverity,
    ServerIconsPresentRule,
    ServerInstructionsPresentRule,
    ServerNamePresentRule,
    ServerTitlePresentRule,
    ServerVersionPresentRule,
    ServerWebsiteUrlPresentRule,
)


def test_server_name_present_rule(implementation_full, implementation_missing):
    rule = ServerNamePresentRule()
    assert rule.check(AuditData(server_info=implementation_full)).passed
    assert not rule.check(AuditData(server_info=implementation_missing)).passed


def test_server_title_present_rule(implementation_full, implementation_missing):
    rule = ServerTitlePresentRule()
    assert rule.check(AuditData(server_info=implementation_full)).passed
    assert not rule.check(AuditData(server_info=implementation_missing)).passed


def test_server_version_present_rule(implementation_full, implementation_missing):
    rule = ServerVersionPresentRule()
    assert rule.check(AuditData(server_info=implementation_full)).passed
    assert not rule.check(AuditData(server_info=implementation_missing)).passed


def test_server_instructions_present_rule():
    rule = ServerInstructionsPresentRule()
    assert rule.rule_id == "server_instructions_present"
    assert rule.severity == RuleSeverity.LOW
    assert rule.check(AuditData(instructions="Use tool X to do Y.")).passed
    # Missing, empty, and whitespace-only instructions all fail.
    assert not rule.check(AuditData(instructions=None)).passed
    assert not rule.check(AuditData(instructions="")).passed
    assert not rule.check(AuditData(instructions="   ")).passed


def test_server_websiteurl_present_rule(implementation_full, implementation_missing):
    rule = ServerWebsiteUrlPresentRule()
    assert rule.rule_id == "server_websiteurl_present"
    assert rule.min_spec_version == "2025-11-25"
    with_url = replace(implementation_full, website_url="https://server.example")
    assert rule.check(AuditData(server_info=with_url)).passed
    assert not rule.check(AuditData(server_info=implementation_full)).passed
    assert not rule.check(AuditData(server_info=implementation_missing)).passed


def test_server_icons_present_rule(implementation_full, implementation_missing):
    from mcp_types import Icon

    rule = ServerIconsPresentRule()
    assert rule.rule_id == "server_icons_present"
    assert rule.min_spec_version == "2025-11-25"

    valid = replace(implementation_full, icons=[Icon(src="https://server.example/icon.png")])
    assert rule.check(AuditData(server_info=valid)).passed

    data_uri = replace(implementation_full, icons=[Icon(src="data:image/png;base64,AAAA")])
    assert rule.check(AuditData(server_info=data_uri)).passed

    # No icons at all fails.
    no_icons = rule.check(AuditData(server_info=implementation_missing))
    assert not no_icons.passed
    assert "no icons" in no_icons.message

    # A plain-http src is not a valid icon source.
    invalid = replace(implementation_full, icons=[Icon(src="http://server.example/icon.png")])
    result = rule.check(AuditData(server_info=invalid))
    assert not result.passed
    assert result.details is not None
    assert result.details["invalid_srcs"] == ["http://server.example/icon.png"]
