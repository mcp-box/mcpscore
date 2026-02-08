from mcpaudit.rules import (
    AuditData,
    ServerNamePresentRule,
    ServerTitlePresentRule,
    ServerVersionPresentRule,
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
