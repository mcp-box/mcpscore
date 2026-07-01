from mcpscore.rules import (
    AuditData,
    RuleSeverity,
    ServerInstructionsPresentRule,
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


def test_server_instructions_present_rule():
    rule = ServerInstructionsPresentRule()
    assert rule.rule_id == "server_instructions_present"
    assert rule.severity == RuleSeverity.LOW
    assert rule.check(AuditData(instructions="Use tool X to do Y.")).passed
    # Missing, empty, and whitespace-only instructions all fail.
    assert not rule.check(AuditData(instructions=None)).passed
    assert not rule.check(AuditData(instructions="")).passed
    assert not rule.check(AuditData(instructions="   ")).passed
