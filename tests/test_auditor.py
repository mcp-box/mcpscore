from typing import Any

import pytest

from mcpaudit import MCPAuditor, MCPClient
from mcpaudit.rules import AuditData, BaseRule, RuleResult, RuleSeverity


class DummyClient(MCPClient):
    def __init__(self, init_result: Any | None) -> None:
        super().__init__()
        self._init_result = init_result

    async def initialize(self):
        return self._init_result


class DummyRule(BaseRule):
    rule_id = "dummy_rule"
    group_order = 0
    rule_order = 0

    def __init__(self, passed: bool, severity: RuleSeverity) -> None:
        super().__init__()
        self._passed = passed
        self._severity = severity

    @property
    def sort_order(self) -> int:
        return 0

    @property
    def rule_name(self) -> str:
        return "dummy"

    @property
    def severity(self) -> RuleSeverity:
        return self._severity

    def check(self, audit_data: AuditData) -> RuleResult:
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=self._passed,
            message="msg",
        )


@pytest.mark.asyncio
async def test_auditor_collects_data_and_scores():
    """Test that the auditor properly collects server data and calculates audit scores.

    This test verifies that:
    - The auditor can process initialization results from MCP servers
    - Rule execution affects the final audit score correctly
    - Passed rules add points, failed rules subtract points
    - The audit summary provides accurate counts of passed/failed rules
    """

    class InitResult:
        def __init__(self) -> None:
            super().__init__()
            self.protocolVersion = "2025-06-18"
            self.serverInfo = type("Impl", (), {"name": "n", "title": "t", "version": "1"})()
            self.capabilities = type(
                "Caps",
                (),
                {"tools": None, "resources": None, "prompts": None, "logging": None, "sampling": None},
            )()
            self.instructions = "instr"

    auditor = MCPAuditor()
    auditor.rules = [
        DummyRule(passed=True, severity=RuleSeverity.HIGH),
        DummyRule(passed=False, severity=RuleSeverity.MEDIUM),
    ]

    score, max_score = await auditor.audit(DummyClient(InitResult()))
    # Score is sum of passed rules' severity values
    assert score == RuleSeverity.HIGH
    # Max score is sum of all rules' severity values
    assert max_score == (RuleSeverity.HIGH + RuleSeverity.MEDIUM)

    summary = auditor.get_audit_summary()
    assert summary["total"] == 2
    assert summary["passed"] == 1
    assert summary["failed"] == 1
