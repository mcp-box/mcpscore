"""Rules for servers advertising the Tasks extension (``io.modelcontextprotocol/tasks``, SEP-2663).

Each rule judges a server whose ``server/discover`` advertises the extension. The probe asks only about a task ID
no server issued, so an audit never reads, changes or cancels a real task.
"""

from __future__ import annotations

from typing import Any

from mcpscore.probes import (
    AUTH_GATED_STATUSES,
    PROBE_TASKS_EXTENSION,
    TASKS_ERROR_MISSING_CLIENT_CAPABILITY,
    TASKS_EXTENSION_ID,
    ProbeOutcome,
    ProbeResult,
)

from .base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_NOT_APPLICABLE,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
)
from .probe_diagnostics import diagnostic_result
from .registry import register_rule
from .skills import discover_capabilities

SEP = "MCP Tasks Extension (SEP-2663, Final)"
TASKS_GROUP = "tasks"

ERROR_INVALID_PARAMS = -32602
ERROR_METHOD_NOT_FOUND = -32601


def advertises_tasks(audit_data: AuditData) -> bool:
    """Whether ``server/discover`` advertised the Tasks extension."""
    extensions = discover_capabilities(audit_data).get("extensions")
    return isinstance(extensions, dict) and TASKS_EXTENSION_ID in extensions


class TasksBaseRule(BaseRule):
    """Base for rules that judge a server advertising the Tasks extension."""

    group_name = TASKS_GROUP
    group_order = 11

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip unless ``server/discover`` advertised the extension."""
        if not advertises_tasks(audit_data):
            return SKIP_REASON_NOT_APPLICABLE
        return None

    def _result(self, *, passed: bool, message: str, details: dict[str, Any], fix: str) -> RuleResult:
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details=details,
            suggested_fix=None if passed else fix,
        )


class _TasksAnswerRule(TasksBaseRule):
    """Base for rules judging one answer of the Tasks probe.

    An answer judges the server only when it is a result or one of ``decisive_codes``. Anything else, such as a
    401 or a server-specific authorization error, says the request was refused before the task was looked up.
    """

    answer_key: str
    decisive_codes: frozenset[int]

    def _answer(self, audit_data: AuditData) -> dict[str, Any] | None:
        probe: ProbeResult | None = (audit_data.probes or {}).get(PROBE_TASKS_EXTENSION)
        if probe is None or probe.outcome is not ProbeOutcome.SUPPORTED:
            return None
        answer = probe.details.get(self.answer_key)
        return answer if isinstance(answer, dict) else None

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when the request was not made or was refused for a reason this rule cannot judge."""
        if reason := super().skip_reason(audit_data):
            return reason
        answer = self._answer(audit_data)
        if answer is None or answer.get("http_status") in AUTH_GATED_STATUSES:
            return SKIP_REASON_INSUFFICIENT_DATA
        if not answer.get("result") and answer.get("error_code") not in self.decisive_codes:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def _observed(self, audit_data: AuditData) -> dict[str, Any]:
        answer = self._answer(audit_data)
        assert answer is not None  # noqa: S101 — guaranteed by skip_reason
        return answer


@register_rule
class TasksGetUnknownRejectedRule(_TasksAnswerRule):
    """Medium check: ``tasks/get`` for a task the server never issued answers ``-32602``."""

    rule_id = "tasks_get_unknown_rejected"
    basis = f"{SEP} §Error Handling (an invalid or nonexistent taskId MUST return -32602 for tasks/get)"
    rule_order = 1
    answer_key = "get_unknown"
    decisive_codes = frozenset({ERROR_INVALID_PARAMS, ERROR_METHOD_NOT_FOUND})

    @property
    def rule_name(self) -> str:
        return "Tasks - tasks/get Refuses Unknown Tasks"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: an unknown task ID is refused with JSON-RPC ``-32602`` (Invalid params)."""
        answer = self._observed(audit_data)
        passed = not answer["result"] and answer["error_code"] == ERROR_INVALID_PARAMS
        if passed:
            message = "✅ tasks/get refused a task ID the server never issued with -32602"
        elif answer["result"]:
            message = "❌ tasks/get returned a result for a task ID the server never issued"
        else:
            message = "❌ tasks/get answered Method not found (-32601) although the server advertises Tasks"
        return self._result(
            passed=passed,
            message=message,
            details={"answer": answer},
            fix=(
                "Implement tasks/get, and answer it with JSON-RPC error -32602 (Invalid params) when the taskId "
                "names no task the caller can see."
            ),
        )


@register_rule
class TasksUndeclaredClientRejectedRule(_TasksAnswerRule):
    """Low check: ``tasks/get`` from a client that did not declare the extension answers ``-32021``."""

    rule_id = "tasks_undeclared_client_rejected"
    basis = (
        f"{SEP} §Error Handling (servers MUST return -32021 Missing Required Client Capability for non-declaring "
        "clients issuing tasks/get, tasks/update and tasks/cancel)"
    )
    rule_order = 2
    answer_key = "get_undeclared"
    decisive_codes = frozenset({TASKS_ERROR_MISSING_CLIENT_CAPABILITY, ERROR_INVALID_PARAMS, ERROR_METHOD_NOT_FOUND})

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Also skip a server that serves no ``tasks/get`` at all; ``tasks_get_unknown_rejected`` judges that."""
        if reason := super().skip_reason(audit_data):
            return reason
        probe = (audit_data.probes or {}).get(PROBE_TASKS_EXTENSION)
        declared = probe.details.get("get_unknown") if probe is not None else None
        if isinstance(declared, dict) and declared.get("error_code") == ERROR_METHOD_NOT_FOUND:
            return SKIP_REASON_NOT_APPLICABLE
        return None

    @property
    def rule_name(self) -> str:
        return "Tasks - Undeclared Clients Get -32021"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def check(self, audit_data: AuditData) -> RuleResult:
        """Low check: the missing client capability is reported before the task ID is looked up."""
        answer = self._observed(audit_data)
        code = answer["error_code"]
        passed = not answer["result"] and code == TASKS_ERROR_MISSING_CLIENT_CAPABILITY
        if passed:
            message = "✅ tasks/get from a client without the Tasks extension was refused with -32021"
        elif answer["result"]:
            message = "❌ tasks/get returned a result to a client that did not declare the Tasks extension"
        else:
            message = (
                f"❌ tasks/get from a client without the Tasks extension was answered with {code}, not -32021 "
                "(Missing Required Client Capability)"
            )
        return self._result(
            passed=passed,
            message=message,
            details={"answer": answer},
            fix=(
                "Check the request's clientCapabilities first: when it does not declare "
                f"{TASKS_EXTENSION_ID}, answer tasks/get, tasks/update and tasks/cancel with JSON-RPC error -32021 "
                "and name the extension in data.requiredCapabilities."
            ),
        )


@register_rule
class TasksResultMethodRemovedRule(_TasksAnswerRule):
    """Low check: the 2025-11-25 ``tasks/result`` method answers ``-32601`` (Method not found)."""

    rule_id = "tasks_result_method_removed"
    basis = f"{SEP} §Backward Compatibility (tasks/result is removed; clients calling it MUST receive -32601)"
    rule_order = 3
    answer_key = "result_method"
    decisive_codes = frozenset({ERROR_METHOD_NOT_FOUND, ERROR_INVALID_PARAMS})

    @property
    def rule_name(self) -> str:
        return "Tasks - tasks/result Is Removed"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def check(self, audit_data: AuditData) -> RuleResult:
        """Low check: ``tasks/result`` is not served on the protocol version that carries the extension."""
        answer = self._observed(audit_data)
        passed = not answer["result"] and answer["error_code"] == ERROR_METHOD_NOT_FOUND
        message = (
            "✅ tasks/result answered Method not found (-32601), as the Tasks extension requires"
            if passed
            else "❌ tasks/result is still served alongside the Tasks extension; it MUST answer -32601"
        )
        return self._result(
            passed=passed,
            message=message,
            details={"answer": answer},
            fix=(
                "Stop serving the 2025-11-25 tasks/result method on protocol versions with the Tasks extension: "
                "answer it with JSON-RPC error -32601 (Method not found). The final result is in tasks/get."
            ),
        )


@register_rule
class TasksLegacyCapabilityRemovedRule(TasksBaseRule):
    """Low check: a server advertising the extension no longer advertises the 2025-11-25 ``tasks`` capability."""

    rule_id = "tasks_legacy_capability_removed"
    basis = (
        f"{SEP} §Backward Compatibility (servers MUST NOT continue to advertise the legacy tasks capabilities "
        "under any protocol version that includes this extension)"
    )
    rule_order = 4

    @property
    def rule_name(self) -> str:
        return "Tasks - No Legacy tasks Capability"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def check(self, audit_data: AuditData) -> RuleResult:
        """Low check: ``server/discover`` carries ``extensions["io.modelcontextprotocol/tasks"]`` without ``tasks``."""
        legacy = discover_capabilities(audit_data).get("tasks")
        passed = legacy is None
        message = (
            "✅ server/discover advertises the Tasks extension without the legacy tasks capability"
            if passed
            else "❌ server/discover still advertises the 2025-11-25 tasks capability next to the Tasks extension"
        )
        return self._result(
            passed=passed,
            message=message,
            details={"legacy_tasks_capability": legacy is not None},
            fix=(
                "Remove capabilities.tasks from the server/discover result; advertise only "
                f'capabilities.extensions["{TASKS_EXTENSION_ID}"].'
            ),
        )
