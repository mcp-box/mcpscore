"""Format protocol findings and safe observations without changing rule verdicts."""

from collections.abc import Iterable
import json
from typing import Any

from mcpscore.diagnostics import entity_label
from mcpscore.report_evidence import report_evidence

from .base import AuditData, RuleResult, RuleSeverity


def diagnostic_result(
    *,
    rule_name: str,
    severity: RuleSeverity,
    passed: bool,
    message: str,
    details: dict[str, Any],
    suggested_fix: str | None,
    audit_data: AuditData | None = None,
    expected: dict[str, Any] | None = None,
    issues: Iterable[dict[str, Any]] = (),
) -> RuleResult:
    """Attach failure-only repairs and safe, explicitly observed response context."""
    evidence = report_evidence(details)
    message = message.rstrip().rstrip(".") + "."
    if not passed:
        if expected is not None:
            evidence["expected"] = expected.copy()
        bounded = []
        total = 0
        for issue in issues:
            total += 1
            if len(bounded) < 20:
                bounded.append(issue)
        if total:
            evidence.update(issues=bounded, issues_total=total, issues_omitted=total - len(bounded))
            first = bounded[0]
            location = entity_label(first.get("entity_kind")).lower()
            if "entity_index" in first:
                location += f" at index {first['entity_index']}"
            if "probe_id" in first:
                location += f" from {first['probe_id']}"
            if "path" in first:
                location += " " + json.dumps(first["path"], ensure_ascii=True)
            message += f" First affected field: {location}."
        observed = []
        for key, label in (("error_code", "JSON-RPC error code"), ("http_status", "HTTP status")):
            if key in details:
                value = details[key]
                # Never print a server-controlled malformed error-code value.
                display = str(value) if type(value) is int else "not observed" if value is None else "invalid type"
                observed.append(f"{label}: {display}")
        if observed:
            message += " Observed " + "; ".join(observed) + "."
        if audit_data is not None:
            evidence["context"] = {
                "protocol_version": audit_data.protocol_version,
                "session_protocol_version": audit_data.session_protocol_version,
                "transport_type": audit_data.transport_type,
            }
    return RuleResult(
        rule_name=rule_name,
        severity=severity,
        passed=passed,
        message=message,
        details=evidence,
        suggested_fix=None if passed else suggested_fix,
    )
