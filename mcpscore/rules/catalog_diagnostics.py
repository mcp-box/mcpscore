"""Build bounded catalog evidence without copying publisher-controlled values."""

from collections.abc import Callable, Iterable
import json
from typing import Any, TypeVar

from mcpscore.diagnostics import entity_label

from .base import RuleResult, RuleSeverity

T = TypeVar("T")


def field_issue(kind: str, index: int | None, path: str, reason: str, expected: str) -> dict[str, Any]:
    """Identify a field relative to its catalog item, or to server metadata."""
    issue: dict[str, Any] = {"entity_kind": kind, "reason": reason, "expected": expected}
    if index is not None:
        issue["entity_index"] = index
    if len(path) <= 255:
        issue["path"] = path
    else:
        issue["path_omitted"] = True
    return issue


def pointer_token(value: str) -> str:
    """Escape one JSON Pointer token without altering its Unicode contents."""
    return value.replace("~", "~0").replace("/", "~1")


def catalog_result(
    *,
    rule_name: str,
    severity: RuleSeverity,
    passed: bool,
    message: str,
    details: dict[str, Any],
    suggested_fix: str,
    issues: Iterable[dict[str, Any]],
    recommendation: bool = False,
) -> RuleResult:
    """Add failure-only guidance while preserving verdicts and legacy evidence.

    Paths are relative to the indexed item, not the paginated wire response.
    New evidence omits names, URI values and schema values deliberately: indexes
    disambiguate duplicate identifiers without echoing secrets or image payloads.
    Existing detail keys remain available to older consumers.
    """
    message = message.rstrip(".") + "."
    if not passed:
        bounded: list[dict[str, Any]] = []
        total = 0
        for issue in issues:
            total += 1
            if len(bounded) < 20:
                bounded.append(issue)
        details = {**details, "issues": bounded, "issues_total": total, "issues_omitted": total - len(bounded)}
        if recommendation:
            message += " This is an optional quality recommendation."
        if bounded:
            first = bounded[0]
            location = entity_label(first.get("entity_kind")).lower()
            if "entity_index" in first:
                location += f" at index {first['entity_index']}"
            if "path" in first:
                location += " " + json.dumps(first["path"], ensure_ascii=True)
            message += f" First affected field: {location}."
    return RuleResult(
        rule_name=rule_name,
        severity=severity,
        passed=passed,
        message=message,
        details=details,
        suggested_fix=suggested_fix if not passed else None,
    )


def fields(
    items: Iterable[T], kind: str, path: str, reason: str, expected: str, invalid: Callable[[T], bool]
) -> Iterable[dict[str, Any]]:
    """Yield indexed evidence for each item matching an existing predicate."""
    for index, item in enumerate(items):
        if invalid(item):
            yield field_issue(kind, index, path, reason, expected)
