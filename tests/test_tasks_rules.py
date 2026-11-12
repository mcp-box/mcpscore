"""Tasks extension (SEP-2663): the unknown-task probe and the rules judging its answers."""

import json
from typing import Any

import httpx2
import pytest

from mcpscore.enums import MCPTransportType
from mcpscore.probes import (
    PROBE_DISCOVER,
    PROBE_TASKS_EXTENSION,
    TASKS_EXTENSION_ID,
    UNKNOWN_TASK_PREFIX,
    ProbeOutcome,
    ProbeResult,
    _HttpTarget,
    _probe_tasks_extension,
)
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE, AuditData, RuleSeverity
from mcpscore.rules.registry import create_all_rules

URL = "https://example.com/mcp"
RULES = {rule.rule_id: rule for rule in create_all_rules() if rule.group_name == "tasks"}
CAPABILITIES_META = "io.modelcontextprotocol/clientCapabilities"


def answer(*, code: int | None = None, result: bool = False, http_status: int = 200) -> dict[str, Any]:
    return {"http_status": http_status, "error_code": code, "result": result}


GOOD = {
    "get_unknown": answer(code=-32602),
    "get_undeclared": answer(code=-32021),
    "result_method": answer(code=-32601),
}


def data(
    *,
    advertised: bool = True,
    legacy: bool = False,
    probe: ProbeResult | None = None,
    answers: dict[str, dict[str, Any]] | None = None,
) -> AuditData:
    capabilities: dict[str, Any] = {"tools": {}}
    if advertised:
        capabilities["extensions"] = {TASKS_EXTENSION_ID: {}}
    if legacy:
        capabilities["tasks"] = {"requests": {"tools": {"call": {}}}}
    discover = ProbeResult(
        PROBE_DISCOVER,
        ProbeOutcome.SUPPORTED,
        {"supported_versions": ["2026-07-28"]},
        payload={"supportedVersions": ["2026-07-28"], "capabilities": capabilities},
    )
    tasks = probe or ProbeResult(PROBE_TASKS_EXTENSION, ProbeOutcome.SUPPORTED, {**GOOD, **(answers or {})})
    return AuditData(
        protocol_version="2026-07-28",
        url=URL,
        transport_type=MCPTransportType.STREAMABLE_HTTP,
        probes={PROBE_DISCOVER: discover, PROBE_TASKS_EXTENSION: tasks},
    )


def failure_cases() -> list[tuple[str, AuditData, str]]:
    """One failure per Tasks rule, with a phrase from its repair."""
    return [
        ("tasks_get_unknown_rejected", data(answers={"get_unknown": answer(code=-32601)}), "-32602"),
        ("tasks_undeclared_client_rejected", data(answers={"get_undeclared": answer(code=-32602)}), "-32021"),
        ("tasks_result_method_removed", data(answers={"result_method": answer(code=-32602)}), "-32601"),
        ("tasks_legacy_capability_removed", data(legacy=True), "capabilities.tasks"),
    ]


def test_the_pack_has_four_rules_with_the_agreed_severities() -> None:
    assert {rule_id: rule.severity for rule_id, rule in RULES.items()} == {
        "tasks_get_unknown_rejected": RuleSeverity.MEDIUM,
        "tasks_undeclared_client_rejected": RuleSeverity.LOW,
        "tasks_result_method_removed": RuleSeverity.LOW,
        "tasks_legacy_capability_removed": RuleSeverity.LOW,
    }


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_a_conforming_server_passes(rule_id: str) -> None:
    rule = RULES[rule_id]
    audit = data()
    assert rule.skip_reason(audit) is None
    result = rule.check(audit)
    assert result.passed
    assert result.message.endswith(".")
    assert "suggested_fix" not in result.to_dict()
    assert rule.basis is not None
    assert rule.basis.startswith("MCP Tasks Extension (SEP-2663")


@pytest.mark.parametrize(
    ("rule_id", "audit", "action"), failure_cases(), ids=lambda v: v if isinstance(v, str) else None
)
def test_failure_has_a_repair(rule_id: str, audit: AuditData, action: str) -> None:
    rule = RULES[rule_id]
    assert rule.skip_reason(audit) is None
    result = rule.check(audit)
    assert not result.passed
    assert result.severity == rule.severity
    assert result.message.endswith(".")
    fix = result.to_dict()["suggested_fix"]
    assert 0 < len(fix) <= 255
    assert action in fix


def test_failure_cases_cover_every_rule() -> None:
    assert {case[0] for case in failure_cases()} == set(RULES)


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_a_server_without_the_extension_is_not_judged(rule_id: str) -> None:
    assert RULES[rule_id].skip_reason(data(advertised=False)) == SKIP_REASON_NOT_APPLICABLE


@pytest.mark.parametrize("outcome", [ProbeOutcome.ERROR, ProbeOutcome.NOT_APPLICABLE])
@pytest.mark.parametrize("rule_id", ["tasks_get_unknown_rejected", "tasks_undeclared_client_rejected",
                                     "tasks_result_method_removed"])  # fmt: skip
def test_an_unobserved_probe_is_not_a_failure(rule_id: str, outcome: ProbeOutcome) -> None:
    audit = data(probe=ProbeResult(PROBE_TASKS_EXTENSION, outcome, {"reason": "x"}))
    assert RULES[rule_id].skip_reason(audit) == SKIP_REASON_INSUFFICIENT_DATA


@pytest.mark.parametrize(
    "refusal",
    [answer(http_status=401), answer(http_status=403, code=-32602), answer(code=-32001), answer(code=-32600),
     answer()],
)  # fmt: skip
@pytest.mark.parametrize("key", ["get_unknown", "get_undeclared", "result_method"])
def test_a_refusal_before_the_lookup_is_not_judged(key: str, refusal: dict[str, Any]) -> None:
    rule = next(rule for rule in RULES.values() if getattr(rule, "answer_key", None) == key)
    assert rule.skip_reason(data(answers={key: refusal})) == SKIP_REASON_INSUFFICIENT_DATA


@pytest.mark.parametrize(
    ("key", "observed"),
    [
        ("get_unknown", answer(result=True)),
        ("get_undeclared", answer(result=True)),
        ("get_undeclared", answer(code=-32601)),
        ("result_method", answer(result=True)),
    ],
)
def test_other_wrong_answers_fail(key: str, observed: dict[str, Any]) -> None:
    rule = next(rule for rule in RULES.values() if getattr(rule, "answer_key", None) == key)
    audit = data(answers={key: observed})
    assert rule.skip_reason(audit) is None
    assert not rule.check(audit).passed


def test_a_server_without_tasks_get_loses_points_once() -> None:
    audit = data(answers={"get_unknown": answer(code=-32601), "get_undeclared": answer(code=-32601)})
    assert not RULES["tasks_get_unknown_rejected"].check(audit).passed
    assert RULES["tasks_undeclared_client_rejected"].skip_reason(audit) == SKIP_REASON_NOT_APPLICABLE


def test_the_legacy_capability_rule_needs_no_probe_answer() -> None:
    rule = RULES["tasks_legacy_capability_removed"]
    audit = data(legacy=True, probe=ProbeResult(PROBE_TASKS_EXTENSION, ProbeOutcome.ERROR, {}))
    assert rule.skip_reason(audit) is None
    assert rule.check(audit).details == {"legacy_tasks_capability": True}


# --- probe ---------------------------------------------------------------


def _rpc(request_id: Any, *, result: dict[str, Any] | None = None, code: int | None = None) -> httpx2.Response:
    body: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    if code is not None:
        body["error"] = {"code": code, "message": "error"}
    else:
        body["result"] = result or {}
    return httpx2.Response(200, json=body)


def _server(*, advertise: bool) -> tuple[list[httpx2.Request], Any]:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        body = json.loads(request.content)
        method, request_id = body["method"], body["id"]
        if method == "server/discover":
            extensions = {TASKS_EXTENSION_ID: {}} if advertise else {}
            return _rpc(
                request_id, result={"supportedVersions": ["2026-07-28"], "capabilities": {"extensions": extensions}}
            )
        if method == "tasks/get":
            declared = TASKS_EXTENSION_ID in body["params"]["_meta"][CAPABILITIES_META].get("extensions", {})
            return _rpc(request_id, code=-32602 if declared else -32021)
        return _rpc(request_id, code=-32601)

    return seen, handler


async def test_probe_skips_a_server_that_does_not_advertise_tasks() -> None:
    seen, handler = _server(advertise=False)
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        result = await _probe_tasks_extension(_HttpTarget(client, URL))
    assert result.outcome is ProbeOutcome.NOT_APPLICABLE
    assert [json.loads(r.content)["method"] for r in seen] == ["server/discover"]


async def test_probe_asks_about_an_unissued_task_only() -> None:
    seen, handler = _server(advertise=True)
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        result = await _probe_tasks_extension(_HttpTarget(client, URL))

    assert result.outcome is ProbeOutcome.SUPPORTED
    assert result.details == GOOD
    bodies = [json.loads(r.content) for r in seen]
    assert [b["method"] for b in bodies] == ["server/discover", "tasks/get", "tasks/get", "tasks/result"]
    task_ids = {b["params"]["taskId"] for b in bodies[1:]}
    assert len(task_ids) == 1
    task_id = task_ids.pop()
    assert task_id.startswith(UNKNOWN_TASK_PREFIX)
    assert all(r.headers["Mcp-Name"] == task_id for r in seen[1:])
    declared = [TASKS_EXTENSION_ID in b["params"]["_meta"][CAPABILITIES_META].get("extensions", {}) for b in bodies]
    assert declared == [True, True, False, True]


async def test_probe_records_a_result_for_an_unknown_task() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        extensions = {TASKS_EXTENSION_ID: {}}
        if body["method"] == "server/discover":
            return _rpc(
                body["id"], result={"supportedVersions": ["2026-07-28"], "capabilities": {"extensions": extensions}}
            )
        return _rpc(body["id"], result={"resultType": "complete"})

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        result = await _probe_tasks_extension(_HttpTarget(client, URL))
    assert all(result.details[key] == answer(result=True) for key in GOOD)
