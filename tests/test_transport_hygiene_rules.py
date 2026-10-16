"""Rule tests for the Streamable HTTP envelope rules in rules/transport.py."""

from typing import Any

import pytest

from mcpscore.enums import MCPTransportType
from mcpscore.probes import (
    PROBE_GET_STREAM,
    PROBE_INVALID_REQUEST,
    PROBE_NOTIFICATION_ACCEPTED,
    PROBE_SESSION_DELETE,
    ProbeOutcome,
    ProbeResult,
)
from mcpscore.rules import (
    AuditData,
    GetStreamContractRule,
    InvalidRequestErrorCodeRule,
    InvalidRequestRejectedRule,
    NotificationAcceptedRule,
    RuleSeverity,
    SessionDeleteRule,
)
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE

URL = "https://server.example/mcp"


def _data(
    probe_id: str,
    outcome: ProbeOutcome,
    details: dict[str, Any],
    *,
    version: str | None = "2025-11-25",
    transport: MCPTransportType = MCPTransportType.STREAMABLE_HTTP,
) -> AuditData:
    return AuditData(
        transport_type=transport,
        url=URL,
        protocol_version=version,
        probes={probe_id: ProbeResult(probe_id, outcome, details)},
    )


ALL_RULES = [
    (NotificationAcceptedRule, PROBE_NOTIFICATION_ACCEPTED),
    (InvalidRequestRejectedRule, PROBE_INVALID_REQUEST),
    (InvalidRequestErrorCodeRule, PROBE_INVALID_REQUEST),
    (GetStreamContractRule, PROBE_GET_STREAM),
    (SessionDeleteRule, PROBE_SESSION_DELETE),
]


@pytest.mark.parametrize(("rule_class", "probe_id"), ALL_RULES)
class TestApplicability:
    @pytest.mark.parametrize("transport", [MCPTransportType.STDIO, MCPTransportType.SSE])
    def test_not_streamable_http_is_not_applicable(self, rule_class, probe_id, transport):
        data = _data(probe_id, ProbeOutcome.SUPPORTED, {}, transport=transport)
        assert rule_class().skip_reason(data) == SKIP_REASON_NOT_APPLICABLE

    def test_unobservable_probe_is_not_applicable(self, rule_class, probe_id):
        data = _data(probe_id, ProbeOutcome.NOT_APPLICABLE, {"reason": "x"})
        assert rule_class().skip_reason(data) == SKIP_REASON_NOT_APPLICABLE

    def test_errored_probe_is_insufficient_data(self, rule_class, probe_id):
        data = _data(probe_id, ProbeOutcome.ERROR, {"exception": "ReadTimeout"})
        assert rule_class().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_missing_probe_is_insufficient_data(self, rule_class, probe_id):
        data = AuditData(transport_type=MCPTransportType.STREAMABLE_HTTP, url=URL, probes={})
        assert rule_class().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_observed_probe_is_judged(self, rule_class, probe_id):
        assert rule_class().skip_reason(_data(probe_id, ProbeOutcome.SUPPORTED, {})) is None

    def test_starts_with_streamable_http(self, rule_class, probe_id):
        assert rule_class().applies_to("2024-11-05") is False
        assert rule_class().applies_to("2025-03-26") is True


@pytest.mark.parametrize("rule_class", [GetStreamContractRule, SessionDeleteRule])
def test_session_rules_end_where_2026_07_28_removed_sessions(rule_class):
    assert rule_class().applies_to("2025-11-25") is True
    assert rule_class().applies_to("2026-07-28") is False


@pytest.mark.parametrize(
    "rule_class", [NotificationAcceptedRule, InvalidRequestRejectedRule, InvalidRequestErrorCodeRule]
)
def test_envelope_rules_apply_to_2026_07_28(rule_class):
    assert rule_class().applies_to("2026-07-28") is True


class TestNotificationAccepted:
    rule = NotificationAcceptedRule()

    def test_202_passes(self):
        details = {"http_status": 202, "body_present": False, "shape": "legacy-initialized"}
        result = self.rule.check(_data(PROBE_NOTIFICATION_ACCEPTED, ProbeOutcome.SUPPORTED, details))
        assert result.passed is True
        assert result.severity is RuleSeverity.LOW
        assert "HTTP 202 and no body" in result.message
        assert result.details["spec"] == (
            "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#sending-messages-to-the-server"
        )
        assert result.suggested_fix is None

    def test_refusal_passes_with_its_own_message(self):
        details = {"http_status": 400, "body_present": True, "shape": "legacy-initialized"}
        result = self.rule.check(_data(PROBE_NOTIFICATION_ACCEPTED, ProbeOutcome.SUPPORTED, details))
        assert result.passed is True
        assert "refused with an HTTP error status" in result.message

    def test_202_with_a_body_fails(self):
        details = {"http_status": 202, "body_present": True, "shape": "legacy-initialized"}
        result = self.rule.check(_data(PROBE_NOTIFICATION_ACCEPTED, ProbeOutcome.UNSUPPORTED, details))
        assert result.passed is False
        assert "carries a body" in result.message
        assert "HTTP 202 Accepted and an empty body" in result.suggested_fix

    def test_other_status_fails_and_reports_it(self):
        details = {"http_status": 204, "body_present": False, "shape": "legacy-initialized"}
        result = self.rule.check(_data(PROBE_NOTIFICATION_ACCEPTED, ProbeOutcome.UNSUPPORTED, details))
        assert result.passed is False
        assert "not answered with HTTP 202" in result.message
        assert "Observed HTTP status: 204" in result.message

    @pytest.mark.parametrize("version", [None, "2026-07-28"])
    def test_current_or_unknown_revision_cites_the_current_page(self, version):
        details = {"http_status": 202, "body_present": False, "shape": "modern-cancelled"}
        data = _data(PROBE_NOTIFICATION_ACCEPTED, ProbeOutcome.SUPPORTED, details, version=version)
        assert self.rule.check(data).details["spec"] == (
            "https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#sending-messages"
        )


class TestInvalidRequestRejected:
    rule = InvalidRequestRejectedRule()

    def test_invalid_request_code_passes(self):
        details = {"http_status": 400, "error_code": -32600, "served": False, "id_echoed_or_null": True}
        result = self.rule.check(_data(PROBE_INVALID_REQUEST, ProbeOutcome.SUPPORTED, details))
        assert result.passed is True
        assert result.severity is RuleSeverity.MEDIUM
        assert "rejected with -32600" in result.message
        assert result.details["invalid_request_code"] is True
        assert result.details["spec"] == "https://www.jsonrpc.org/specification#error_object"

    def test_another_code_passes_and_names_it(self):
        details = {"http_status": 400, "error_code": -32700, "served": False, "id_echoed_or_null": True}
        result = self.rule.check(_data(PROBE_INVALID_REQUEST, ProbeOutcome.SUPPORTED, details))
        assert result.passed is True
        assert "(-32700; transport_invalid_request_error_code judges the code)" in result.message
        assert result.details["invalid_request_code"] is False

    def test_refusal_without_a_json_rpc_error_passes_and_says_so(self):
        details = {"http_status": 400, "served": False}
        result = self.rule.check(_data(PROBE_INVALID_REQUEST, ProbeOutcome.SUPPORTED, details))
        assert result.passed is True
        assert "no JSON-RPC error" in result.message

    def test_served_fails(self):
        details = {"http_status": 200, "served": True}
        result = self.rule.check(_data(PROBE_INVALID_REQUEST, ProbeOutcome.UNSUPPORTED, details))
        assert result.passed is False
        assert "served as if it were valid" in result.message
        assert "-32600" in result.suggested_fix

    def test_no_answer_fails(self):
        details = {"control_http_status": 200, "timed_out": True}
        result = self.rule.check(_data(PROBE_INVALID_REQUEST, ProbeOutcome.UNSUPPORTED, details))
        assert result.passed is False
        assert "gets no answer" in result.message
        assert result.details["timed_out"] is True

    def test_server_error_fails(self):
        details = {"http_status": 500, "served": False}
        result = self.rule.check(_data(PROBE_INVALID_REQUEST, ProbeOutcome.UNSUPPORTED, details))
        assert result.passed is False
        assert "HTTP 5xx" in result.message

    def test_empty_success_fails(self):
        details = {"http_status": 202, "served": False}
        result = self.rule.check(_data(PROBE_INVALID_REQUEST, ProbeOutcome.UNSUPPORTED, details))
        assert result.passed is False
        assert "neither rejected" in result.message


class TestInvalidRequestErrorCode:
    rule = InvalidRequestErrorCodeRule()

    def test_invalid_request_code_passes(self):
        details = {"http_status": 400, "error_code": -32600, "shape": "legacy-ping"}
        result = self.rule.check(_data(PROBE_INVALID_REQUEST, ProbeOutcome.SUPPORTED, details))
        assert result.passed is True
        assert result.severity is RuleSeverity.LOW
        assert "refused with -32600" in result.message
        assert result.details["spec"] == "https://www.jsonrpc.org/specification#error_object"

    @pytest.mark.parametrize("code", [-32700, -32602, -32601, -32020])
    def test_another_code_fails_and_names_it(self, code):
        details = {"http_status": 400, "error_code": code, "shape": "legacy-ping"}
        result = self.rule.check(_data(PROBE_INVALID_REQUEST, ProbeOutcome.SUPPORTED, details))
        assert result.passed is False
        assert f"refused with {code}; JSON-RPC 2.0 assigns -32600" in result.message
        assert "Some MCP SDKs send -32700 or -32602" in result.suggested_fix
        assert result.details["expected"] == {"error_code": -32600}

    def test_refusal_without_a_json_rpc_error_fails(self):
        details = {"http_status": 400, "shape": "legacy-ping"}
        result = self.rule.check(_data(PROBE_INVALID_REQUEST, ProbeOutcome.SUPPORTED, details))
        assert result.passed is False
        assert "without a JSON-RPC error" in result.message

    def test_header_mismatch_passes_on_the_stateless_path(self):
        details = {"http_status": 400, "error_code": -32020, "shape": "modern-discover"}
        result = self.rule.check(_data(PROBE_INVALID_REQUEST, ProbeOutcome.SUPPORTED, details, version="2026-07-28"))
        assert result.passed is True
        assert "header validation with -32020" in result.message

    @pytest.mark.parametrize("details", [{"served": True}, {"http_status": 500}, {"timed_out": True}])
    def test_skips_when_the_request_was_not_refused(self, details):
        data = _data(PROBE_INVALID_REQUEST, ProbeOutcome.UNSUPPORTED, details)
        assert self.rule.skip_reason(data) == SKIP_REASON_NOT_APPLICABLE


class TestGetStreamContract:
    rule = GetStreamContractRule()

    def test_405_passes(self):
        result = self.rule.check(_data(PROBE_GET_STREAM, ProbeOutcome.SUPPORTED, {"http_status": 405}))
        assert result.passed is True
        assert "refused with HTTP 405" in result.message
        assert result.details["spec"].endswith("2025-11-25/basic/transports#listening-for-messages-from-the-server")

    def test_event_stream_passes(self):
        details = {"http_status": 200, "content_type": "text/event-stream"}
        result = self.rule.check(_data(PROBE_GET_STREAM, ProbeOutcome.SUPPORTED, details))
        assert result.passed is True
        assert "opens a text/event-stream" in result.message

    def test_json_answer_fails(self):
        details = {"http_status": 200, "content_type": "application/json"}
        result = self.rule.check(_data(PROBE_GET_STREAM, ProbeOutcome.UNSUPPORTED, details))
        assert result.passed is False
        assert "405 Method Not Allowed" in result.suggested_fix
        assert result.details["content_type"] == "application/json"

    @pytest.mark.parametrize(("version", "cited"), [("2025-06-18", "2025-06-18"), (None, "2025-11-25")])
    def test_cites_the_negotiated_revision_or_the_last_one_with_a_get_stream(self, version, cited):
        data = _data(PROBE_GET_STREAM, ProbeOutcome.SUPPORTED, {"http_status": 405}, version=version)
        assert f"/specification/{cited}/basic/transports#" in self.rule.check(data).details["spec"]


class TestSessionDelete:
    rule = SessionDeleteRule()

    def test_405_passes(self):
        result = self.rule.check(_data(PROBE_SESSION_DELETE, ProbeOutcome.SUPPORTED, {"http_status": 405}))
        assert result.passed is True
        assert "refused with HTTP 405" in result.message
        assert result.details["spec"].endswith("#session-management")

    def test_termination_passes(self):
        details = {"http_status": 204, "after_delete_http_status": 404}
        result = self.rule.check(_data(PROBE_SESSION_DELETE, ProbeOutcome.SUPPORTED, details))
        assert result.passed is True
        assert "gets HTTP 404" in result.message

    def test_surviving_session_fails_and_names_both_statuses(self):
        details = {"http_status": 200, "after_delete_http_status": 200}
        result = self.rule.check(_data(PROBE_SESSION_DELETE, ProbeOutcome.UNSUPPORTED, details))
        assert result.passed is False
        assert "returns HTTP 200, but a later request with its ID gets HTTP 200, not 404" in result.message
        assert "return HTTP 404" in result.suggested_fix

    def test_server_error_fails(self):
        result = self.rule.check(_data(PROBE_SESSION_DELETE, ProbeOutcome.UNSUPPORTED, {"http_status": 500}))
        assert result.passed is False
        assert "neither accepted nor refused" in result.message
