"""Credential refusals sent as a JSON-RPC error with HTTP 200 instead of a 401/403.

The fixture is the recorded anonymous exchange of a public API-key server; no test makes a live call.
"""

import json
import logging
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx2
import pytest

from mcpscore import mcp_auditor, probes
from mcpscore.cli import (
    credential_challenge_seen,
    credential_hint,
    describe_gate,
    end_sentence,
    gated_partial_reason,
    log_audit_outcome,
)
from mcpscore.credential_challenge import (
    challenge_header,
    challenge_summary,
    has_credential,
    is_credential_challenge,
    redact_values,
)
from mcpscore.enums import ConnectionErrorReason
from mcpscore.mcp_auditor import MCPAuditor, has_authorization_credential
from mcpscore.mcp_client import ConnectionFailure, MCPClient
from mcpscore.probes import (
    PROBE_DISCOVER,
    PROBE_MALFORMED_JSON,
    PROBE_NOTIFICATION_ACCEPTED,
    PROBE_STATELESS_LIST,
    PROBE_UNAUTHENTICATED,
    ProbeOutcome,
    ProbeResult,
    auth_gate_status,
    observed_auth_status,
)

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "credential_challenge_http200.json").read_text(encoding="utf-8")
)
URL = "https://api-key.example/mcp"
REFUSAL = FIXTURE["error"]


def _request_id(request: httpx2.Request) -> Any:
    try:
        body = json.loads(request.content)
    except ValueError:
        return None
    return body.get("id") if isinstance(body, dict) else None


def _api_key_server(valid_key: str | None = None):
    """Answer like the recorded server: every anonymous request gets HTTP 200 and JSON-RPC -32001."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        if "/.well-known/" in request.url.path:
            return httpx2.Response(FIXTURE["well_known_status"])
        key = request.headers.get("X-API-Key")
        error = FIXTURE["invalid_key_error"] if key and key != valid_key else REFUSAL
        request_id = _request_id(request) if request.method == "POST" else None
        return httpx2.Response(
            FIXTURE["status"],
            headers=FIXTURE["headers"],
            json={"jsonrpc": "2.0", "id": request_id, "error": error},
        )

    return handler


def _mock_client(handler):
    def factory(**kwargs) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(transport=httpx2.MockTransport(handler), **kwargs)

    return factory


async def _run_probes(handler) -> dict[str, ProbeResult]:
    async with (
        httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client,
        httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as fresh,
    ):
        return await probes.run_all_probes(URL, client=client, fresh_client=fresh)


class TestMatcher:
    @pytest.mark.parametrize(
        "error",
        [
            REFUSAL,
            {"code": -32001, "message": "Unauthorized"},
            {"code": -32000, "message": "Authentication required"},
            {"code": -32600, "message": "Missing access token"},
            {"code": -32001, "message": "Request refused", "data": "Invalid credentials"},
            {"code": -32001, "message": "Refused", "data": {"detail": "Configure X-API-Key for this server."}},
        ],
    )
    def test_credential_refusals_are_recognised(self, error):
        assert is_credential_challenge(error)

    @pytest.mark.parametrize(
        "error",
        [
            {"code": -32601, "message": "Method not found"},
            {"code": -32602, "message": "Resource not found: 'resource://mcpscore/does-not-exist'"},
            {"code": -32700, "message": "Parse error"},
            {"code": -32603, "message": "Internal error", "data": 7},
            {"code": -32001, "message": "Tokenizer failed on input"},
            {"code": -32603, "message": "Internal error: API key database unavailable"},
            {"code": -32602, "message": "Invalid params: cursor token is invalid"},
            {"code": -32602, "message": "Invalid cursor token"},
            "Unauthorized",
            None,
        ],
    )
    def test_other_errors_are_not(self, error):
        assert not is_credential_challenge(error)

    def test_the_named_header_is_extracted_as_spelled(self):
        assert challenge_header(REFUSAL) == "X-API-Key"
        assert challenge_header({"message": "Authorization header is required"}) == "Authorization"
        assert challenge_header({"message": "Unauthorized"}) is None

    def test_credential_headers(self):
        assert has_credential({"X-API-Key": "k"})
        assert has_credential({"authorization": "Bearer t"})
        assert has_credential({"X-Auth-Token": "t"})
        assert not has_credential({"X-Trace": "1"})
        assert not has_credential({"X-API-Key": "  "})
        assert has_authorization_credential({"X-API-Key": "k"})

    def test_supplied_credentials_are_redacted_from_the_server_text(self):
        headers = {"X-API-Key": "sk-live-指南-1234", "Authorization": "Bearer tok-5678", "X-Trace": "trace-0001"}
        text = "Key sk-live-指南-1234 and token tok-5678 refused; trace trace-0001"

        assert redact_values(text, headers) == "Key [redacted] and token [redacted] refused; trace trace-0001"

    def test_a_short_value_is_redacted_too(self):
        assert redact_values("key abc refused", {"X-API-Key": "abc"}) == "key [redacted] refused"

    def test_summary_quotes_bounds_and_escapes_the_message(self):
        long = {"code": -32001, "message": "API key required.\n" + "x" * 300}

        summary = challenge_summary(long)

        assert summary["error_code"] == -32001
        assert summary["message"].startswith('"API key required.\\n')
        assert summary["message"].endswith(" [truncated]")
        assert summary["header"] is None


class TestClientClassification:
    async def test_the_handshake_refusal_is_credential_required(self):
        client = MCPClient()

        with patch("mcpscore.mcp_client.async_client", side_effect=_mock_client(_api_key_server())):
            assert await client._connect_with_streamable_http(URL) is False

        failure = client.last_connection_error
        assert failure is not None
        assert failure.reason is ConnectionErrorReason.CREDENTIAL_REQUIRED
        assert failure.status_code == 200
        assert failure.challenge == {
            "error_code": -32001,
            "message": '"X-API-Key header is required."',
            "header": "X-API-Key",
        }
        assert failure.message == (
            'The MCP server requires a credential (HTTP 200, JSON-RPC error -32001: "X-API-Key header is required.").'
        )

    async def test_the_status_is_the_refusals_own_not_the_recovery_requests(self):
        client = MCPClient()

        def handler(request: httpx2.Request) -> httpx2.Response:
            if b"status-recovery" in request.content:
                return httpx2.Response(500)
            return _api_key_server()(request)

        with patch("mcpscore.mcp_client.async_client", side_effect=_mock_client(handler)):
            assert await client._connect_with_streamable_http(URL) is False

        failure = client.last_connection_error
        assert failure is not None
        assert failure.reason is ConnectionErrorReason.CREDENTIAL_REQUIRED
        assert failure.status_code == 200

    async def test_a_rejected_key_is_classified_and_never_echoed(self):
        client = MCPClient(headers={"X-API-Key": "not-the-key"})

        def echoing(request: httpx2.Request) -> httpx2.Response:
            message = f"API key {request.headers.get('X-API-Key')} is not valid."
            error = {"code": -32001, "message": message}
            return httpx2.Response(200, json={"jsonrpc": "2.0", "id": _request_id(request), "error": error})

        with patch("mcpscore.mcp_client.async_client", side_effect=_mock_client(echoing)):
            assert await client._connect_with_streamable_http(URL) is False

        failure = client.last_connection_error
        assert failure is not None
        assert failure.reason is ConnectionErrorReason.CREDENTIAL_REQUIRED
        assert failure.challenge is not None
        assert failure.challenge["message"] == '"API key [redacted] is not valid."'


class TestProbes:
    async def test_every_refused_probe_is_gated_not_failed(self):
        results = await _run_probes(_api_key_server())

        unauthenticated = results[PROBE_UNAUTHENTICATED]
        assert unauthenticated.details["error_code"] == -32001
        assert observed_auth_status(results) == 200
        assert auth_gate_status(results[PROBE_DISCOVER]) == 200
        assert auth_gate_status(results[PROBE_STATELESS_LIST]) == 200
        assert results[PROBE_MALFORMED_JSON].outcome is ProbeOutcome.NOT_APPLICABLE
        assert results[PROBE_NOTIFICATION_ACCEPTED].outcome is ProbeOutcome.NOT_APPLICABLE

    async def test_an_answer_naming_no_credential_is_not_a_gate(self):
        def broken(request: httpx2.Request) -> httpx2.Response:
            error = {"code": -32603, "message": "Internal error"}
            return httpx2.Response(200, json={"jsonrpc": "2.0", "id": _request_id(request), "error": error})

        results = await _run_probes(broken)

        assert observed_auth_status(results) is None
        assert auth_gate_status(results[PROBE_DISCOVER]) is None


class TestPartialAudit:
    async def test_only_observable_rules_score_and_the_challenge_is_reported(self, monkeypatch: pytest.MonkeyPatch):
        handler = _api_key_server()

        async def real_probes(url: str, client: Any = None, headers: Any = None) -> dict[str, ProbeResult]:
            return await _run_probes(handler)

        async def fake_tls(url: str) -> str:
            return "TLSv1.3"

        monkeypatch.setattr(mcp_auditor, "run_all_probes", real_probes)
        monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(fake_tls))
        auditor = MCPAuditor()

        assert await auditor.audit_partial(URL, reason="requires a credential") is True
        report = auditor.get_audit_report()

        assert [res["rule_id"] for res in report["results"] if not res["passed"]] == []
        assert report["readiness"]["max_score"] == 0
        assert report["credential_challenge"] == {
            "http_status": 200,
            "error_code": -32001,
            "message": '"X-API-Key header is required."',
            "header": "X-API-Key",
            "basis": "MCP Authorization 2025-11-25 §Protocol Requirements (authorization is OPTIONAL)",
        }
        assert report["authenticated"] is False

    def test_a_standard_401_is_no_credential_challenge_fact(self):
        auditor = MCPAuditor()
        auditor.audit_data.probes = {
            PROBE_UNAUTHENTICATED: ProbeResult(
                PROBE_UNAUTHENTICATED,
                ProbeOutcome.SUPPORTED,
                {"http_status": 401, "error_code": -32001, "error_message": "Unauthorized"},
            )
        }

        assert auditor.get_audit_report()["credential_challenge"] is None


class TestCliWording:
    CHALLENGE = {"error_code": -32001, "message": '"X-API-Key header is required."', "header": "X-API-Key"}

    def test_anonymous_credential_gate(self, caplog: pytest.LogCaptureFixture):
        failure = ConnectionFailure(ConnectionErrorReason.CREDENTIAL_REQUIRED, 200, challenge=self.CHALLENGE)

        with caplog.at_level(logging.INFO, logger="mcpscore.cli"):
            reason = gated_partial_reason(failure, None, {}, session_gated=True, probed_status=None)

        assert reason == (
            'Server requires a credential (HTTP 200, JSON-RPC error -32001: "X-API-Key header is required."); '
            'scored the unauthenticated surface only — pass it with --header "X-API-Key: <value>".'
        )
        assert "Server requires a credential — running a partial audit of the observable surface." in caplog.text
        assert (
            '(The server answered HTTP 200 with JSON-RPC error -32001: "X-API-Key header is required." '
            'Pass it with --header "X-API-Key: <value>".)'
        ) in caplog.text

    def test_a_rejected_key_blames_the_credential(self):
        challenge = {"error_code": -32001, "message": '"The provided API key is not valid."', "header": None}
        failure = ConnectionFailure(ConnectionErrorReason.CREDENTIAL_REQUIRED, 200, challenge=challenge)

        reason = gated_partial_reason(failure, None, {"X-API-Key": "wrong"}, session_gated=True, probed_status=None)

        assert reason.startswith(
            'Server rejected the provided credentials (HTTP 200, JSON-RPC error -32001: "The provided API key is not '
            'valid.")'
        )

    def test_a_probe_seen_challenge_is_used_when_the_session_failed_otherwise(self):
        probe = ProbeResult(
            PROBE_UNAUTHENTICATED,
            ProbeOutcome.SUPPORTED,
            {"http_status": 200, "error_code": -32001, "error_message": "X-API-Key header is required."},
        )
        failure = ConnectionFailure(ConnectionErrorReason.UNKNOWN)

        assert credential_challenge_seen(failure, {PROBE_UNAUTHENTICATED: probe}, {}) == self.CHALLENGE
        reason = gated_partial_reason(
            failure, {PROBE_UNAUTHENTICATED: probe}, {}, session_gated=False, probed_status=200
        )
        assert reason.startswith('Server requires a credential (HTTP 200, JSON-RPC error -32001: "X-API-Key')

    @pytest.mark.parametrize(
        ("message", "expected"),
        [
            ("X-API-Key header is required.", "users must configure X-API-Key by hand."),
            ("Unauthorized", "users must configure it by hand."),
        ],
    )
    def test_the_fact_line(self, caplog: pytest.LogCaptureFixture, message: str, expected: str):
        auditor = MCPAuditor()
        auditor.audit_data.probes = {
            PROBE_UNAUTHENTICATED: ProbeResult(
                PROBE_UNAUTHENTICATED,
                ProbeOutcome.SUPPORTED,
                {"http_status": 200, "error_code": -32001, "error_message": message},
            )
        }

        with caplog.at_level(logging.INFO, logger="mcpscore.cli"):
            log_audit_outcome(auditor)

        line = next(record.getMessage() for record in caplog.records if "Credential challenge" in record.getMessage())
        assert line.startswith("Credential challenge (not scored): anonymous requests get HTTP 200 with JSON-RPC error")
        assert line.endswith(expected)

    def test_helpers(self):
        assert describe_gate(401, None) == "HTTP 401"
        assert describe_gate(None, self.CHALLENGE) == 'JSON-RPC error -32001: "X-API-Key header is required."'
        assert credential_hint({"header": "Authorization"}) == "--token or --header"
        assert credential_hint({"header": None}) == "--token or --header"
        assert end_sentence('error -32001: "Unauthorized"') == 'error -32001: "Unauthorized".'
        assert end_sentence('error -32001: "Required."') == 'error -32001: "Required."'


def _refuse(request: httpx2.Request, error: dict[str, Any]) -> httpx2.Response:
    return httpx2.Response(200, json={"jsonrpc": "2.0", "id": _request_id(request), "error": error})


class TestRefusalEverywhere:
    async def test_the_sse_fallback_is_skipped_after_a_credential_refusal(self):
        client = MCPClient()
        methods: list[str] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            methods.append(request.method)
            return _api_key_server()(request)

        with patch("mcpscore.mcp_client.async_client", side_effect=_mock_client(handler)):
            assert await client.detect_and_connect(URL) == (False, None)

        assert "GET" not in methods
        assert client.last_connection_error is not None
        assert client.last_connection_error.reason is ConnectionErrorReason.CREDENTIAL_REQUIRED

    async def test_a_get_refused_for_a_credential_is_not_judged(self):
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(_api_key_server())) as client:
            result = await probes._probe_get_stream_removed(probes._HttpTarget(client, URL))

        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["credential_refusal"] is True

    async def test_a_refusal_named_only_in_its_data_is_a_gate(self):
        error = {"code": -32001, "message": "Request refused", "data": "Invalid credentials"}
        results = await _run_probes(lambda request: _refuse(request, error))

        assert observed_auth_status(results) == 200
        assert auth_gate_status(results[PROBE_DISCOVER]) == 200
        auditor = MCPAuditor()
        auditor.audit_data.probes = results
        fact = auditor.get_audit_report()["credential_challenge"]
        assert fact is not None
        assert fact["message"] == '"Request refused"'

    async def test_a_refused_stateless_notification_is_not_judged(self):
        def handler(request: httpx2.Request) -> httpx2.Response:
            if json.loads(request.content).get("method") == "initialize":
                return _refuse(request, {"code": -32601, "message": "Method not found"})
            return _refuse(request, REFUSAL)

        async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
            result = await probes._probe_notification_accepted(probes._HttpTarget(client, URL))

        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["shape"] == "modern-cancelled"
