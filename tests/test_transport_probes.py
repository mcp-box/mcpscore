"""Probe tests for the Streamable HTTP envelope: notification 202, invalid requests, the GET stream, DELETE."""

import asyncio
from dataclasses import dataclass, field
import gzip
import json

import httpx2
import pytest

from mcpscore import probes
from mcpscore.probes import (
    INVALID_REQUEST_METHOD,
    ProbeOutcome,
    _HttpTarget,
    _probe_get_stream,
    _probe_invalid_request,
    _probe_notification_accepted,
    _probe_session_delete,
)

URL = "https://server.example/mcp"


async def _open_sse(first: bytes = b"data: {}\n\n"):
    """Yield one chunk, then never end the body."""
    yield first
    await asyncio.Event().wait()


def _open_sse_response(status: int = 200, first: bytes = b"data: {}\n\n") -> httpx2.Response:
    return httpx2.Response(status, headers={"Content-Type": "text/event-stream"}, content=_open_sse(first))


@dataclass
class LegacyServer:
    """A configurable 2025-11-25 server: ``initialize`` opens a session, then each envelope reply is set per test."""

    session_id: str | None = "sess-1"
    initialize_status: int = 200
    notification: httpx2.Response = field(default_factory=lambda: httpx2.Response(202))
    ping: httpx2.Response | None = None
    invalid: httpx2.Response | None = None
    get: httpx2.Response = field(default_factory=lambda: httpx2.Response(405))
    delete_status: int = 200
    honours_delete: bool = True
    requests: list[httpx2.Request] = field(default_factory=list)
    deleted: bool = False

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        if request.method == "GET":
            return self.get
        if request.method == "DELETE":
            if 200 <= self.delete_status < 300 and self.honours_delete:
                self.deleted = True
            return httpx2.Response(self.delete_status)
        body = json.loads(request.content)
        if body.get("method") == "initialize":
            if self.initialize_status != 200:
                return httpx2.Response(self.initialize_status)
            headers = {"Mcp-Session-Id": self.session_id} if self.session_id else {}
            result = {"protocolVersion": "2025-11-25", "capabilities": {}}
            return httpx2.Response(200, headers=headers, json={"jsonrpc": "2.0", "id": body["id"], "result": result})
        if self.deleted:
            return httpx2.Response(404)
        if body.get("method") == "notifications/initialized":
            return self.notification
        if body.get("method") == INVALID_REQUEST_METHOD:
            if self.invalid is not None:
                return self.invalid
            return httpx2.Response(
                400, json={"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
            )
        if body.get("method") == "ping":
            if self.ping is not None:
                return self.ping
            return httpx2.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {}})
        return httpx2.Response(400)

    def methods(self) -> list[str]:
        """HTTP method plus JSON-RPC method of every request, in order."""
        seen = []
        for request in self.requests:
            rpc = json.loads(request.content).get("method") if request.method == "POST" else None
            seen.append(f"{request.method} {rpc}" if rpc is not None else request.method)
        return seen


async def _run(probe, handler):
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        return await probe(_HttpTarget(client, URL))


def _modern_handler(notification: httpx2.Response | None = None, discover_status: int = 200):
    """Simulate a 2026-07-28 server without ``initialize`` that answers ``server/discover`` and notifications."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        if body.get("method") == "initialize":
            return httpx2.Response(400, json={"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32601}})
        if "id" not in body:
            return notification or httpx2.Response(202)
        if body.get("method") == "server/discover":
            if discover_status != 200:
                return httpx2.Response(discover_status)
            return httpx2.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {"supportedVersions": []}})
        return httpx2.Response(400, json={"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "x"}})

    return handler


class TestNotificationAccepted:
    async def test_202_without_body_after_initialize(self):
        server = LegacyServer()
        result = await _run(_probe_notification_accepted, server)
        assert result.outcome is ProbeOutcome.SUPPORTED
        assert result.details == {"http_status": 202, "body_present": False, "shape": "legacy-initialized"}
        assert server.methods() == ["POST initialize", "POST notifications/initialized", "DELETE"]

    async def test_notification_carries_the_negotiated_version_and_session(self):
        server = LegacyServer()
        await _run(_probe_notification_accepted, server)
        notification = server.requests[1]
        assert notification.headers["MCP-Protocol-Version"] == "2025-11-25"
        assert notification.headers["Mcp-Session-Id"] == "sess-1"

    async def test_202_with_a_body_fails(self):
        server = LegacyServer(notification=httpx2.Response(202, json={"jsonrpc": "2.0", "result": {}}))
        result = await _run(_probe_notification_accepted, server)
        assert result.outcome is ProbeOutcome.UNSUPPORTED
        assert result.details["body_present"] is True

    @pytest.mark.parametrize("status", [200, 204])
    async def test_other_success_statuses_fail(self, status):
        result = await _run(_probe_notification_accepted, LegacyServer(notification=httpx2.Response(status)))
        assert result.outcome is ProbeOutcome.UNSUPPORTED

    async def test_202_with_a_whitespace_body_fails(self):
        result = await _run(_probe_notification_accepted, LegacyServer(notification=httpx2.Response(202, text="\n")))
        assert result.outcome is ProbeOutcome.UNSUPPORTED
        assert result.details["body_present"] is True

    async def test_202_with_an_encoded_body_is_not_judged(self):
        encoded = httpx2.Response(202, headers={"Content-Encoding": "gzip"}, content=gzip.compress(b'{"result":{}}'))
        result = await _run(_probe_notification_accepted, LegacyServer(notification=encoded))
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["body_present"] is None
        assert result.details["reason"] == "202 body not observable (encoded)"

    async def test_stateless_202_with_an_encoded_body_is_not_judged(self):
        encoded = httpx2.Response(202, headers={"Content-Encoding": "br"}, content=b"compressed")
        result = await _run(_probe_notification_accepted, _modern_handler(notification=encoded))
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE

    async def test_failed_handshake_notification_still_closes_the_session(self):
        server = LegacyServer()

        def fails(request: httpx2.Request) -> httpx2.Response:
            if request.method == "POST" and json.loads(request.content).get("method") == "notifications/initialized":
                server.requests.append(request)
                raise httpx2.ReadTimeout("no answer", request=request)
            return server(request)

        with pytest.raises(httpx2.ReadTimeout):
            await _run(_probe_get_stream, fails)
        assert server.methods() == ["POST initialize", "POST notifications/initialized", "DELETE"]

    async def test_open_sse_answer_is_judged_from_its_status(self):
        server = LegacyServer(notification=_open_sse_response())
        result = await asyncio.wait_for(_run(_probe_notification_accepted, server), timeout=2)
        assert result.outcome is ProbeOutcome.UNSUPPORTED
        assert result.details == {"http_status": 200, "body_present": None, "shape": "legacy-initialized"}

    async def test_stateless_open_sse_answer_is_judged_from_its_status(self):
        handler = _modern_handler(notification=_open_sse_response())
        result = await asyncio.wait_for(_run(_probe_notification_accepted, handler), timeout=2)
        assert result.outcome is ProbeOutcome.UNSUPPORTED
        assert result.details["shape"] == "modern-cancelled"

    async def test_202_opening_a_stream_fails_on_its_first_byte(self):
        server = LegacyServer(notification=_open_sse_response(202))
        result = await asyncio.wait_for(_run(_probe_notification_accepted, server), timeout=2)
        assert result.outcome is ProbeOutcome.UNSUPPORTED
        assert result.details["body_present"] is True

    async def test_202_sending_exactly_one_byte_then_staying_open_fails(self):
        server = LegacyServer(notification=_open_sse_response(202, first=b"\n"))
        result = await asyncio.wait_for(_run(_probe_notification_accepted, server), timeout=2)
        assert result.outcome is ProbeOutcome.UNSUPPORTED
        assert result.details["body_present"] is True

    async def test_an_error_status_is_a_conforming_refusal(self):
        result = await _run(_probe_notification_accepted, LegacyServer(notification=httpx2.Response(400)))
        assert result.outcome is ProbeOutcome.SUPPORTED

    async def test_access_controlled_initialize_is_not_applicable(self):
        result = await _run(_probe_notification_accepted, LegacyServer(initialize_status=401))
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["reason"] == "initialize is access-controlled"

    async def test_server_without_initialize_gets_a_stateless_notification(self):
        result = await _run(_probe_notification_accepted, _modern_handler())
        assert result.outcome is ProbeOutcome.SUPPORTED
        assert result.details["shape"] == "modern-cancelled"

    async def test_stateless_notification_sends_the_method_header(self):
        seen: list[httpx2.Request] = []
        handler = _modern_handler()

        def recording(request: httpx2.Request) -> httpx2.Response:
            seen.append(request)
            return handler(request)

        await _run(_probe_notification_accepted, recording)
        assert seen[-1].headers["Mcp-Method"] == "notifications/cancelled"
        assert "MCP-Protocol-Version" in seen[-1].headers

    async def test_access_controlled_stateless_notification_is_not_applicable(self):
        result = await _run(_probe_notification_accepted, _modern_handler(notification=httpx2.Response(403)))
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["http_status"] == 403


class TestInvalidRequest:
    async def test_rejected_with_invalid_request(self):
        server = LegacyServer()
        result = await _run(_probe_invalid_request, server)
        assert result.outcome is ProbeOutcome.SUPPORTED
        assert result.details["error_code"] == -32600
        assert result.details["id_echoed_or_null"] is True
        assert result.details["served"] is False
        assert server.methods() == [
            "POST initialize",
            "POST notifications/initialized",
            "POST ping",
            f"POST {INVALID_REQUEST_METHOD}",
            "DELETE",
        ]

    async def test_only_the_method_differs_from_the_control(self):
        server = LegacyServer()
        await _run(_probe_invalid_request, server)
        control, invalid = (json.loads(r.content) for r in server.requests[2:4])
        assert {k: v for k, v in control.items() if k not in {"id", "method"}} == {
            k: v for k, v in invalid.items() if k not in {"id", "method"}
        }
        assert invalid["method"] == INVALID_REQUEST_METHOD

    async def test_another_error_code_still_counts_as_rejected(self):
        invalid = httpx2.Response(400, json={"jsonrpc": "2.0", "id": "server-error", "error": {"code": -32602}})
        result = await _run(_probe_invalid_request, LegacyServer(invalid=invalid))
        assert result.outcome is ProbeOutcome.SUPPORTED
        assert result.details["error_code"] == -32602
        assert result.details["id_echoed_or_null"] is False

    async def test_a_4xx_without_a_json_rpc_body_counts_as_rejected(self):
        result = await _run(_probe_invalid_request, LegacyServer(invalid=httpx2.Response(400, text="bad")))
        assert result.outcome is ProbeOutcome.SUPPORTED

    async def test_404_for_a_session_expired_after_the_control_is_not_applicable(self):
        server = LegacyServer()

        def expires_at_invalid(request: httpx2.Request) -> httpx2.Response:
            if request.method == "POST" and json.loads(request.content).get("method") == INVALID_REQUEST_METHOD:
                server.deleted = True
            return server(request)

        result = await _run(_probe_invalid_request, expires_at_invalid)
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert "no longer exists" in result.details["reason"]
        assert server.methods()[-2:] == ["POST ping", "DELETE"]

    async def test_404_while_the_session_is_still_served_counts_as_rejected(self):
        server = LegacyServer(invalid=httpx2.Response(404))
        result = await _run(_probe_invalid_request, server)
        assert result.outcome is ProbeOutcome.SUPPORTED

    async def test_served_fails(self):
        served = httpx2.Response(200, json={"jsonrpc": "2.0", "id": 24, "result": {}})
        result = await _run(_probe_invalid_request, LegacyServer(invalid=served))
        assert result.outcome is ProbeOutcome.UNSUPPORTED
        assert result.details["served"] is True

    async def test_server_error_fails(self):
        result = await _run(_probe_invalid_request, LegacyServer(invalid=httpx2.Response(500)))
        assert result.outcome is ProbeOutcome.UNSUPPORTED

    async def test_an_empty_success_fails(self):
        result = await _run(_probe_invalid_request, LegacyServer(invalid=httpx2.Response(202)))
        assert result.outcome is ProbeOutcome.UNSUPPORTED

    async def test_no_answer_after_a_served_control_fails_and_the_session_is_closed(self):
        server = LegacyServer()

        def hangs(request: httpx2.Request) -> httpx2.Response:
            if request.method == "POST" and json.loads(request.content).get("method") == INVALID_REQUEST_METHOD:
                raise httpx2.ReadTimeout("no answer", request=request)
            return server(request)

        result = await _run(_probe_invalid_request, hangs)
        assert result.outcome is ProbeOutcome.UNSUPPORTED
        assert result.details["timed_out"] is True
        # A second control after the timeout proves the session still answers.
        assert server.methods()[-3:] == ["POST ping", "POST ping", "DELETE"]

    async def test_no_answer_when_the_session_also_stops_answering_is_an_error(self):
        server = LegacyServer()
        timed_out = False

        def everything_hangs_after(request: httpx2.Request) -> httpx2.Response:
            nonlocal timed_out
            if request.method == "POST" and json.loads(request.content).get("method") == INVALID_REQUEST_METHOD:
                timed_out = True
            if timed_out and request.method == "POST":
                server.requests.append(request)
                raise httpx2.ReadTimeout("no answer", request=request)
            return server(request)

        with pytest.raises(httpx2.ReadTimeout):
            await _run(_probe_invalid_request, everything_hangs_after)
        assert server.methods()[-3:] == [f"POST {INVALID_REQUEST_METHOD}", "POST ping", "DELETE"]

    async def test_no_answer_followed_by_an_unserved_control_is_an_error(self):
        server = LegacyServer()
        timed_out = False

        def refuses_after(request: httpx2.Request) -> httpx2.Response:
            nonlocal timed_out
            method = json.loads(request.content).get("method") if request.method == "POST" else None
            if method == INVALID_REQUEST_METHOD:
                timed_out = True
                raise httpx2.ReadTimeout("no answer", request=request)
            if timed_out and method == "ping":
                return httpx2.Response(503)
            return server(request)

        with pytest.raises(httpx2.ReadTimeout):
            await _run(_probe_invalid_request, refuses_after)

    async def test_unserved_control_is_not_applicable_and_the_session_is_closed(self):
        ping = httpx2.Response(200, json={"jsonrpc": "2.0", "id": 25, "error": {"code": -32601}})
        server = LegacyServer(ping=ping)
        result = await _run(_probe_invalid_request, server)
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert server.methods()[-1] == "DELETE"
        assert f"POST {INVALID_REQUEST_METHOD}" not in server.methods()

    async def test_access_controlled_initialize_is_not_applicable(self):
        result = await _run(_probe_invalid_request, LegacyServer(initialize_status=403))
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE

    async def test_server_without_initialize_is_probed_statelessly(self):
        result = await _run(_probe_invalid_request, _modern_handler())
        assert result.outcome is ProbeOutcome.SUPPORTED
        assert result.details["shape"] == "modern-discover"

    async def test_access_controlled_stateless_control_is_not_applicable(self):
        result = await _run(_probe_invalid_request, _modern_handler(discover_status=401))
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["control_http_status"] == 401


class TestGetStream:
    async def test_405_conforms(self):
        server = LegacyServer()
        result = await _run(_probe_get_stream, server)
        assert result.outcome is ProbeOutcome.SUPPORTED
        assert result.details == {"http_status": 405, "content_type": None}
        assert server.methods() == ["POST initialize", "POST notifications/initialized", "GET", "DELETE"]

    async def test_get_carries_the_session_and_version(self):
        server = LegacyServer()
        await _run(_probe_get_stream, server)
        get = server.requests[2]
        assert get.headers["Accept"] == "text/event-stream"
        assert get.headers["Mcp-Session-Id"] == "sess-1"
        assert get.headers["MCP-Protocol-Version"] == "2025-11-25"

    async def test_event_stream_conforms(self):
        get = httpx2.Response(200, headers={"Content-Type": "text/event-stream; charset=utf-8"})
        result = await _run(_probe_get_stream, LegacyServer(get=get))
        assert result.outcome is ProbeOutcome.SUPPORTED

    @pytest.mark.parametrize(
        "get",
        [
            httpx2.Response(200, json={"error": "use POST"}),
            httpx2.Response(404),
            httpx2.Response(500),
            httpx2.Response(200, headers={"Content-Type": "text/event-streaming"}),
            httpx2.Response(200, headers={"Content-Type": "text/event-stream+json"}),
        ],
    )
    async def test_anything_else_fails(self, get):
        result = await _run(_probe_get_stream, LegacyServer(get=get))
        assert result.outcome is ProbeOutcome.UNSUPPORTED

    async def test_session_less_server_is_still_judged(self):
        server = LegacyServer(session_id=None)
        result = await _run(_probe_get_stream, server)
        assert result.outcome is ProbeOutcome.SUPPORTED
        assert "Mcp-Session-Id" not in server.requests[2].headers

    async def test_access_controlled_get_is_not_applicable(self):
        result = await _run(_probe_get_stream, LegacyServer(get=httpx2.Response(401)))
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE

    async def test_no_legacy_session_is_not_applicable(self):
        result = await _run(_probe_get_stream, _modern_handler())
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["initialize_http_status"] == 400
        assert "no legacy session" in result.details["reason"]


class TestSessionDelete:
    async def test_accepted_delete_then_404(self):
        server = LegacyServer()
        result = await _run(_probe_session_delete, server)
        assert result.outcome is ProbeOutcome.SUPPORTED
        assert result.details == {"http_status": 200, "after_delete_http_status": 404}
        assert server.methods() == ["POST initialize", "POST notifications/initialized", "DELETE", "POST ping"]

    async def test_delete_carries_the_session_and_version(self):
        server = LegacyServer()
        await _run(_probe_session_delete, server)
        delete = server.requests[2]
        assert delete.headers["Mcp-Session-Id"] == "sess-1"
        assert delete.headers["MCP-Protocol-Version"] == "2025-11-25"

    async def test_failed_delete_still_attempts_cleanup(self):
        server = LegacyServer()

        def delete_fails(request: httpx2.Request) -> httpx2.Response:
            if request.method == "DELETE":
                server.requests.append(request)
                raise httpx2.ConnectError("reset", request=request)
            return server(request)

        with pytest.raises(httpx2.ConnectError):
            await _run(_probe_session_delete, delete_fails)
        assert server.methods() == ["POST initialize", "POST notifications/initialized", "DELETE", "DELETE"]

    async def test_405_refusal_conforms(self):
        server = LegacyServer(delete_status=405)
        result = await _run(_probe_session_delete, server)
        assert result.outcome is ProbeOutcome.SUPPORTED
        assert "POST ping" not in server.methods()

    async def test_session_kept_after_an_accepted_delete_is_not_applicable(self):
        result = await _run(_probe_session_delete, LegacyServer(delete_status=204, honours_delete=False))
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["after_delete_http_status"] == 200
        assert "still served" in result.details["reason"]

    async def test_ended_session_answered_with_400_fails(self):
        """The TypeScript SDK example pattern: the session is gone, but the answer is 400, not 404."""
        server = LegacyServer()

        def answers_400(request: httpx2.Request) -> httpx2.Response:
            response = server(request)
            return httpx2.Response(400) if response.status_code == 404 else response

        result = await _run(_probe_session_delete, answers_400)
        assert result.outcome is ProbeOutcome.UNSUPPORTED
        assert result.details == {"http_status": 200, "after_delete_http_status": 400}

    async def test_server_error_fails(self):
        result = await _run(_probe_session_delete, LegacyServer(delete_status=500))
        assert result.outcome is ProbeOutcome.UNSUPPORTED

    async def test_access_controlled_delete_is_not_applicable(self):
        result = await _run(_probe_session_delete, LegacyServer(delete_status=403))
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE

    async def test_no_session_id_is_not_applicable(self):
        server = LegacyServer(session_id=None)
        result = await _run(_probe_session_delete, server)
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert "DELETE" not in server.methods()

    async def test_no_legacy_session_is_not_applicable(self):
        result = await _run(_probe_session_delete, LegacyServer(initialize_status=500))
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["initialize_http_status"] == 500

    async def test_404_for_an_expired_session_is_not_applicable(self):
        server = LegacyServer(delete_status=404)
        server.deleted = False

        def expired(request: httpx2.Request) -> httpx2.Response:
            if request.method == "DELETE":
                server.deleted = True
            return server(request)

        result = await _run(_probe_session_delete, expired)
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert "no longer exists" in result.details["reason"]
        assert server.methods() == ["POST initialize", "POST notifications/initialized", "DELETE", "POST ping"]

    async def test_404_while_the_session_is_still_served_fails(self):
        server = LegacyServer(delete_status=404)
        result = await _run(_probe_session_delete, server)
        assert result.outcome is ProbeOutcome.UNSUPPORTED
        assert server.methods()[-1] == "DELETE"

    @pytest.mark.parametrize("delete_status", [500, 400])
    async def test_refused_delete_is_retried_as_cleanup(self, delete_status):
        server = LegacyServer(delete_status=delete_status)
        result = await _run(_probe_session_delete, server)
        assert result.outcome is ProbeOutcome.UNSUPPORTED
        assert server.methods() == ["POST initialize", "POST notifications/initialized", "DELETE", "DELETE"]

    async def test_session_kept_after_delete_is_closed_again(self):
        server = LegacyServer(honours_delete=False)
        await _run(_probe_session_delete, server)
        assert server.methods() == [
            "POST initialize",
            "POST notifications/initialized",
            "DELETE",
            "POST ping",
            "DELETE",
        ]

    async def test_failed_follow_up_still_attempts_cleanup(self):
        server = LegacyServer()

        def ping_fails(request: httpx2.Request) -> httpx2.Response:
            if request.method == "POST" and json.loads(request.content).get("method") == "ping":
                server.requests.append(request)
                raise httpx2.ConnectError("reset", request=request)
            return server(request)

        with pytest.raises(httpx2.ConnectError):
            await _run(_probe_session_delete, ping_fails)
        assert server.methods()[-1] == "DELETE"


class TestExpiredSessionOnGet:
    async def test_404_for_an_expired_session_is_not_applicable(self):
        server = LegacyServer(get=httpx2.Response(404))

        def expires_at_get(request: httpx2.Request) -> httpx2.Response:
            if request.method == "GET":
                server.deleted = True
            return server(request)

        result = await _run(_probe_get_stream, expires_at_get)
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert "no longer exists" in result.details["reason"]
        assert server.methods() == ["POST initialize", "POST notifications/initialized", "GET", "POST ping", "DELETE"]

    async def test_404_while_the_session_is_still_served_fails(self):
        server = LegacyServer(get=httpx2.Response(404))
        result = await _run(_probe_get_stream, server)
        assert result.outcome is ProbeOutcome.UNSUPPORTED
        assert "POST ping" in server.methods()

    async def test_session_less_404_fails_without_a_check(self):
        server = LegacyServer(session_id=None, get=httpx2.Response(404))
        result = await _run(_probe_get_stream, server)
        assert result.outcome is ProbeOutcome.UNSUPPORTED
        assert "POST ping" not in server.methods()


class TestBoundedCleanup:
    async def test_cleanup_answered_with_an_endless_stream_returns(self):
        server = LegacyServer()

        def streaming_delete(request: httpx2.Request) -> httpx2.Response:
            if request.method == "DELETE":
                server.requests.append(request)
                return _open_sse_response()
            return server(request)

        result = await asyncio.wait_for(_run(_probe_get_stream, streaming_delete), timeout=2)
        assert result.outcome is ProbeOutcome.SUPPORTED
        assert server.methods()[-1] == "DELETE"

    async def test_cleanup_whose_headers_never_arrive_hits_the_deadline(self, monkeypatch):
        monkeypatch.setattr(probes, "PROBE_TIMEOUT_S", 0.2)
        server = LegacyServer()

        async def silent_delete(request: httpx2.Request) -> httpx2.Response:
            if request.method == "DELETE":
                server.requests.append(request)
                await asyncio.Event().wait()
            return server(request)

        result = await asyncio.wait_for(_run(_probe_get_stream, silent_delete), timeout=2)
        assert result.outcome is ProbeOutcome.SUPPORTED


class TestRedirectedEndpoint:
    """A same-origin redirect is followed once, as the audit's session does, and the probes stay on its target."""

    @staticmethod
    def _redirecting(server: LegacyServer):
        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.url.path == "/mcp":
                return httpx2.Response(308, headers={"Location": "https://server.example/mcp/"})
            return server(request)

        return handler

    @pytest.mark.parametrize(
        "probe", [_probe_notification_accepted, _probe_invalid_request, _probe_get_stream, _probe_session_delete]
    )
    async def test_session_probes_follow_and_stay_on_the_redirect_target(self, probe):
        server = LegacyServer()
        result = await _run(probe, self._redirecting(server))
        assert result.outcome is ProbeOutcome.SUPPORTED
        assert all(request.url.path == "/mcp/" for request in server.requests)

    async def test_stateless_fallback_uses_the_redirect_target(self):
        modern = _modern_handler()
        seen: list[str] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.url.path == "/mcp":
                return httpx2.Response(307, headers={"Location": "https://server.example/mcp/"})
            seen.append(request.url.path)
            return modern(request)

        result = await _run(_probe_notification_accepted, handler)
        assert result.outcome is ProbeOutcome.SUPPORTED
        assert result.details["shape"] == "modern-cancelled"
        assert seen == ["/mcp/", "/mcp/"]

    async def test_cross_origin_redirect_is_not_followed(self):
        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(308, headers={"Location": "https://elsewhere.example/mcp"})

        result = await _run(_probe_get_stream, handler)
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["initialize_http_status"] == 308


class TestUnfollowedRedirect:
    """A redirect the probe does not follow never reached the endpoint, so nothing is judged."""

    async def test_notification(self):
        server = LegacyServer(notification=httpx2.Response(307, headers={"Location": "https://other.example/"}))
        result = await _run(_probe_notification_accepted, server)
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["reason"] == "endpoint redirects"

    async def test_invalid_request(self):
        server = LegacyServer(invalid=httpx2.Response(308, headers={"Location": "https://other.example/"}))
        assert (await _run(_probe_invalid_request, server)).outcome is ProbeOutcome.NOT_APPLICABLE

    async def test_get(self):
        server = LegacyServer(get=httpx2.Response(302, headers={"Location": "https://other.example/"}))
        assert (await _run(_probe_get_stream, server)).outcome is ProbeOutcome.NOT_APPLICABLE

    async def test_delete(self):
        server = LegacyServer(delete_status=301)
        assert (await _run(_probe_session_delete, server)).outcome is ProbeOutcome.NOT_APPLICABLE


class TestIncompleteHandshake:
    """A refused ``notifications/initialized`` leaves no usable session: later checks are not judged."""

    @pytest.mark.parametrize("probe", [_probe_invalid_request, _probe_get_stream, _probe_session_delete])
    @pytest.mark.parametrize("status", [400, 307])
    async def test_session_checks_skip_and_close_the_session(self, probe, status):
        server = LegacyServer(notification=httpx2.Response(status, headers={"Location": "https://other.example/"}))
        result = await _run(probe, server)
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details == {
            "initialized_http_status": status,
            "reason": "handshake notification was not accepted",
        }
        assert server.methods() == ["POST initialize", "POST notifications/initialized", "DELETE"]

    async def test_the_notification_rule_still_judges_the_refusal(self):
        result = await _run(_probe_notification_accepted, LegacyServer(notification=httpx2.Response(400)))
        assert result.outcome is ProbeOutcome.SUPPORTED


class TestAccessControlAfterTheControl:
    @pytest.mark.parametrize("status", [401, 403])
    async def test_invalid_request_refused_by_access_control_is_not_judged(self, status):
        result = await _run(_probe_invalid_request, LegacyServer(invalid=httpx2.Response(status)))
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert "access control" in result.details["reason"]

    @pytest.mark.parametrize(
        ("after", "reason"),
        [
            (httpx2.Response(401), "request after DELETE is access-controlled"),
            (httpx2.Response(403), "request after DELETE is access-controlled"),
            (httpx2.Response(307, headers={"Location": "https://other.example/"}), "endpoint redirects"),
        ],
    )
    async def test_follow_up_after_delete_that_cannot_be_judged(self, after, reason):
        server = LegacyServer()

        def answers(request: httpx2.Request) -> httpx2.Response:
            response = server(request)
            return after if response.status_code == 404 else response

        result = await _run(_probe_session_delete, answers)
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["reason"] == reason


def _sse(*events: bytes, stay_open: bool = False) -> httpx2.Response:
    async def body():
        for event in events:
            yield event
        if stay_open:
            while True:
                yield b": heartbeat\n\n"
                await asyncio.sleep(0.01)

    return httpx2.Response(
        200, headers={"Content-Type": "text/event-stream", "Mcp-Session-Id": "sse-1"}, content=body()
    )


INIT_RESULT = b'data: {"jsonrpc":"2.0","id":%d,"result":{"protocolVersion":"2025-11-25"}}\n\n'


class TestSseAnswers:
    """Session requests answered over SSE are read up to their own response, never to EOF."""

    @staticmethod
    def _server(initialize) -> LegacyServer:
        server = LegacyServer()
        original = server.__call__

        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method == "POST" and json.loads(request.content).get("method") == "initialize":
                server.requests.append(request)
                return initialize(json.loads(request.content)["id"])
            return original(request)

        server.handler = handler  # type: ignore[attr-defined]
        return server

    async def test_priming_event_and_notification_before_the_result(self):
        server = self._server(
            lambda rid: _sse(
                b"id: prime-1\ndata:\n\n",
                b'data: {"jsonrpc":"2.0","method":"notifications/message","params":{}}\n\n',
                INIT_RESULT % rid,
            )
        )
        result = await asyncio.wait_for(_run(_probe_get_stream, server.handler), timeout=2)
        assert result.outcome is ProbeOutcome.SUPPORTED
        assert server.requests[-1].headers["Mcp-Session-Id"] == "sse-1"

    async def test_result_followed_by_endless_heartbeats(self):
        server = self._server(lambda rid: _sse(INIT_RESULT % rid, stay_open=True))
        result = await asyncio.wait_for(_run(_probe_session_delete, server.handler), timeout=2)
        assert result.outcome is ProbeOutcome.SUPPORTED

    async def test_stream_that_never_answers_hits_the_deadline_and_closes_the_session(self, monkeypatch):
        monkeypatch.setattr(probes, "PROBE_TIMEOUT_S", 0.2)
        server = self._server(lambda _rid: _sse(stay_open=True))
        with pytest.raises(httpx2.ReadTimeout):
            await asyncio.wait_for(_run(_probe_get_stream, server.handler), timeout=2)
        assert server.methods()[-1] == "DELETE"
        assert server.requests[-1].headers["Mcp-Session-Id"] == "sse-1"

    async def test_byte_cap_ends_a_stream_without_an_answer(self, monkeypatch):
        monkeypatch.setattr(probes, "_RPC_READ_LIMIT", 64)
        server = self._server(lambda _rid: _sse(stay_open=True))
        result = await asyncio.wait_for(_run(_probe_get_stream, server.handler), timeout=2)
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["reason"] == "initialize answer not observable (capped)"
        assert server.methods()[-1] == "DELETE"

    async def test_unparsable_events_are_skipped(self):
        server = self._server(lambda rid: _sse(b"data: not json\n\n", INIT_RESULT % rid))
        result = await asyncio.wait_for(_run(_probe_get_stream, server.handler), timeout=2)
        assert result.outcome is ProbeOutcome.SUPPORTED

    async def test_stream_ending_without_an_answer_is_not_a_session(self):
        server = self._server(lambda _rid: _sse(b'data: {"jsonrpc":"2.0","id":999,"result":{}}\n\n'))
        result = await asyncio.wait_for(_run(_probe_get_stream, server.handler), timeout=2)
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert server.methods()[-1] == "DELETE"

    async def test_error_with_a_null_id_answers_the_invalid_request(self):
        server = LegacyServer(invalid=_sse(b'data: {"jsonrpc":"2.0","id":null,"error":{"code":-32600}}\n\n'))
        result = await asyncio.wait_for(_run(_probe_invalid_request, server), timeout=2)
        assert result.outcome is ProbeOutcome.SUPPORTED
        assert result.details["error_code"] == -32600


async def test_unusable_initialize_answer_with_a_session_id_is_closed():
    server = LegacyServer()

    def no_version(request: httpx2.Request) -> httpx2.Response:
        if request.method == "POST" and json.loads(request.content).get("method") == "initialize":
            server.requests.append(request)
            return httpx2.Response(200, headers={"Mcp-Session-Id": "sess-x"}, json={"jsonrpc": "2.0", "id": 1})
        return server(request)

    result = await _run(_probe_get_stream, no_version)
    assert result.outcome is ProbeOutcome.NOT_APPLICABLE
    assert server.methods() == ["POST initialize", "DELETE"]


class TestNotModifiedIsJudged:
    """304 is not a redirect: it is judged like any other wrong answer."""

    async def test_get(self):
        assert (
            await _run(_probe_get_stream, LegacyServer(get=httpx2.Response(304)))
        ).outcome is ProbeOutcome.UNSUPPORTED

    async def test_notification(self):
        server = LegacyServer(notification=httpx2.Response(304))
        assert (await _run(_probe_notification_accepted, server)).outcome is ProbeOutcome.UNSUPPORTED


class TestBoundedAnswers:
    """The byte cap applies before buffering, and an interrupted ``initialize`` still closes its session."""

    @staticmethod
    def _initialize_answers(server: LegacyServer, answer, path: str = "/mcp"):
        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method == "POST" and request.url.path == "/mcp" and path != "/mcp":
                return httpx2.Response(308, headers={"Location": f"https://server.example{path}"})
            if request.method == "POST" and json.loads(request.content).get("method") == "initialize":
                server.requests.append(request)
                return answer(json.loads(request.content)["id"])
            return server(request)

        return handler

    async def test_oversized_unterminated_line_hits_the_cap(self, monkeypatch):
        monkeypatch.setattr(probes, "_RPC_READ_LIMIT", 64)
        server = LegacyServer()

        async def body():
            yield b"data: " + b"x" * 200
            await asyncio.Event().wait()

        answer = lambda _rid: httpx2.Response(  # noqa: E731
            200, headers={"Content-Type": "text/event-stream", "Mcp-Session-Id": "big"}, content=body()
        )
        result = await asyncio.wait_for(_run(_probe_get_stream, self._initialize_answers(server, answer)), timeout=2)
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["reason"] == "initialize answer not observable (capped)"
        assert server.requests[-1].method == "DELETE"
        assert server.requests[-1].headers["Mcp-Session-Id"] == "big"

    async def test_multibyte_characters_split_across_chunks_are_decoded(self):
        server = LegacyServer()

        async def body(rid):
            message = {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-11-25", "n": "é漢"}}
            event = f"data: {json.dumps(message, ensure_ascii=False)}\n\n".encode()
            split = event.index("漢".encode()) + 1
            yield event[:split]
            yield event[split:]

        answer = lambda rid: httpx2.Response(  # noqa: E731
            200, headers={"Content-Type": "text/event-stream", "Mcp-Session-Id": "mb"}, content=body(rid)
        )
        result = await asyncio.wait_for(_run(_probe_get_stream, self._initialize_answers(server, answer)), timeout=2)
        assert result.outcome is ProbeOutcome.SUPPORTED

    async def test_the_cap_counts_bytes_not_characters(self, monkeypatch):
        monkeypatch.setattr(probes, "_RPC_READ_LIMIT", 64)
        server = LegacyServer()
        answer = lambda _rid: httpx2.Response(  # noqa: E731
            200, headers={"Content-Type": "text/event-stream"}, content=("data: " + "漢" * 20 + "\n").encode()
        )
        result = await asyncio.wait_for(_run(_probe_get_stream, self._initialize_answers(server, answer)), timeout=2)
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["reason"] == "initialize answer not observable (capped)"

    async def test_read_error_mid_body_closes_the_session_and_propagates(self):
        server = LegacyServer()

        async def body():
            yield b"id: prime\ndata:\n\n"
            raise httpx2.ReadError("connection reset")

        answer = lambda _rid: httpx2.Response(  # noqa: E731
            200, headers={"Content-Type": "text/event-stream", "Mcp-Session-Id": "reset"}, content=body()
        )
        with pytest.raises(httpx2.ReadError):
            await _run(_probe_get_stream, self._initialize_answers(server, answer))
        assert server.requests[-1].method == "DELETE"
        assert server.requests[-1].headers["Mcp-Session-Id"] == "reset"

    async def test_redirected_initialize_deadline_closes_the_session_where_it_lives(self, monkeypatch):
        monkeypatch.setattr(probes, "PROBE_TIMEOUT_S", 0.2)
        server = LegacyServer()
        answer = lambda _rid: _sse(stay_open=True)  # noqa: E731
        with pytest.raises(httpx2.ReadTimeout):
            await asyncio.wait_for(
                _run(_probe_get_stream, self._initialize_answers(server, answer, path="/mcp/")), timeout=2
            )
        assert server.requests[-1].method == "DELETE"
        assert server.requests[-1].url.path == "/mcp/"

    async def test_oversized_json_answer_hits_the_cap(self, monkeypatch):
        monkeypatch.setattr(probes, "_RPC_READ_LIMIT", 64)
        server = LegacyServer()
        answer = lambda _rid: httpx2.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"pad": "x" * 200}})  # noqa: E731
        result = await asyncio.wait_for(_run(_probe_get_stream, self._initialize_answers(server, answer)), timeout=2)
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["reason"] == "initialize answer not observable (capped)"

    async def test_encoded_answer_is_not_decoded(self):
        server = LegacyServer()
        answer = lambda _rid: httpx2.Response(  # noqa: E731
            200, headers={"Content-Encoding": "gzip", "Mcp-Session-Id": "gz"}, content=gzip.compress(b"{}")
        )
        result = await _run(_probe_get_stream, self._initialize_answers(server, answer))
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert server.methods() == ["POST initialize", "DELETE"]

    async def test_initialize_requests_an_identity_body(self):
        server = LegacyServer()
        await _run(_probe_get_stream, server)
        assert server.requests[0].headers["Accept-Encoding"] == "identity"

    async def test_stream_ending_mid_line_has_no_answer(self):
        server = LegacyServer()
        answer = lambda rid: httpx2.Response(  # noqa: E731
            200,
            headers={"Content-Type": "text/event-stream", "Mcp-Session-Id": "eof"},
            content=(INIT_RESULT % rid).rstrip(b"\n"),
        )
        result = await _run(_probe_get_stream, self._initialize_answers(server, answer))
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert server.methods()[-1] == "DELETE"

    async def test_read_error_on_a_later_request_propagates_after_cleanup(self):
        async def body():
            yield b"id: prime\ndata:\n\n"
            raise httpx2.ReadError("connection reset")

        server = LegacyServer(
            invalid=httpx2.Response(200, headers={"Content-Type": "text/event-stream"}, content=body())
        )
        with pytest.raises(httpx2.ReadError):
            await _run(_probe_invalid_request, server)
        assert server.methods()[-1] == "DELETE"


class TestSseLineEndings:
    """WHATWG SSE: CR, LF and CRLF all end a line, and a leading UTF-8 BOM is ignored."""

    @staticmethod
    def _chunks(*chunks: bytes) -> httpx2.Response:
        async def body():
            for chunk in chunks:
                yield chunk

        return httpx2.Response(
            200, headers={"Content-Type": "text/event-stream", "Mcp-Session-Id": "le"}, content=body()
        )

    @staticmethod
    def _event(rid: int, newline: bytes) -> bytes:
        message = json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-11-25"}})
        return b"id: 1" + newline + b"data: " + message.encode() + newline + newline

    @pytest.mark.parametrize("newline", [b"\r", b"\n", b"\r\n"])
    async def test_every_line_ending(self, newline):
        server = LegacyServer()
        answer = lambda rid: self._chunks(self._event(rid, newline))  # noqa: E731
        result = await _run(_probe_get_stream, TestBoundedAnswers._initialize_answers(server, answer))
        assert result.outcome is ProbeOutcome.SUPPORTED

    @pytest.mark.parametrize("newline", [b"\r", b"\r\n", b"\n"])
    async def test_complete_event_on_a_stream_left_open(self, newline):
        server = LegacyServer()

        def answer(rid: int) -> httpx2.Response:
            async def body():
                yield self._event(rid, newline)
                await asyncio.Event().wait()

            headers = {"Content-Type": "text/event-stream", "Mcp-Session-Id": "open"}
            return httpx2.Response(200, headers=headers, content=body())

        handler = TestBoundedAnswers._initialize_answers(server, answer)
        result = await asyncio.wait_for(_run(_probe_get_stream, handler), timeout=2)
        assert result.outcome is ProbeOutcome.SUPPORTED

    async def test_lone_cr_at_a_chunk_end_followed_by_another_line(self):
        server = LegacyServer()

        def answer(rid: int) -> httpx2.Response:
            event = self._event(rid, b"\r")
            return self._chunks(b"id: 0\r", b"data: x\r\r", event)

        result = await _run(_probe_get_stream, TestBoundedAnswers._initialize_answers(server, answer))
        assert result.outcome is ProbeOutcome.SUPPORTED

    async def test_crlf_split_across_chunks(self):
        server = LegacyServer()

        def answer(rid: int) -> httpx2.Response:
            event = self._event(rid, b"\r\n")
            first_cr = event.index(b"\r") + 1
            return self._chunks(event[:first_cr], event[first_cr:])

        result = await _run(_probe_get_stream, TestBoundedAnswers._initialize_answers(server, answer))
        assert result.outcome is ProbeOutcome.SUPPORTED

    @pytest.mark.parametrize("split", [0, 1, 2, 3])
    async def test_leading_bom_whole_or_split(self, split):
        server = LegacyServer()

        def answer(rid: int) -> httpx2.Response:
            stream = b"\xef\xbb\xbf" + self._event(rid, b"\n")
            return self._chunks(stream[:split], stream[split:]) if split else self._chunks(stream)

        result = await _run(_probe_get_stream, TestBoundedAnswers._initialize_answers(server, answer))
        assert result.outcome is ProbeOutcome.SUPPORTED


class TestUnobservableAnswers:
    """A compressed or over-cap answer is not evidence; only a status that decides alone is judged."""

    @staticmethod
    def _gzip(status: int) -> httpx2.Response:
        return httpx2.Response(status, headers={"Content-Encoding": "gzip"}, content=gzip.compress(b'{"error":{}}'))

    async def test_compressed_refusal_counts_as_rejected_without_a_code(self):
        result = await _run(_probe_invalid_request, LegacyServer(invalid=self._gzip(400)))
        assert result.outcome is ProbeOutcome.SUPPORTED
        assert result.details["body_unobservable"] == "encoded"
        assert "error_code" not in result.details

    async def test_compressed_success_is_not_judged(self):
        result = await _run(_probe_invalid_request, LegacyServer(invalid=self._gzip(200)))
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["reason"] == "answer to the invalid request not observable (encoded)"

    async def test_compressed_crash_still_fails_on_its_status(self):
        result = await _run(_probe_invalid_request, LegacyServer(invalid=self._gzip(502)))
        assert result.outcome is ProbeOutcome.UNSUPPORTED

    async def test_over_cap_refusal_is_rejected_not_a_timeout(self, monkeypatch):
        monkeypatch.setattr(probes, "_RPC_READ_LIMIT", 400)
        big = httpx2.Response(400, json={"jsonrpc": "2.0", "id": 24, "error": {"code": -32600, "data": "x" * 1000}})
        server = LegacyServer(invalid=big)
        result = await _run(_probe_invalid_request, server)
        assert result.outcome is ProbeOutcome.SUPPORTED
        assert result.details["body_unobservable"] == "capped"
        assert "timed_out" not in result.details
        assert [m for m in server.methods() if m == "POST ping"] == ["POST ping"]

    async def test_compressed_control_is_not_judged(self):
        server = LegacyServer(ping=self._gzip(200))
        result = await _run(_probe_invalid_request, server)
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["reason"] == "control answer not observable (encoded)"

    async def test_compressed_initialize_is_not_a_stateless_server(self):
        server = LegacyServer()

        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method == "POST" and json.loads(request.content).get("method") == "initialize":
                server.requests.append(request)
                return self._gzip(200)
            return server(request)

        for probe in (_probe_notification_accepted, _probe_invalid_request):
            result = await _run(probe, handler)
            assert result.outcome is ProbeOutcome.NOT_APPLICABLE
            assert result.details["reason"] == "initialize answer not observable (encoded)"

    async def test_compressed_answer_after_delete_is_not_judged(self):
        server = LegacyServer(honours_delete=False, ping=self._gzip(200))
        result = await _run(_probe_session_delete, server)
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["reason"] == "answer after DELETE not observable (encoded)"

    @pytest.mark.parametrize("status", [400, 500])
    async def test_unreadable_error_after_delete_still_fails_on_its_status(self, status):
        server = LegacyServer()

        def gzip_error(request: httpx2.Request) -> httpx2.Response:
            response = server(request)
            if response.status_code == 404:
                return self._gzip(status)
            return response

        result = await _run(_probe_session_delete, gzip_error)
        assert result.outcome is ProbeOutcome.UNSUPPORTED
        assert result.details["after_delete_http_status"] == status

    async def test_compressed_404_after_delete_still_passes(self):
        server = LegacyServer()

        def gzip_404(request: httpx2.Request) -> httpx2.Response:
            response = server(request)
            if response.status_code == 404:
                return httpx2.Response(404, headers={"Content-Encoding": "gzip"}, content=gzip.compress(b"gone"))
            return response

        result = await _run(_probe_session_delete, gzip_404)
        assert result.outcome is ProbeOutcome.SUPPORTED


class TestCapAndDeadlineKeepWhatArrived:
    @pytest.mark.parametrize("coalesced", [False, True])
    async def test_answer_inside_the_cap_is_found_however_it_is_chunked(self, monkeypatch, coalesced):
        monkeypatch.setattr(probes, "_RPC_READ_LIMIT", 400)
        server = LegacyServer()

        def answer(rid: int) -> httpx2.Response:
            event = INIT_RESULT % rid
            tail = b": " + b"x" * 1000 + b"\n"
            chunks = [event + tail] if coalesced else [event, tail]

            async def body():
                for chunk in chunks:
                    yield chunk

            headers = {"Content-Type": "text/event-stream", "Mcp-Session-Id": "cap"}
            return httpx2.Response(200, headers=headers, content=body())

        result = await _run(_probe_get_stream, TestBoundedAnswers._initialize_answers(server, answer))
        assert result.outcome is ProbeOutcome.SUPPORTED

    @pytest.mark.parametrize(("status", "outcome"), [(400, ProbeOutcome.SUPPORTED), (500, ProbeOutcome.UNSUPPORTED)])
    async def test_error_status_with_an_unfinished_body_is_judged_by_its_status(self, monkeypatch, status, outcome):
        monkeypatch.setattr(probes, "PROBE_TIMEOUT_S", 0.2)
        server = LegacyServer(invalid=_open_sse_response(status, first=b": still thinking\n\n"))
        result = await asyncio.wait_for(_run(_probe_invalid_request, server), timeout=2)
        assert result.outcome is outcome
        assert result.details["body_unobservable"] == "unfinished"
        assert "timed_out" not in result.details
        assert [m for m in server.methods() if m == "POST ping"] == ["POST ping"]

    async def test_success_status_with_an_unfinished_body_still_needs_the_second_control(self, monkeypatch):
        monkeypatch.setattr(probes, "PROBE_TIMEOUT_S", 0.2)
        server = LegacyServer(invalid=_open_sse_response(200, first=b": still thinking\n\n"))
        result = await asyncio.wait_for(_run(_probe_invalid_request, server), timeout=2)
        assert result.outcome is ProbeOutcome.UNSUPPORTED
        assert result.details["timed_out"] is True

    async def test_a_chunk_arriving_after_the_cap_is_exactly_full(self, monkeypatch):
        monkeypatch.setattr(probes, "_RPC_READ_LIMIT", 10)
        server = LegacyServer()

        def answer(_rid: int) -> httpx2.Response:
            async def body():
                yield b": 1234567\n"
                yield b": more\n"

            return httpx2.Response(200, headers={"Content-Type": "text/event-stream"}, content=body())

        result = await _run(_probe_get_stream, TestBoundedAnswers._initialize_answers(server, answer))
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details["reason"] == "initialize answer not observable (capped)"
