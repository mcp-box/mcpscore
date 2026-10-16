"""Probe tests for the Streamable HTTP envelope: notification 202, invalid requests, the GET stream, DELETE."""

from dataclasses import dataclass, field
import json

import httpx2
import pytest

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
        assert server.methods()[-1] == "DELETE"

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
        "get", [httpx2.Response(200, json={"error": "use POST"}), httpx2.Response(404), httpx2.Response(500)]
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
