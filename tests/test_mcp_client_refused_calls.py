"""A call answered with an HTTP error status keeps that status, whether or not the body held a JSON-RPC error."""

import json
from typing import Any
from unittest.mock import patch

import httpx2
from mcp.shared.exceptions import MCPError
from mcp_types import CONNECTION_CLOSED, REQUEST_TIMEOUT, Tool
import pytest

from mcpscore import mcp_client, probes
from mcpscore.apps import collect_apps
from mcpscore.enums import MCPTransportType
from mcpscore.mcp_client import MCPClient
from mcpscore.skills import UNOBSERVED_OUTCOMES, HTTPRefusedCallError, rpc_error
from mcpscore.tls import async_client

URL = "https://example.com/mcp"
URI = "ui://server/app.html"


def _server(read_response: httpx2.Response) -> httpx2.MockTransport:
    """Serve the streamable HTTP handshake, then answer every other request with *read_response*."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method != "POST":
            return httpx2.Response(405)
        body = json.loads(request.content)
        if body.get("method") == "initialize":
            result = {
                "protocolVersion": body["params"]["protocolVersion"],
                "capabilities": {"tools": {}, "resources": {}},
                "serverInfo": {"name": "refusing", "version": "1"},
            }
            return httpx2.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})
        if "id" not in body:
            return httpx2.Response(202)
        return read_response

    return httpx2.MockTransport(handler)


def _rpc_error(status: int, code: int, message: str) -> httpx2.Response:
    return httpx2.Response(status, json={"jsonrpc": "2.0", "id": None, "error": {"code": code, "message": message}})


async def _connected(read_response: httpx2.Response) -> MCPClient:
    transport = _server(read_response)

    def client_with_transport(**kwargs: Any) -> httpx2.AsyncClient:
        return async_client(transport=transport, **kwargs)

    client = MCPClient()
    with patch.object(mcp_client, "async_client", client_with_transport):
        assert await client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, URL)
    return client


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (httpx2.Response(429, text="Too Many Requests"), {"outcome": "throttled", "http_status": 429}),
        (httpx2.Response(503, text="busy"), {"outcome": "throttled", "http_status": 503}),
        (httpx2.Response(401, json={"detail": "Authentication required"}), {"outcome": "gated", "http_status": 401}),
        (httpx2.Response(403, text=""), {"outcome": "gated", "http_status": 403}),
        (
            httpx2.Response(500, text="boom"),
            {"outcome": "rpc_error", "error_code": -32603, "http_status": 500},
        ),
        (_rpc_error(429, -32029, "Request limit reached."), {"outcome": "throttled", "http_status": 429}),
        (_rpc_error(401, -32001, "Unauthorized"), {"outcome": "gated", "http_status": 401}),
    ],
    ids=["429", "503", "401-json-body", "403", "500", "429-json-rpc-error", "401-json-rpc-error"],
)
async def test_read_keeps_the_http_status(response: httpx2.Response, expected: dict[str, Any]) -> None:
    client = await _connected(response)
    try:
        with pytest.raises(HTTPRefusedCallError) as caught:
            await client.read_resource_contents(URI)
        assert caught.value.http_status == expected["http_status"]
        assert rpc_error(caught.value) == expected
    finally:
        await client.cleanup()


async def test_raw_request_keeps_the_http_status() -> None:
    client = await _connected(httpx2.Response(429, text="slow down"))
    try:
        with pytest.raises(HTTPRefusedCallError) as caught:
            await client.request_raw("skills/list", {})
        assert rpc_error(caught.value) == {"outcome": "throttled", "http_status": 429}
    finally:
        await client.cleanup()


async def test_json_rpc_error_at_another_status_stays_the_servers_answer() -> None:
    client = await _connected(_rpc_error(400, -32002, "Resource not found"))
    try:
        with pytest.raises(HTTPRefusedCallError) as caught:
            await client.read_resource_contents(URI)
        assert rpc_error(caught.value) == {"outcome": "rpc_error", "error_code": -32002, "http_status": 400}
        assert client._refused_calls == {}
    finally:
        await client.cleanup()


@pytest.mark.parametrize("status", [401, 429])
async def test_refused_ui_read_is_unanswered(status: int) -> None:
    client = await _connected(httpx2.Response(status, text=""))
    tool = Tool.model_validate(
        {"name": "show", "inputSchema": {"type": "object"}, "_meta": {"ui": {"resourceUri": URI}}}
    )
    try:
        evidence = await collect_apps(client, [tool])
    finally:
        await client.cleanup()
    read = evidence.reads[URI]
    assert read.error is not None
    assert read.error["outcome"] in UNOBSERVED_OUTCOMES
    assert not read.answered


def test_error_without_a_recorded_status_is_unchanged() -> None:
    original = MCPError(code=-32002, message="Resource not found")
    assert MCPClient()._with_http_status(original, "resources/read", {"uri": URI}) is original


async def test_resending_a_call_forgets_the_earlier_status() -> None:
    client = MCPClient()
    request = httpx2.Request(
        "POST", URL, json={"jsonrpc": "2.0", "id": 7, "method": "resources/read", "params": {"uri": URI}}
    )
    await client._record_refused_call(httpx2.Response(429, request=request))
    assert client._refused_calls == {("resources/read", URI): 429}
    await client._forget_refused_call(request)
    assert client._refused_calls == {}


async def test_only_json_rpc_requests_are_recorded() -> None:
    client = MCPClient()
    for request in (
        httpx2.Request("GET", URL),
        httpx2.Request("POST", URL, content=b"not json"),
        httpx2.Request("POST", URL, json={"jsonrpc": "2.0", "method": "notifications/initialized"}),
    ):
        await client._record_refused_call(httpx2.Response(429, request=request))
    assert client._refused_calls == {}


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (_rpc_error(429, -32029, "Request limit reached."), {"outcome": "throttled", "http_status": 429}),
        (_rpc_error(403, -32001, "Forbidden"), {"outcome": "gated", "http_status": 403}),
        (
            _rpc_error(400, -32002, "Resource not found"),
            {"outcome": "rpc_error", "error_code": -32002, "http_status": 400},
        ),
    ],
    ids=["429", "403", "400"],
)
async def test_stateless_read_keeps_the_http_status(response: httpx2.Response, expected: dict[str, Any]) -> None:
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(lambda _request: response)) as http:
        session = probes.StatelessSession(probes._HttpTarget(http, URL))
        with pytest.raises(HTTPRefusedCallError) as caught:
            await session.read_resource_contents(URI)
    assert rpc_error(caught.value) == expected


async def test_stateless_error_at_status_200_stays_a_plain_answer() -> None:
    response = httpx2.Response(200, json={"jsonrpc": "2.0", "id": None, "error": {"code": -32002, "message": "nope"}})
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(lambda _request: response)) as http:
        session = probes.StatelessSession(probes._HttpTarget(http, URL))
        with pytest.raises(MCPError) as caught:
            await session.read_resource_contents(URI)
    assert not isinstance(caught.value, HTTPRefusedCallError)
    assert rpc_error(caught.value) == {"outcome": "rpc_error", "error_code": -32002}


@pytest.mark.parametrize("code", [REQUEST_TIMEOUT, CONNECTION_CLOSED], ids=["request-timeout", "connection-closed"])
def test_status_wins_over_a_no_answer_code(code: int) -> None:
    error = HTTPRefusedCallError(MCPError(code=code, message="server's own meaning"), 400)
    assert rpc_error(error) == {"outcome": "rpc_error", "error_code": code, "http_status": 400}


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (httpx2.Response(500, text="boom"), {"outcome": "rpc_error", "error_code": -32603, "http_status": 500}),
        (httpx2.Response(404, text=""), {"outcome": "rpc_error", "error_code": -32601, "http_status": 404}),
        (httpx2.Response(429, text=""), {"outcome": "throttled", "http_status": 429}),
        (httpx2.Response(401, json={"error": "invalid_token"}), {"outcome": "gated", "http_status": 401}),
    ],
    ids=["500-text", "404-empty", "429-empty", "401-oauth-body"],
)
async def test_stateless_error_status_without_json_rpc_body(
    response: httpx2.Response, expected: dict[str, Any]
) -> None:
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(lambda _request: response)) as http:
        session = probes.StatelessSession(probes._HttpTarget(http, URL))
        with pytest.raises(HTTPRefusedCallError) as caught:
            await session.read_resource_contents(URI)
    assert rpc_error(caught.value) == expected


async def test_stateless_error_status_ignores_a_mismatched_id() -> None:
    error = {"code": -32603, "message": "boom"}
    response = httpx2.Response(500, json={"jsonrpc": "2.0", "id": 99999, "error": error})
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(lambda _request: response)) as http:
        session = probes.StatelessSession(probes._HttpTarget(http, URL))
        with pytest.raises(HTTPRefusedCallError) as caught:
            await session.read_resource_contents(URI)
    assert rpc_error(caught.value) == {"outcome": "rpc_error", "error_code": -32603, "http_status": 500}


async def test_stateless_success_with_a_mismatched_id_is_no_answer() -> None:
    response = httpx2.Response(200, json={"jsonrpc": "2.0", "id": 99999, "result": {"contents": []}})
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(lambda _request: response)) as http:
        session = probes.StatelessSession(probes._HttpTarget(http, URL))
        with pytest.raises(ConnectionError):
            await session.read_resource_contents(URI)


async def test_same_origin_redirect_still_connects_and_keeps_the_status() -> None:
    inner = _server(httpx2.Response(429, text=""))

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.path == "/mcp":
            return httpx2.Response(307, headers={"location": URL + "/"})
        return inner.handler(request)  # type: ignore[attr-defined]

    transport = httpx2.MockTransport(handler)
    client = MCPClient()
    with patch.object(mcp_client, "async_client", lambda **kwargs: async_client(transport=transport, **kwargs)):
        assert await client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, URL)
    try:
        with pytest.raises(HTTPRefusedCallError) as caught:
            await client.read_resource_contents(URI)
        assert caught.value.http_status == 429
    finally:
        await client.cleanup()


async def test_a_body_that_cannot_be_read_is_skipped() -> None:
    class Unreadable(httpx2.Request):
        async def aread(self) -> bytes:
            raise httpx2.StreamConsumed

    client = MCPClient()
    request = Unreadable("POST", URL, content=b"{}")
    await client._forget_refused_call(request)
    await client._record_refused_call(httpx2.Response(429, request=request))
    assert client._refused_calls == {}
