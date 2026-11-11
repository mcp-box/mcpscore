"""Session answers are read up to a byte limit: a large or inflating body is unread, never judged."""

import asyncio
from collections.abc import AsyncIterator, Callable
import gzip
import json
from typing import Any
from unittest.mock import patch
import zlib

import httpx2
import pytest

from mcpscore import mcp_client
from mcpscore.enums import ConnectionErrorReason, MCPTransportType
from mcpscore.mcp_client import MCPClient
from mcpscore.probes import ProbeOutcome
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, AuditData
from mcpscore.rules.capabilities import CapabilityToolsPresentRule
from mcpscore.session_reads import SESSION_READ_LIMIT, AnswerOverLimitError, cap_body
from mcpscore.skills import UNOBSERVED_OUTCOMES, UnreadAnswerError, rpc_error
from mcpscore.tls import async_client

URL = "https://example.com/mcp"
URI = "ui://server/app.html"
CHUNK = 64 * 1024
DEADLINE_S = 60  # generous: the bound is on bytes, the deadline only stops a regression from hanging the suite


class _Body(httpx2.AsyncByteStream):
    """A streamed body that counts what it hands out, as a network body would arrive."""

    def __init__(self, chunks: Callable[[], AsyncIterator[bytes]]) -> None:
        super().__init__()
        self._chunks = chunks
        self.sent = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._chunks():
            self.sent += len(chunk)
            yield chunk


async def _endless() -> AsyncIterator[bytes]:
    while True:
        yield b" " * CHUNK


async def _gzip_bomb() -> AsyncIterator[bytes]:
    """Yield an endless gzip stream of zeros: a few KiB on the wire per MiB inflated."""
    compressor = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
    block = b"\0" * (1024 * 1024)
    while True:
        if piece := compressor.compress(block):
            yield piece


def _answer(body: _Body, *, gzip_encoded: bool = False) -> httpx2.Response:
    headers = {"content-type": "application/json"}
    if gzip_encoded:
        headers["content-encoding"] = "gzip"
    return httpx2.Response(200, headers=headers, stream=body)


def _initialize_result(body: dict[str, Any]) -> httpx2.Response:
    result = {
        "protocolVersion": body["params"]["protocolVersion"],
        "capabilities": {"tools": {}, "resources": {}},
        "serverInfo": {"name": "bounded", "version": "1"},
    }
    return httpx2.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})


def _server(answer: Callable[[dict[str, Any]], httpx2.Response | None]) -> httpx2.MockTransport:
    """Serve the handshake unless *answer* returns a response for the request first."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method != "POST":
            return httpx2.Response(405)
        body = json.loads(request.content)
        if (response := answer(body)) is not None:
            return response
        if body.get("method") == "initialize":
            return _initialize_result(body)
        if "id" not in body:
            return httpx2.Response(202)
        return httpx2.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {}})

    return httpx2.MockTransport(handler)


async def _connect(transport: httpx2.MockTransport) -> tuple[MCPClient, bool]:
    def client_with_transport(**kwargs: Any) -> httpx2.AsyncClient:
        return async_client(transport=transport, **kwargs)

    client = MCPClient()
    with patch.object(mcp_client, "async_client", client_with_transport):
        async with asyncio.timeout(DEADLINE_S):
            connected = await client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, URL)
    return client, connected


@pytest.mark.parametrize(("chunks", "encoded"), [(_endless, False), (_gzip_bomb, True)], ids=["endless", "gzip-bomb"])
async def test_oversized_initialize_answer_is_unread_not_a_protocol_failure(
    chunks: Callable[[], AsyncIterator[bytes]], encoded: bool
) -> None:
    bodies: list[_Body] = []

    def answer(body: dict[str, Any]) -> httpx2.Response | None:
        if body.get("method") != "initialize":
            return None
        bodies.append(_Body(chunks))
        return _answer(bodies[-1], gzip_encoded=encoded)

    client, connected = await _connect(_server(answer))
    try:
        assert not connected
        failure = client.last_connection_error
        assert failure is not None
        assert failure.reason is ConnectionErrorReason.UNKNOWN
        assert "read limit" in (failure.detail or "")
        assert bodies
        # Identity bytes stop at the limit; compressed ones far below it.
        assert all(body.sent <= SESSION_READ_LIMIT + CHUNK for body in bodies)
    finally:
        await client.cleanup()


@pytest.mark.parametrize(("chunks", "encoded"), [(_endless, False), (_gzip_bomb, True)], ids=["endless", "gzip-bomb"])
async def test_oversized_listing_page_is_recorded_as_unread(
    chunks: Callable[[], AsyncIterator[bytes]], encoded: bool
) -> None:
    def answer(body: dict[str, Any]) -> httpx2.Response | None:
        return _answer(_Body(chunks), gzip_encoded=encoded) if body.get("method") == "tools/list" else None

    client, connected = await _connect(_server(answer))
    try:
        assert connected
        async with asyncio.timeout(DEADLINE_S):
            assert await client.list_tools() is None
        assert client.listing_errors["tools"] == {"outcome": "unread", "page_index": 0}
        assert "tools" in client.incomplete_listings
        assert client._unread_calls == set()
    finally:
        await client.cleanup()


async def test_oversized_resource_read_is_unobserved() -> None:
    def answer(body: dict[str, Any]) -> httpx2.Response | None:
        return _answer(_Body(_endless)) if body.get("method") == "resources/read" else None

    client, connected = await _connect(_server(answer))
    try:
        assert connected
        with pytest.raises(UnreadAnswerError) as caught:
            async with asyncio.timeout(DEADLINE_S):
                await client.read_resource_contents(URI)
        error = rpc_error(caught.value)
        assert error == {"outcome": "transport", "exception": "UnreadAnswer"}
        assert error["outcome"] in UNOBSERVED_OUTCOMES
    finally:
        await client.cleanup()


async def test_a_small_compressed_answer_is_still_read() -> None:
    page = {"tools": [{"name": "echo", "inputSchema": {"type": "object"}}]}

    def answer(body: dict[str, Any]) -> httpx2.Response | None:
        if body.get("method") != "tools/list":
            return None
        payload = gzip.compress(json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": page}).encode())

        async def chunks() -> AsyncIterator[bytes]:
            yield payload

        return _answer(_Body(chunks), gzip_encoded=True)

    client, connected = await _connect(_server(answer))
    try:
        assert connected
        tools = await client.list_tools()
        assert [tool.name for tool in tools or []] == ["echo"]
        assert "tools" not in client.listing_errors
    finally:
        await client.cleanup()


async def test_sse_bodies_are_left_to_the_sdk_event_limit() -> None:
    response = httpx2.Response(200, headers={"content-type": "text/event-stream"}, stream=_Body(_endless))
    stream = response.stream
    cap_body(response, lambda: None)
    assert response.stream is stream


async def test_cap_reports_the_cut_off_answer() -> None:
    capped: list[bool] = []
    response = httpx2.Response(
        200,
        headers={"content-type": "application/json"},
        stream=_Body(_endless),
        request=httpx2.Request("POST", URL),
    )
    cap_body(response, lambda: capped.append(True), limit=CHUNK * 2)
    with pytest.raises(AnswerOverLimitError):
        await response.aread()
    assert capped == [True]


def test_capability_rule_skips_a_first_page_that_was_not_read() -> None:
    audit_data = AuditData()
    audit_data.listings_attempted = frozenset({"tools"})
    audit_data.listing_errors = {"tools": {"outcome": "unread", "page_index": 0}}
    assert CapabilityToolsPresentRule().skip_reason(audit_data) == SKIP_REASON_INSUFFICIENT_DATA

    audit_data.listing_errors = {"tools": {"outcome": "unread", "page_index": 2}}
    assert CapabilityToolsPresentRule().skip_reason(audit_data) is None


async def test_oversized_invalid_cursor_answer_is_a_probe_error() -> None:
    def answer(body: dict[str, Any]) -> httpx2.Response | None:
        if body.get("method") == "tools/list" and (body.get("params") or {}).get("cursor"):
            return _answer(_Body(_endless))
        return None

    client, connected = await _connect(_server(answer))
    try:
        assert connected
        async with asyncio.timeout(DEADLINE_S):
            results = await client.probe_invalid_cursors({"tools": "probe_tools_invalid_cursor"})
        result = results["probe_tools_invalid_cursor"]
        assert result.outcome is ProbeOutcome.ERROR
        assert result.details == {"exception": "UnreadAnswer"}
    finally:
        await client.cleanup()


async def test_oversized_sse_handshake_answer_is_unread() -> None:
    client = MCPClient()

    async def establish(*_args: Any, **_kwargs: Any) -> None:
        client._unread_calls.add(("initialize", None))
        raise RuntimeError("handshake failed")

    with patch.object(client, "_establish_session", establish):
        assert not await client._connect_with_sse("https://example.com/sse")
    failure = client.last_connection_error
    assert failure is not None
    assert failure.reason is ConnectionErrorReason.UNKNOWN
    assert "initialize answer exceeded" in (failure.detail or "")


async def test_a_capped_answer_outside_a_call_records_nothing() -> None:
    client = MCPClient()
    response = httpx2.Response(
        200,
        headers={"content-type": "application/json"},
        stream=_Body(_endless),
        request=httpx2.Request("GET", URL),
    )
    await client._cap_answer(response)
    with pytest.raises(AnswerOverLimitError):
        await response.aread()
    assert client._unread_calls == set()
