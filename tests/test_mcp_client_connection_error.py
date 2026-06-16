"""Tests for connection-failure classification on MCPClient.

A server that is up but auth-gated (HTTP 401/403) must be distinguishable from
one that is genuinely unreachable, so the CLI/backend can show an actionable
message instead of a flat "could not connect".
"""

from contextlib import AsyncExitStack
from unittest.mock import MagicMock, patch

import httpx
import pytest

from mcpscore.enums import ConnectionErrorReason, MCPTransportType
from mcpscore.mcp_client import (
    ConnectionFailure,
    MCPClient,
    _preferred_failure,
    extract_http_status,
    reason_for_status,
)


def _http_status_error(status_code: int) -> httpx.HTTPStatusError:
    response = MagicMock()
    response.status_code = status_code
    return httpx.HTTPStatusError("boom", request=MagicMock(), response=response)


class TestReasonForStatus:
    @pytest.mark.parametrize(
        ("status", "reason"),
        [
            (401, ConnectionErrorReason.UNAUTHORIZED),
            (403, ConnectionErrorReason.FORBIDDEN),
            (404, ConnectionErrorReason.HTTP_ERROR),
            (500, ConnectionErrorReason.HTTP_ERROR),
        ],
    )
    def test_maps_status_to_reason(self, status, reason):
        assert reason_for_status(status) == reason


class TestExtractHttpStatus:
    def test_direct_error(self):
        assert extract_http_status(_http_status_error(401)) == 401

    def test_inside_exception_group(self):
        # The MCP SDK's anyio task group surfaces the real cause this way.
        group = ExceptionGroup("transport", [_http_status_error(401)])
        assert extract_http_status(group) == 401

    def test_chained_via_cause(self):
        outer = RuntimeError("wrapper")
        outer.__cause__ = _http_status_error(403)
        assert extract_http_status(outer) == 403

    def test_none_when_absent(self):
        assert extract_http_status(RuntimeError("no http here")) is None


class TestConnectionFailureMessage:
    def test_unauthorized_mentions_authentication(self):
        msg = ConnectionFailure(ConnectionErrorReason.UNAUTHORIZED).message
        assert "authentication" in msg.lower()

    def test_forbidden_mentions_access(self):
        msg = ConnectionFailure(ConnectionErrorReason.FORBIDDEN).message
        assert "403" in msg

    def test_http_error_surfaces_status_code(self):
        msg = ConnectionFailure(ConnectionErrorReason.HTTP_ERROR, status_code=503).message
        assert "503" in msg

    def test_not_mcp_message(self):
        msg = ConnectionFailure(ConnectionErrorReason.NOT_MCP).message
        assert "MCP" in msg


class TestPreferredFailure:
    def test_picks_more_informative(self):
        auth = ConnectionFailure(ConnectionErrorReason.UNAUTHORIZED)
        http = ConnectionFailure(ConnectionErrorReason.HTTP_ERROR, 405)
        # Order-independent: the auth failure (higher rank) always wins.
        assert _preferred_failure(auth, http) is auth
        assert _preferred_failure(http, auth) is auth

    def test_handles_none(self):
        only = ConnectionFailure(ConnectionErrorReason.TIMEOUT)
        assert _preferred_failure(None, only) is only
        assert _preferred_failure(only, None) is only
        assert _preferred_failure(None, None) is None


class TestConnectRecordsFailure:
    @pytest.fixture
    def mcp_client(self):
        return MCPClient()

    async def test_streamable_http_401_is_unauthorized(self, mcp_client):
        with patch("mcpscore.mcp_client.streamable_http_client") as mock_client:
            mock_client.return_value.__aenter__.side_effect = _http_status_error(401)

            result = await mcp_client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, "https://example.com/mcp")

        assert result is False
        assert mcp_client.last_connection_error is not None
        assert mcp_client.last_connection_error.reason == ConnectionErrorReason.UNAUTHORIZED
        assert "authentication" in mcp_client.last_connection_error.message.lower()

    async def test_connect_error_is_unreachable(self, mcp_client):
        with patch("mcpscore.mcp_client.streamable_http_client") as mock_client:
            mock_client.return_value.__aenter__.side_effect = httpx.ConnectError("refused")

            result = await mcp_client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, "https://example.com/mcp")

        assert result is False
        assert mcp_client.last_connection_error.reason == ConnectionErrorReason.UNREACHABLE

    async def test_invalid_url_recorded(self, mcp_client):
        result = await mcp_client.connect_to_server(MCPTransportType.SSE, "not-a-url")
        assert result is False
        assert mcp_client.last_connection_error.reason == ConnectionErrorReason.INVALID_URL


class TestHandshakeFailureClassification:
    """Transport opens, then a buffered HTTP status surfaces during teardown as a cancellation."""

    @pytest.fixture
    def mcp_client(self):
        return MCPClient()

    async def test_discard_attempt_recovers_buffered_status(self, mcp_client):
        stack = AsyncExitStack()

        async def teardown_raises():
            raise ExceptionGroup("transport teardown", [_http_status_error(401)])

        stack.push_async_callback(teardown_raises)

        await mcp_client._discard_attempt(stack)

        assert mcp_client._pending_http_status == 401

    def test_handshake_failure_uses_buffered_status(self, mcp_client):
        mcp_client._pending_http_status = 401
        mcp_client._record_handshake_failure("https://example.com/mcp")
        assert mcp_client.last_connection_error.reason == ConnectionErrorReason.UNAUTHORIZED

    def test_handshake_failure_without_status_is_not_mcp(self, mcp_client):
        mcp_client._pending_http_status = None
        mcp_client._record_handshake_failure("https://example.com/mcp")
        assert mcp_client.last_connection_error.reason == ConnectionErrorReason.NOT_MCP


class TestDetectAndConnectPrefersInformativeFailure:
    @pytest.fixture
    def mcp_client(self):
        return MCPClient()

    async def test_http_401_beats_sse_405(self, mcp_client):
        # Streamable HTTP fails with 401; SSE fallback fails with a generic 405.
        async def fake_streamable(_url):
            mcp_client._record_failure(ConnectionErrorReason.UNAUTHORIZED, 401)
            return False

        async def fake_sse(_url):
            mcp_client._record_failure(ConnectionErrorReason.HTTP_ERROR, 405)
            return False

        with (
            patch.object(mcp_client, "_connect_with_streamable_http", side_effect=fake_streamable),
            patch.object(mcp_client, "_connect_with_sse", side_effect=fake_sse),
        ):
            success, transport = await mcp_client.detect_and_connect("https://example.com/mcp")

        assert success is False
        assert transport is None
        assert mcp_client.last_connection_error.reason == ConnectionErrorReason.UNAUTHORIZED
