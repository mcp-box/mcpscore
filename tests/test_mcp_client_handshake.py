"""Unit tests for the MCP initialize handshake performed during connect.

A connection only counts as established once the server completes the MCP
`initialize` handshake — merely opening the transport stream succeeds against
any reachable endpoint (e.g. a plain HTTPS site), MCP server or not.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcpscore.enums import MCPTransportType
from mcpscore.mcp_client import MCPClient


def _mock_http_transport(mock_client, mock_session):
    """Wire up streamable_http_client and ClientSession mocks."""
    mock_client.return_value.__aenter__.return_value = (
        AsyncMock(),
        AsyncMock(),
        MagicMock(return_value="test-session-id"),
    )
    mock_session.__aenter__.return_value = mock_session


class TestHandshakeDuringConnect:
    """Connect must verify the MCP handshake, not just open the stream."""

    @pytest.fixture
    def mcp_client(self):
        return MCPClient()

    @pytest.mark.asyncio
    async def test_connect_succeeds_and_caches_init_result(self, mcp_client):
        mock_session = AsyncMock()
        init_result = MagicMock()
        mock_session.initialize.return_value = init_result

        with (
            patch("mcpscore.mcp_client.streamable_http_client") as mock_client,
            patch("mcpscore.mcp_client.ClientSession", return_value=mock_session),
        ):
            _mock_http_transport(mock_client, mock_session)

            result = await mcp_client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, "https://example.com/mcp")

            assert result is True
            mock_session.initialize.assert_awaited_once()

            # initialize() returns the cached handshake result without a second call
            assert await mcp_client.initialize() is init_result
            mock_session.initialize.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_fails_when_handshake_raises(self, mcp_client):
        mock_session = AsyncMock()
        mock_session.initialize.side_effect = RuntimeError("not an MCP server")

        with (
            patch("mcpscore.mcp_client.streamable_http_client") as mock_client,
            patch("mcpscore.mcp_client.ClientSession", return_value=mock_session),
        ):
            _mock_http_transport(mock_client, mock_session)

            result = await mcp_client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, "https://example.com/mcp")

            assert result is False
            assert mcp_client.session is None
            # The failed attempt was torn down immediately
            mock_client.return_value.__aexit__.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_fails_when_handshake_times_out(self):
        mcp_client = MCPClient(timeout=1)
        mock_session = AsyncMock()

        async def hang():
            await asyncio.sleep(60)

        mock_session.initialize.side_effect = hang

        with (
            patch("mcpscore.mcp_client.streamable_http_client") as mock_client,
            patch("mcpscore.mcp_client.ClientSession", return_value=mock_session),
            patch("mcpscore.mcp_client.asyncio.wait_for", side_effect=TimeoutError),
        ):
            _mock_http_transport(mock_client, mock_session)

            result = await mcp_client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, "https://example.com/mcp")

            assert result is False
            assert mcp_client.session is None

    @pytest.mark.asyncio
    async def test_connect_fails_when_transport_cancels_task(self, mcp_client):
        """Treat CancelledError leaked by the transport as a failed connection."""
        mock_session = AsyncMock()
        mock_session.initialize.side_effect = asyncio.CancelledError()

        with (
            patch("mcpscore.mcp_client.streamable_http_client") as mock_client,
            patch("mcpscore.mcp_client.ClientSession", return_value=mock_session),
        ):
            _mock_http_transport(mock_client, mock_session)

            result = await mcp_client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, "https://example.com/mcp")

            assert result is False
            assert mcp_client.session is None

    @pytest.mark.asyncio
    async def test_genuine_cancellation_propagates(self, mcp_client):
        mock_session = AsyncMock()

        async def hang():
            await asyncio.sleep(60)

        mock_session.initialize.side_effect = hang

        with (
            patch("mcpscore.mcp_client.streamable_http_client") as mock_client,
            patch("mcpscore.mcp_client.ClientSession", return_value=mock_session),
        ):
            _mock_http_transport(mock_client, mock_session)

            task = asyncio.create_task(
                mcp_client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, "https://example.com/mcp")
            )
            await asyncio.sleep(0.01)
            task.cancel()

            with pytest.raises(asyncio.CancelledError):
                await task

    @pytest.mark.asyncio
    async def test_sse_connect_fails_when_handshake_raises(self, mcp_client):
        mock_session = AsyncMock()
        mock_session.initialize.side_effect = RuntimeError("not an MCP server")

        with (
            patch("mcpscore.mcp_client.sse_client") as mock_sse,
            patch("mcpscore.mcp_client.ClientSession", return_value=mock_session),
        ):
            mock_sse.return_value.__aenter__.return_value = (AsyncMock(), AsyncMock())
            mock_session.__aenter__.return_value = mock_session

            result = await mcp_client.connect_to_server(MCPTransportType.SSE, "https://example.com/sse")

            assert result is False
            assert mcp_client.session is None

    @pytest.mark.asyncio
    async def test_detect_and_connect_falls_back_to_sse_after_failed_http_handshake(self, mcp_client):
        http_session = AsyncMock()
        http_session.initialize.side_effect = asyncio.CancelledError()
        http_session.__aenter__.return_value = http_session

        sse_session = AsyncMock()
        sse_session.__aenter__.return_value = sse_session

        with (
            patch("mcpscore.mcp_client.streamable_http_client") as mock_http,
            patch("mcpscore.mcp_client.sse_client") as mock_sse,
            patch("mcpscore.mcp_client.ClientSession", side_effect=[http_session, sse_session]),
        ):
            mock_http.return_value.__aenter__.return_value = (
                AsyncMock(),
                AsyncMock(),
                MagicMock(return_value="test-session-id"),
            )
            mock_sse.return_value.__aenter__.return_value = (AsyncMock(), AsyncMock())

            success, transport = await mcp_client.detect_and_connect("https://example.com/mcp")

            assert success is True
            assert transport == MCPTransportType.SSE
            assert mcp_client.session is sse_session

    @pytest.mark.asyncio
    async def test_failed_attempt_teardown_error_is_swallowed(self, mcp_client):
        """Teardown errors from a failed attempt must not mask the connect result."""
        mock_session = AsyncMock()
        mock_session.initialize.side_effect = RuntimeError("handshake failed")

        with (
            patch("mcpscore.mcp_client.streamable_http_client") as mock_client,
            patch("mcpscore.mcp_client.ClientSession", return_value=mock_session),
        ):
            _mock_http_transport(mock_client, mock_session)
            mock_client.return_value.__aexit__.side_effect = RuntimeError("buffered transport error")

            result = await mcp_client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, "https://example.com/mcp")

            assert result is False
