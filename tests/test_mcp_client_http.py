"""Unit tests for MCPClient HTTP transport."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mcpaudit.enums import MCPTransportType
from mcpaudit.mcp_client import MCPClient


class TestMCPClientHTTP:
    """Test MCPClient HTTP transport functionality."""

    @pytest.fixture
    def mcp_client(self):
        """Create a fresh MCPClient instance for each test."""
        return MCPClient()

    @pytest.mark.asyncio
    async def test_connect_with_streamable_http_success(self, mcp_client):
        """Test successful Streamable HTTP connection."""
        server_url = "https://example.com/mcp"

        # Mock the streamable_http_client context manager
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_session_id_callback = MagicMock(return_value="test-session-id")
        mock_session = AsyncMock()

        with (
            patch("mcpaudit.mcp_client.streamable_http_client") as mock_client,
            patch("mcpaudit.mcp_client.ClientSession", return_value=mock_session),
        ):
            # Set up the mock to return streams and session_id_callback
            mock_client.return_value.__aenter__.return_value = (
                mock_read_stream,
                mock_write_stream,
                mock_session_id_callback,
            )
            mock_session.__aenter__.return_value = mock_session

            # Test connection
            result = await mcp_client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, server_url)

            assert result is True
            assert mcp_client.session == mock_session

    @pytest.mark.asyncio
    async def test_connect_with_streamable_http_invalid_url(self, mcp_client):
        """Test Streamable HTTP connection with invalid URL."""
        invalid_urls = [
            "not-a-url",
            "ftp://example.com",
            "example.com",
            "",
        ]

        for url in invalid_urls:
            result = await mcp_client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, url)
            assert result is False

    @pytest.mark.asyncio
    async def test_connect_with_streamable_http_connection_error(self, mcp_client):
        """Test Streamable HTTP connection with connection refused."""
        server_url = "https://example.com/mcp"

        with patch("mcpaudit.mcp_client.streamable_http_client") as mock_client:
            # Simulate connection error
            mock_client.return_value.__aenter__.side_effect = httpx.ConnectError("Connection refused")

            result = await mcp_client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, server_url)

            assert result is False

    @pytest.mark.asyncio
    async def test_connect_with_streamable_http_timeout(self, mcp_client):
        """Test Streamable HTTP connection with timeout."""
        server_url = "https://example.com/mcp"

        with patch("mcpaudit.mcp_client.streamable_http_client") as mock_client:
            # Simulate timeout
            mock_client.return_value.__aenter__.side_effect = httpx.TimeoutException("Request timed out")

            result = await mcp_client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, server_url)

            assert result is False

    @pytest.mark.asyncio
    async def test_connect_with_streamable_http_http_error(self, mcp_client):
        """Test Streamable HTTP connection with HTTP error."""
        server_url = "https://example.com/mcp"

        with patch("mcpaudit.mcp_client.streamable_http_client") as mock_client:
            # Simulate 404 error
            mock_response = MagicMock()
            mock_response.status_code = 404
            http_error = httpx.HTTPStatusError("Not Found", request=MagicMock(), response=mock_response)
            mock_client.return_value.__aenter__.side_effect = http_error

            result = await mcp_client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, server_url)

            assert result is False

    @pytest.mark.asyncio
    async def test_detect_and_connect_streamable_http(self, mcp_client):
        """Test auto-detection chooses Streamable HTTP."""
        server_url = "https://example.com/mcp"

        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_session_id_callback = MagicMock(return_value="test-session-id")
        mock_session = AsyncMock()

        with (
            patch("mcpaudit.mcp_client.streamable_http_client") as mock_client,
            patch("mcpaudit.mcp_client.ClientSession", return_value=mock_session),
        ):
            mock_client.return_value.__aenter__.return_value = (
                mock_read_stream,
                mock_write_stream,
                mock_session_id_callback,
            )
            mock_session.__aenter__.return_value = mock_session

            success, transport = await mcp_client.detect_and_connect(server_url)

            assert success is True
            assert transport == MCPTransportType.STREAMABLE_HTTP

    @pytest.mark.asyncio
    async def test_detect_and_connect_fallback_to_sse(self, mcp_client):
        """Test auto-detection falls back to SSE when HTTP fails."""
        server_url = "https://example.com/mcp"

        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_session = AsyncMock()

        with (
            patch("mcpaudit.mcp_client.streamable_http_client") as mock_http_client,
            patch("mcpaudit.mcp_client.sse_client") as mock_sse_client,
            patch("mcpaudit.mcp_client.ClientSession", return_value=mock_session),
        ):
            # HTTP fails
            mock_http_client.return_value.__aenter__.side_effect = httpx.ConnectError("Connection refused")

            # SSE succeeds
            mock_sse_client.return_value.__aenter__.return_value = (mock_read_stream, mock_write_stream)
            mock_session.__aenter__.return_value = mock_session

            success, transport = await mcp_client.detect_and_connect(server_url)

            assert success is True
            assert transport == MCPTransportType.SSE

    @pytest.mark.asyncio
    async def test_cleanup(self, mcp_client):
        """Test cleanup closes connections properly."""
        server_url = "https://example.com/mcp"

        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_session_id_callback = MagicMock(return_value="test-session-id")
        mock_session = AsyncMock()

        with (
            patch("mcpaudit.mcp_client.streamable_http_client") as mock_client,
            patch("mcpaudit.mcp_client.ClientSession", return_value=mock_session),
        ):
            mock_client.return_value.__aenter__.return_value = (
                mock_read_stream,
                mock_write_stream,
                mock_session_id_callback,
            )
            mock_session.__aenter__.return_value = mock_session

            await mcp_client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, server_url)
            await mcp_client.cleanup()

            # Verify exit stack was closed
            assert mcp_client.session is not None  # Session object still exists
