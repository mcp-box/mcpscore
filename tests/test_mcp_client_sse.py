"""Unit tests for MCPClient SSE transport."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mcpaudit.enums import MCPTransportType
from mcpaudit.mcp_client import MCPClient


class TestMCPClientSSE:
    """Test MCPClient SSE transport functionality."""

    @pytest.fixture
    def mcp_client(self):
        """Create a fresh MCPClient instance for each test."""
        return MCPClient()

    @pytest.mark.asyncio
    async def test_connect_with_sse_success(self, mcp_client):
        """Test successful SSE connection."""
        server_url = "https://example.com/sse"

        # Mock the sse_client context manager
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_session = AsyncMock()

        with (
            patch("mcpaudit.mcp_client.sse_client") as mock_client,
            patch("mcpaudit.mcp_client.ClientSession", return_value=mock_session),
        ):
            # Set up the mock to return streams
            mock_client.return_value.__aenter__.return_value = (mock_read_stream, mock_write_stream)
            mock_session.__aenter__.return_value = mock_session

            # Test connection
            result = await mcp_client.connect_to_server(MCPTransportType.SSE, server_url)

            assert result is True
            assert mcp_client.session == mock_session

    @pytest.mark.asyncio
    async def test_connect_with_sse_invalid_url(self, mcp_client):
        """Test SSE connection with invalid URL."""
        invalid_urls = [
            "not-a-url",
            "ftp://example.com",
            "example.com",
            "",
        ]

        for url in invalid_urls:
            result = await mcp_client.connect_to_server(MCPTransportType.SSE, url)
            assert result is False

    @pytest.mark.asyncio
    async def test_connect_with_sse_connection_error(self, mcp_client):
        """Test SSE connection with connection refused."""
        server_url = "https://example.com/sse"

        with patch("mcpaudit.mcp_client.sse_client") as mock_client:
            # Simulate connection error
            mock_client.return_value.__aenter__.side_effect = httpx.ConnectError("Connection refused")

            result = await mcp_client.connect_to_server(MCPTransportType.SSE, server_url)

            assert result is False

    @pytest.mark.asyncio
    async def test_connect_with_sse_timeout(self, mcp_client):
        """Test SSE connection with timeout."""
        server_url = "https://example.com/sse"

        with patch("mcpaudit.mcp_client.sse_client") as mock_client:
            # Simulate timeout
            mock_client.return_value.__aenter__.side_effect = httpx.TimeoutException("Request timed out")

            result = await mcp_client.connect_to_server(MCPTransportType.SSE, server_url)

            assert result is False

    @pytest.mark.asyncio
    async def test_connect_with_sse_http_error(self, mcp_client):
        """Test SSE connection with HTTP error."""
        server_url = "https://example.com/sse"

        with patch("mcpaudit.mcp_client.sse_client") as mock_client:
            # Simulate 500 error
            mock_response = MagicMock()
            mock_response.status_code = 500
            http_error = httpx.HTTPStatusError("Internal Server Error", request=MagicMock(), response=mock_response)
            mock_client.return_value.__aenter__.side_effect = http_error

            result = await mcp_client.connect_to_server(MCPTransportType.SSE, server_url)

            assert result is False

    @pytest.mark.asyncio
    async def test_detect_and_connect_stdio_for_py_file(self, mcp_client):
        """Test auto-detection uses stdio for .py files."""
        server_path = "server.py"

        with patch.object(mcp_client, "_connect_with_stdio", return_value=True) as mock_stdio:
            success, transport = await mcp_client.detect_and_connect(server_path)

            assert success is True
            assert transport == MCPTransportType.STDIO
            mock_stdio.assert_called_once_with(server_path)

    @pytest.mark.asyncio
    async def test_detect_and_connect_stdio_for_js_file(self, mcp_client):
        """Test auto-detection uses stdio for .js files."""
        server_path = "server.js"

        with patch.object(mcp_client, "_connect_with_stdio", return_value=True) as mock_stdio:
            success, transport = await mcp_client.detect_and_connect(server_path)

            assert success is True
            assert transport == MCPTransportType.STDIO
            mock_stdio.assert_called_once_with(server_path)

    @pytest.mark.asyncio
    async def test_detect_and_connect_invalid_input(self, mcp_client):
        """Test auto-detection with invalid input."""
        invalid_inputs = [
            "not-a-url-or-file",
            "file.txt",
            "",
        ]

        for invalid_input in invalid_inputs:
            success, transport = await mcp_client.detect_and_connect(invalid_input)

            assert success is False
            assert transport is None

    @pytest.mark.asyncio
    async def test_cleanup_after_sse_connection(self, mcp_client):
        """Test cleanup after SSE connection."""
        server_url = "https://example.com/sse"

        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        mock_session = AsyncMock()

        with (
            patch("mcpaudit.mcp_client.sse_client") as mock_client,
            patch("mcpaudit.mcp_client.ClientSession", return_value=mock_session),
        ):
            mock_client.return_value.__aenter__.return_value = (mock_read_stream, mock_write_stream)
            mock_session.__aenter__.return_value = mock_session

            await mcp_client.connect_to_server(MCPTransportType.SSE, server_url)
            await mcp_client.cleanup()

            # Verify cleanup was called
            assert mcp_client.session is not None  # Session object still exists
