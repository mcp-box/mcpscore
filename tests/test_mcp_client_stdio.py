"""Unit tests for MCPClient STDIO transport error paths."""

from unittest.mock import AsyncMock, patch

import pytest

from mcpscore.enums import MCPTransportType
from mcpscore.mcp_client import MCPClient


class TestMCPClientStdioErrors:
    """Test MCPClient STDIO transport error handling."""

    @pytest.fixture
    def mcp_client(self):
        """Create a fresh MCPClient instance for each test."""
        return MCPClient()

    async def test_connect_stdio_invalid_file_extension(self, mcp_client, caplog):
        """Test stdio connection with invalid file extension."""
        invalid_paths = [
            "server.txt",
            "server.sh",
            "server",
            "server.exe",
        ]

        for path in invalid_paths:
            result = await mcp_client._connect_with_stdio(path)
            assert result is False
            assert "Server script must be a .py or .js file" in caplog.text

    async def test_connect_stdio_python_filenotfound(self, mcp_client, caplog):
        """Test stdio connection with Python interpreter not found."""
        server_path = "server.py"

        with patch("mcpscore.mcp_client.stdio_client") as mock_client:
            # Simulate FileNotFoundError (Python not found)
            mock_client.return_value.__aenter__.side_effect = FileNotFoundError("python not found")

            result = await mcp_client._connect_with_stdio(server_path)

            assert result is False
            assert "Python interpreter not found" in caplog.text

    async def test_connect_stdio_nodejs_filenotfound(self, mcp_client, caplog):
        """Test stdio connection with Node.js not found."""
        server_path = "server.js"

        with patch("mcpscore.mcp_client.stdio_client") as mock_client:
            # Simulate FileNotFoundError (Node.js not found)
            mock_client.return_value.__aenter__.side_effect = FileNotFoundError("node not found")

            result = await mcp_client._connect_with_stdio(server_path)

            assert result is False
            assert "Node.js not found" in caplog.text

    async def test_connect_stdio_permission_error(self, mcp_client, caplog):
        """Test stdio connection with permission denied."""
        server_path = "server.py"

        with patch("mcpscore.mcp_client.stdio_client") as mock_client:
            # Simulate PermissionError
            mock_client.return_value.__aenter__.side_effect = PermissionError("Permission denied")

            result = await mcp_client._connect_with_stdio(server_path)

            assert result is False
            assert "Permission denied accessing server script" in caplog.text

    async def test_connect_stdio_generic_exception(self, mcp_client, caplog):
        """Test stdio connection with generic exception."""
        server_path = "server.py"

        with patch("mcpscore.mcp_client.stdio_client") as mock_client:
            # Simulate generic exception
            mock_client.return_value.__aenter__.side_effect = RuntimeError("Unexpected error")

            result = await mcp_client._connect_with_stdio(server_path)

            assert result is False
            assert "Failed to connect to MCP server" in caplog.text

    async def test_connect_stdio_success_python(self, mcp_client):
        """Test successful stdio connection with Python server."""
        server_path = "server.py"

        mock_stdio = AsyncMock()
        mock_write = AsyncMock()
        mock_session = AsyncMock()

        with (
            patch("mcpscore.mcp_client.stdio_client") as mock_client,
            patch("mcpscore.mcp_client.ClientSession", return_value=mock_session),
        ):
            # Set up successful connection
            mock_client.return_value.__aenter__.return_value = (mock_stdio, mock_write)
            mock_session.__aenter__.return_value = mock_session

            result = await mcp_client._connect_with_stdio(server_path)

            assert result is True
            assert mcp_client.session == mock_session
            assert mcp_client.transport_type == MCPTransportType.STDIO
            assert mcp_client.url is None

    async def test_connect_stdio_success_nodejs(self, mcp_client):
        """Test successful stdio connection with Node.js server."""
        server_path = "server.js"

        mock_stdio = AsyncMock()
        mock_write = AsyncMock()
        mock_session = AsyncMock()

        with (
            patch("mcpscore.mcp_client.stdio_client") as mock_client,
            patch("mcpscore.mcp_client.ClientSession", return_value=mock_session),
        ):
            # Set up successful connection
            mock_client.return_value.__aenter__.return_value = (mock_stdio, mock_write)
            mock_session.__aenter__.return_value = mock_session

            result = await mcp_client._connect_with_stdio(server_path)

            assert result is True
            assert mcp_client.session == mock_session
            assert mcp_client.transport_type == MCPTransportType.STDIO

    async def test_detect_and_connect_stdio_failure(self, mcp_client):
        """Test detect_and_connect returns None transport on stdio failure."""
        server_path = "server.py"

        with patch.object(mcp_client, "_connect_with_stdio", return_value=False):
            success, transport = await mcp_client.detect_and_connect(server_path)

            assert success is False
            assert transport is None
