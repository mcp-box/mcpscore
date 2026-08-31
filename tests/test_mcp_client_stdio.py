"""Unit tests for MCPClient STDIO transport error paths."""

import logging
from unittest.mock import AsyncMock, patch

import pytest

from mcpscore.enums import MCPTransportType
from mcpscore.mcp_client import MCPClient, StdioCommand


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
            assert "Permission denied launching server" in caplog.text

    async def test_connect_stdio_generic_exception(self, mcp_client, caplog):
        """Test stdio connection with generic exception."""
        server_path = "server.py"

        with patch("mcpscore.mcp_client.stdio_client") as mock_client, caplog.at_level(logging.INFO):
            # Simulate generic exception
            mock_client.return_value.__aenter__.side_effect = RuntimeError("Unexpected error")

            result = await mcp_client._connect_with_stdio(server_path)

            assert result is False
            assert "Legacy MCP initialize handshake failed" in caplog.text

    async def test_failed_handshake_retains_launch_parameters_for_modern_fallback(self, mcp_client):
        """A rejected legacy handshake must not discard the probe launch spec."""
        with patch.object(
            mcp_client,
            "_establish_session",
            new=AsyncMock(side_effect=RuntimeError("modern-only server rejected initialize")),
        ):
            result = await mcp_client._connect_with_stdio("server.py")

        assert result is False
        assert mcp_client.stdio_params is not None
        assert mcp_client.stdio_params.args == ["server.py"]

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


class TestStdioCommand:
    """Generic stdio commands: any-language local servers via StdioCommand."""

    @pytest.fixture
    def mcp_client(self):
        return MCPClient()

    async def test_display_joins_command_and_args(self):
        cmd = StdioCommand(command="java", args=("-jar", "server.jar"))
        assert cmd.display == "java -jar server.jar"

    async def test_detect_and_connect_dispatches_stdio_command(self, mcp_client):
        cmd = StdioCommand(command="./server")
        with patch.object(mcp_client, "_connect_with_stdio_command", return_value=True) as connect:
            success, transport = await mcp_client.detect_and_connect(cmd)
        assert success is True
        assert transport is MCPTransportType.STDIO
        connect.assert_awaited_once_with(cmd)

    async def test_detect_and_connect_stdio_command_failure(self, mcp_client):
        cmd = StdioCommand(command="./server")
        with patch.object(mcp_client, "_connect_with_stdio_command", return_value=False):
            success, transport = await mcp_client.detect_and_connect(cmd)
        assert success is False
        assert transport is None

    async def test_command_passed_through_without_env(self, mcp_client):
        """No --env: the SDK's own default environment handling applies (env=None)."""
        cmd = StdioCommand(command="dotnet", args=("run", "--project", "./srv"))
        with (
            patch("mcpscore.mcp_client.stdio_client") as mock_stdio,
            patch.object(mcp_client, "_establish_session", new=AsyncMock()) as establish,
        ):
            result = await mcp_client._connect_with_stdio_command(cmd)
        assert result is True
        params = mock_stdio.call_args.args[0]
        assert params.command == "dotnet"
        assert params.args == ["run", "--project", "./srv"]
        assert params.env is None
        establish.assert_awaited_once()

    async def test_env_merged_over_default_environment(self, mcp_client):
        """--env vars land on top of the SDK default env, not instead of it."""
        cmd = StdioCommand(command="./server", env={"API_KEY": "secret", "PATH": "/custom"})
        with (
            patch("mcpscore.mcp_client.stdio_client") as mock_stdio,
            patch("mcpscore.mcp_client.get_default_environment", return_value={"PATH": "/usr/bin", "HOME": "/home"}),
            patch.object(mcp_client, "_establish_session", new=AsyncMock()),
        ):
            result = await mcp_client._connect_with_stdio_command(cmd)
        assert result is True
        params = mock_stdio.call_args.args[0]
        assert params.env == {"PATH": "/custom", "HOME": "/home", "API_KEY": "secret"}

    async def test_command_not_found_names_the_command(self, mcp_client, caplog):
        cmd = StdioCommand(command="no-such-binary")
        with patch("mcpscore.mcp_client.stdio_client") as mock_stdio:
            mock_stdio.return_value.__aenter__.side_effect = FileNotFoundError("not found")
            result = await mcp_client._connect_with_stdio_command(cmd)
        assert result is False
        assert "Command not found: 'no-such-binary'" in caplog.text
        assert mcp_client.last_connection_error is not None

    async def test_command_handshake_timeout_classified(self, mcp_client, caplog):
        cmd = StdioCommand(command="./slow-server")
        with patch("mcpscore.mcp_client.stdio_client") as mock_stdio:
            mock_stdio.return_value.__aenter__.side_effect = TimeoutError()
            result = await mcp_client._connect_with_stdio_command(cmd)
        assert result is False
        assert "handshake timed out" in caplog.text
        assert "./slow-server" in caplog.text
        assert mcp_client.last_connection_error.reason.value == "timeout"

    async def test_command_handshake_cancelled_classified_not_mcp(self, mcp_client, caplog):
        """Classify an SDK-teardown CancelledError as NOT_MCP, not a re-raise.

        The cancellation comes from the SDK's context teardown, not from our
        own task being cancelled — it means the process spoke no MCP.
        """
        import asyncio

        cmd = StdioCommand(command="./not-an-mcp-server")
        with patch("mcpscore.mcp_client.stdio_client") as mock_stdio:
            mock_stdio.return_value.__aenter__.side_effect = asyncio.CancelledError()
            result = await mcp_client._connect_with_stdio_command(cmd)
        assert result is False
        assert "handshake failed" in caplog.text
        assert mcp_client.last_connection_error.reason.value == "not_mcp"


class TestStdioCommandRealProcess:
    """End-to-end: launch a real server process, no transport mocking.

    Guards the integration the mocked tests cannot see: StdioServerParameters,
    the SDK's environment handling, actual process launch, and the MCP
    handshake working together.
    """

    async def test_handshake_and_env_round_trip_through_real_process(self):
        from pathlib import Path
        import sys as _sys

        server = str(Path(__file__).parent / "stdio_e2e_server.py")
        cmd = StdioCommand(
            command=_sys.executable,
            args=(server,),
            env={"MCPSCORE_E2E_ENV": "env-round-trip-proof"},
        )
        client = MCPClient()
        try:
            success, transport = await client.detect_and_connect(cmd)
            assert success is True
            assert transport is MCPTransportType.STDIO
            # The env var reached the real subprocess: the server echoes it
            # back as its version through the actual handshake.
            assert client._init_result is not None
            assert client._init_result.server_info.version == "env-round-trip-proof"
        finally:
            await client.cleanup()
