"""Unit tests for MCPClient session operations error paths."""

from unittest.mock import AsyncMock, MagicMock

from mcp import InitializeResult, ListPromptsResult, ListResourcesResult, ListToolsResult
from mcp.types import Prompt, Resource, Tool
from pydantic import AnyUrl
import pytest

from mcpaudit.mcp_client import ERROR_NO_ACTIVE_SESSION, MCPClient


class TestMCPClientSessionOperations:
    """Test MCPClient session operations error handling."""

    @pytest.fixture
    def mcp_client(self):
        """Create a fresh MCPClient instance for each test."""
        return MCPClient()

    @pytest.fixture
    def mock_connected_client(self, mcp_client):
        """Create a client with a mocked session."""
        mcp_client.session = AsyncMock()
        return mcp_client

    @pytest.mark.asyncio
    async def test_initialize_no_session(self, mcp_client, caplog):
        """Test initialize fails when no session is active."""
        result = await mcp_client.initialize()

        assert result is None
        assert ERROR_NO_ACTIVE_SESSION in caplog.text

    @pytest.mark.asyncio
    async def test_initialize_exception(self, mock_connected_client, caplog):
        """Test initialize handles exceptions properly."""
        # Simulate exception during initialization
        mock_connected_client.session.initialize.side_effect = RuntimeError("Initialization failed")

        result = await mock_connected_client.initialize()

        assert result is None
        assert "Failed to initialize MCP server" in caplog.text

    @pytest.mark.asyncio
    async def test_initialize_success(self, mock_connected_client):
        """Test successful initialization."""
        mock_init_result = MagicMock(spec=InitializeResult)
        mock_connected_client.session.initialize.return_value = mock_init_result

        result = await mock_connected_client.initialize()

        assert result == mock_init_result
        mock_connected_client.session.initialize.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_tools_no_session(self, mcp_client, caplog):
        """Test list_tools fails when no session is active."""
        result = await mcp_client.list_tools()

        assert result is None
        assert ERROR_NO_ACTIVE_SESSION in caplog.text

    @pytest.mark.asyncio
    async def test_list_tools_exception(self, mock_connected_client, caplog):
        """Test list_tools handles exceptions properly."""
        # Simulate exception during list_tools
        mock_connected_client.session.list_tools.side_effect = RuntimeError("Failed to list tools")

        result = await mock_connected_client.list_tools()

        assert result is None
        assert "Failed to list tools from the MCP server" in caplog.text

    @pytest.mark.asyncio
    async def test_list_tools_success(self, mock_connected_client):
        """Test successful list_tools."""
        mock_tools = [
            Tool(name="tool1", description="Test tool 1", inputSchema={"type": "object"}),
            Tool(name="tool2", description="Test tool 2", inputSchema={"type": "object"}),
        ]
        mock_result = ListToolsResult(tools=mock_tools)
        mock_connected_client.session.list_tools.return_value = mock_result

        result = await mock_connected_client.list_tools()

        assert result == mock_tools
        assert len(result) == 2
        mock_connected_client.session.list_tools.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_resources_no_session(self, mcp_client, caplog):
        """Test list_resources fails when no session is active."""
        result = await mcp_client.list_resources()

        assert result is None
        assert ERROR_NO_ACTIVE_SESSION in caplog.text

    @pytest.mark.asyncio
    async def test_list_resources_exception(self, mock_connected_client, caplog):
        """Test list_resources handles exceptions properly."""
        # Simulate exception during list_resources
        mock_connected_client.session.list_resources.side_effect = RuntimeError("Failed to list resources")

        result = await mock_connected_client.list_resources()

        assert result is None
        assert "Failed to list resources from the MCP server" in caplog.text

    @pytest.mark.asyncio
    async def test_list_resources_success(self, mock_connected_client):
        """Test successful list_resources."""
        mock_resources = [
            Resource(uri=AnyUrl("file:///test1.txt"), name="Test Resource 1", mimeType="text/plain"),
            Resource(uri=AnyUrl("file:///test2.txt"), name="Test Resource 2", mimeType="text/plain"),
        ]
        mock_result = ListResourcesResult(resources=mock_resources)
        mock_connected_client.session.list_resources.return_value = mock_result

        result = await mock_connected_client.list_resources()

        assert result == mock_resources
        assert len(result) == 2
        mock_connected_client.session.list_resources.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_prompts_no_session(self, mcp_client, caplog):
        """Test list_prompts fails when no session is active."""
        result = await mcp_client.list_prompts()

        assert result is None
        assert ERROR_NO_ACTIVE_SESSION in caplog.text

    @pytest.mark.asyncio
    async def test_list_prompts_exception(self, mock_connected_client, caplog):
        """Test list_prompts handles exceptions properly."""
        # Simulate exception during list_prompts
        mock_connected_client.session.list_prompts.side_effect = RuntimeError("Failed to list prompts")

        result = await mock_connected_client.list_prompts()

        assert result is None
        assert "Failed to list prompts from the MCP server" in caplog.text

    @pytest.mark.asyncio
    async def test_list_prompts_success(self, mock_connected_client):
        """Test successful list_prompts."""
        mock_prompts = [
            Prompt(name="prompt1", description="Test prompt 1"),
            Prompt(name="prompt2", description="Test prompt 2"),
        ]
        mock_result = ListPromptsResult(prompts=mock_prompts)
        mock_connected_client.session.list_prompts.return_value = mock_result

        result = await mock_connected_client.list_prompts()

        assert result == mock_prompts
        assert len(result) == 2
        mock_connected_client.session.list_prompts.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_tools_empty_list(self, mock_connected_client):
        """Test list_tools returns empty list when no tools available."""
        mock_result = ListToolsResult(tools=[])
        mock_connected_client.session.list_tools.return_value = mock_result

        result = await mock_connected_client.list_tools()

        assert result == []
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_list_resources_empty_list(self, mock_connected_client):
        """Test list_resources returns empty list when no resources available."""
        mock_result = ListResourcesResult(resources=[])
        mock_connected_client.session.list_resources.return_value = mock_result

        result = await mock_connected_client.list_resources()

        assert result == []
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_list_prompts_empty_list(self, mock_connected_client):
        """Test list_prompts returns empty list when no prompts available."""
        mock_result = ListPromptsResult(prompts=[])
        mock_connected_client.session.list_prompts.return_value = mock_result

        result = await mock_connected_client.list_prompts()

        assert result == []
        assert len(result) == 0
