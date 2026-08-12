"""Unit tests for MCPClient session operations error paths."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from mcp import InitializeResult, ListPromptsResult, ListResourcesResult, ListToolsResult
from mcp_types import ListResourceTemplatesResult, Prompt, Resource, ResourceTemplate, Tool
import pytest

from mcpscore.mcp_client import ERROR_NO_ACTIVE_SESSION, MCPClient


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

    async def test_initialize_no_session(self, mcp_client, caplog):
        """Test initialize fails when no session is active."""
        result = await mcp_client.initialize()

        assert result is None
        assert ERROR_NO_ACTIVE_SESSION in caplog.text

    async def test_initialize_exception(self, mock_connected_client, caplog):
        """Test initialize handles exceptions properly."""
        # Simulate exception during initialization
        mock_connected_client.session.initialize.side_effect = RuntimeError("Initialization failed")

        result = await mock_connected_client.initialize()

        assert result is None
        assert "Failed to initialize MCP server" in caplog.text

    async def test_initialize_success(self, mock_connected_client):
        """Test successful initialization."""
        mock_init_result = MagicMock(spec=InitializeResult)
        mock_connected_client.session.initialize.return_value = mock_init_result

        result = await mock_connected_client.initialize()

        assert result == mock_init_result
        mock_connected_client.session.initialize.assert_called_once()

    async def test_list_tools_no_session(self, mcp_client, caplog):
        """Test list_tools fails when no session is active."""
        result = await mcp_client.list_tools()

        assert result is None
        assert ERROR_NO_ACTIVE_SESSION in caplog.text

    async def test_list_tools_exception(self, mock_connected_client, caplog):
        """Test list_tools handles exceptions properly."""
        # Simulate exception during list_tools
        mock_connected_client.session.list_tools.side_effect = RuntimeError("Failed to list tools")

        result = await mock_connected_client.list_tools()

        assert result is None
        assert "Failed to list tools from the MCP server" in caplog.text

    async def test_list_tools_success(self, mock_connected_client):
        """Test successful list_tools."""
        mock_tools = [
            Tool(name="tool1", description="Test tool 1", input_schema={"type": "object"}),
            Tool(name="tool2", description="Test tool 2", input_schema={"type": "object"}),
        ]
        mock_result = ListToolsResult(tools=mock_tools)
        mock_connected_client.session.list_tools.return_value = mock_result

        result = await mock_connected_client.list_tools()

        assert result == mock_tools
        assert len(result) == 2
        mock_connected_client.session.list_tools.assert_called_once()

    async def test_list_resources_no_session(self, mcp_client, caplog):
        """Test list_resources fails when no session is active."""
        result = await mcp_client.list_resources()

        assert result is None
        assert ERROR_NO_ACTIVE_SESSION in caplog.text

    async def test_list_resources_exception(self, mock_connected_client, caplog):
        """Test list_resources handles exceptions properly."""
        # Simulate exception during list_resources
        mock_connected_client.session.list_resources.side_effect = RuntimeError("Failed to list resources")

        result = await mock_connected_client.list_resources()

        assert result is None
        assert "Failed to list resources from the MCP server" in caplog.text

    async def test_list_resources_success(self, mock_connected_client):
        """Test successful list_resources."""
        mock_resources = [
            Resource(uri="file:///test1.txt", name="Test Resource 1", mime_type="text/plain"),
            Resource(uri="file:///test2.txt", name="Test Resource 2", mime_type="text/plain"),
        ]
        mock_result = ListResourcesResult(resources=mock_resources)
        mock_connected_client.session.list_resources.return_value = mock_result

        result = await mock_connected_client.list_resources()

        assert result == mock_resources
        assert len(result) == 2
        mock_connected_client.session.list_resources.assert_called_once()

    async def test_list_prompts_no_session(self, mcp_client, caplog):
        """Test list_prompts fails when no session is active."""
        result = await mcp_client.list_prompts()

        assert result is None
        assert ERROR_NO_ACTIVE_SESSION in caplog.text

    async def test_list_prompts_exception(self, mock_connected_client, caplog):
        """Test list_prompts handles exceptions properly."""
        # Simulate exception during list_prompts
        mock_connected_client.session.list_prompts.side_effect = RuntimeError("Failed to list prompts")

        result = await mock_connected_client.list_prompts()

        assert result is None
        assert "Failed to list prompts from the MCP server" in caplog.text

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

    async def test_list_tools_empty_list(self, mock_connected_client):
        """Test list_tools returns empty list when no tools available."""
        mock_result = ListToolsResult(tools=[])
        mock_connected_client.session.list_tools.return_value = mock_result

        result = await mock_connected_client.list_tools()

        assert result == []
        assert len(result) == 0

    async def test_list_resources_empty_list(self, mock_connected_client):
        """Test list_resources returns empty list when no resources available."""
        mock_result = ListResourcesResult(resources=[])
        mock_connected_client.session.list_resources.return_value = mock_result

        result = await mock_connected_client.list_resources()

        assert result == []
        assert len(result) == 0

    async def test_list_prompts_empty_list(self, mock_connected_client):
        """Test list_prompts returns empty list when no prompts available."""
        mock_result = ListPromptsResult(prompts=[])
        mock_connected_client.session.list_prompts.return_value = mock_result

        result = await mock_connected_client.list_prompts()

        assert result == []
        assert len(result) == 0

    async def test_list_resource_templates_no_session(self, mcp_client, caplog):
        """Resource-template listing requires an active session."""
        assert await mcp_client.list_resource_templates() is None
        assert ERROR_NO_ACTIVE_SESSION in caplog.text

    async def test_list_resource_templates_success(self, mock_connected_client):
        """Resource templates are returned from a complete first page."""
        templates = [ResourceTemplate(name="users", uriTemplate="users/{id}")]
        mock_connected_client.session.list_resource_templates.return_value = ListResourceTemplatesResult(
            resourceTemplates=templates
        )

        assert await mock_connected_client.list_resource_templates() == templates
        mock_connected_client.session.list_resource_templates.assert_called_once()

    @pytest.mark.parametrize(
        ("method_name", "result_type", "item_field", "first_item", "second_item"),
        [
            (
                "list_tools",
                ListToolsResult,
                "tools",
                Tool(name="first", input_schema={"type": "object"}),
                Tool(name="second", input_schema={"type": "object"}),
            ),
            (
                "list_resources",
                ListResourcesResult,
                "resources",
                Resource(uri="file:///first", name="first"),
                Resource(uri="file:///second", name="second"),
            ),
            (
                "list_prompts",
                ListPromptsResult,
                "prompts",
                Prompt(name="first"),
                Prompt(name="second"),
            ),
            (
                "list_resource_templates",
                ListResourceTemplatesResult,
                "resource_templates",
                ResourceTemplate(name="first", uriTemplate="file:///{path}"),
                ResourceTemplate(name="second", uriTemplate="https://example.com/{id}"),
            ),
        ],
    )
    async def test_listing_collects_all_pages(
        self,
        mock_connected_client,
        method_name,
        result_type,
        item_field,
        first_item,
        second_item,
    ):
        """Every supported listing follows nextCursor and aggregates its pages."""
        session_method = getattr(mock_connected_client.session, method_name)
        session_method.side_effect = [
            result_type(**{item_field: [first_item], "nextCursor": ""}),
            result_type(**{item_field: [second_item]}),
        ]

        result = await getattr(mock_connected_client, method_name)()

        assert result == [first_item, second_item]
        assert session_method.call_count == 2
        assert session_method.call_args_list[0].args == ()
        assert session_method.call_args_list[1].kwargs["params"].cursor == ""
        assert mock_connected_client.incomplete_listings == set()

    async def test_repeated_cursor_stops_tools_listing_and_marks_it_incomplete(self, mock_connected_client, caplog):
        """A looping server cannot make pagination run forever."""
        first = Tool(name="first", input_schema={"type": "object"})
        second = Tool(name="second", input_schema={"type": "object"})
        mock_connected_client.session.list_tools.side_effect = [
            ListToolsResult(tools=[first], nextCursor="again"),
            ListToolsResult(tools=[second], nextCursor="again"),
        ]

        result = await mock_connected_client.list_tools()

        assert result == [first, second]
        assert mock_connected_client.incomplete_listings == {"tools"}
        assert "repeated cursor" in caplog.text

    async def test_later_page_failure_returns_partial_listing(self, mock_connected_client):
        """Evidence from successful pages remains usable but is labelled incomplete."""
        first = Resource(uri="file:///first", name="first")
        mock_connected_client.session.list_resources.side_effect = [
            ListResourcesResult(resources=[first], nextCursor="next"),
            RuntimeError("page failed"),
        ]

        result = await mock_connected_client.list_resources()

        assert result == [first]
        assert mock_connected_client.incomplete_listings == {"resources"}

    async def test_empty_partial_listing_is_a_list_not_none(self, mock_connected_client):
        """A successful-but-empty page followed by an error is partial evidence, not 'unavailable'.

        `None` would make every tool rule fail as "Tools object is not
        available"; an empty list with the incomplete marker lets rules skip
        or judge appropriately. (PR #63 Bugbot finding.)
        """
        mock_connected_client.session.list_tools.side_effect = [
            ListToolsResult(tools=[], nextCursor="next"),
            RuntimeError("page failed"),
        ]

        result = await mock_connected_client.list_tools()

        assert result == []
        assert result is not None
        assert mock_connected_client.incomplete_listings == {"tools"}

    async def test_first_page_failure_still_returns_none(self, mock_connected_client):
        """A listing that never produced a page keeps the historical None semantics."""
        mock_connected_client.session.list_tools.side_effect = RuntimeError("boom")

        result = await mock_connected_client.list_tools()

        assert result is None
        assert mock_connected_client.incomplete_listings == {"tools"}

    async def test_a_stalled_server_cannot_hang_a_listing(self, mock_connected_client, monkeypatch, caplog):
        """A server that accepts the request and never answers must not stall forever.

        This is the shape the 1.3.0 production-readiness review found (F-001)
        and the shape the 2026-08 registry sweep hit: 113 of 10,522 endpoints
        connect and then never complete. Before the listing budget, this test
        would hang until the suite timed out rather than fail.
        """
        monkeypatch.setattr("mcpscore.mcp_client.LISTING_TIMEOUT_S", 0.25)

        async def never_answers(*_args, **_kwargs):
            await asyncio.sleep(3600)

        mock_connected_client.session.list_tools.side_effect = never_answers

        result = await asyncio.wait_for(mock_connected_client.list_tools(), timeout=5)

        assert result is None
        assert mock_connected_client.incomplete_listings == {"tools"}

    async def test_listing_budget_keeps_pages_already_collected(self, mock_connected_client, monkeypatch, caplog):
        """Exhausting the budget mid-listing degrades to partial, not to nothing."""
        monkeypatch.setattr("mcpscore.mcp_client.LISTING_TIMEOUT_S", 0.3)

        async def one_page_then_stall(*_args, **_kwargs):
            if mock_connected_client.session.list_prompts.call_count <= 1:
                return ListPromptsResult(prompts=[Prompt(name="one")], nextCursor="second")
            await asyncio.sleep(3600)
            raise AssertionError("unreachable: the budget must fire first")

        mock_connected_client.session.list_prompts.side_effect = one_page_then_stall

        result = await asyncio.wait_for(mock_connected_client.list_prompts(), timeout=5)

        assert [prompt.name for prompt in result] == ["one"]
        assert mock_connected_client.incomplete_listings == {"prompts"}

    async def test_page_budget_stops_unbounded_prompt_listing(self, mock_connected_client, monkeypatch, caplog):
        """A server that always advances its cursor is still bounded."""
        monkeypatch.setattr("mcpscore.mcp_client.MAX_LISTING_PAGES", 2)
        mock_connected_client.session.list_prompts.side_effect = [
            ListPromptsResult(prompts=[Prompt(name="one")], nextCursor="second"),
            ListPromptsResult(prompts=[Prompt(name="two")], nextCursor="third"),
        ]

        result = await mock_connected_client.list_prompts()

        assert [prompt.name for prompt in result] == ["one", "two"]
        assert mock_connected_client.incomplete_listings == {"prompts"}
        assert "after 2 pages" in caplog.text
