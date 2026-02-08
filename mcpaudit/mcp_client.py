from contextlib import AsyncExitStack
import logging
import sys
from typing import Literal

from mcp import (
    ClientSession,
    InitializeResult,
    ListPromptsResult,
    ListResourcesResult,
    ListToolsResult,
    StdioServerParameters,
)
from mcp.client.stdio import stdio_client
from mcp.types import Prompt, Resource, Tool

from .enums import MCPTransportType

logger = logging.getLogger(__name__)

ERROR_NO_ACTIVE_SESSION = "No active session, connect to the MCP server first!"


class MCPClient:
    """Client for connecting to and communicating with MCP (Model Context Protocol) servers.

    This class provides a high-level interface for:
    - Establishing connections to MCP servers via various transport methods
    - Initializing server sessions
    - Listing available tools and resources
    - Managing connection lifecycle and cleanup

    Currently supports stdio transport for local server processes.
    """

    def __init__(self, timeout: int | None = None) -> None:
        """Initialize a new MCP client instance.

        Args:
            timeout: Connection timeout in seconds (None for no timeout)

        Sets up the client with an empty session and async exit stack for resource management.
        """
        super().__init__()
        self.session: ClientSession | None = None
        self.exit_stack: AsyncExitStack = AsyncExitStack()
        self.timeout: int | None = timeout

    async def connect_to_server(self, transport: MCPTransportType, server_path: str) -> bool:
        """Connect to an MCP server using the specified transport method.

        Args:
            transport: The transport method to use (currently only STDIO supported)
            server_path: Path to the server script file (.py or .js)

        Returns:
            True if a connection was successful, False otherwise

        Raises:
            Logs errors for unsupported transport types or invalid server paths

        """
        result: bool = False

        match transport:
            case MCPTransportType.STDIO:
                result = await self._connect_with_stdio(server_path)
            case _:
                logger.error("This protocol is not supported: %s", transport)

        return result

    async def _connect_with_stdio(self, server_script_path: str) -> bool:
        """Establish a stdio connection to a local MCP server process.

        Args:
            server_script_path: Path to the server script (.py or .js file)

        Returns:
            True if a connection was successful, False otherwise

        Note:
            Automatically detects a script type and uses an appropriate launcher.
            For Python scripts, uses sys.executable to ensure compatibility.

        """
        is_python: bool = server_script_path.endswith(".py")
        is_js: bool = server_script_path.endswith(".js")
        if not (is_python or is_js):
            logger.error("Server script must be a .py or .js file")
            return False

        # Use sys.executable for Python to ensure we use the same interpreter
        command: str = sys.executable if is_python else "node"
        server_params = StdioServerParameters(command=command, args=[server_script_path], env=None)

        try:
            self.stdio, self.write = await self.exit_stack.enter_async_context(stdio_client(server_params))
            self.session = await self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))
            return True
        except FileNotFoundError as e:
            if is_python:
                logger.error("Python interpreter not found. Please ensure Python is installed and on PATH.")
            else:
                logger.error("Node.js not found. Please ensure Node.js is installed and on PATH.")
            logger.debug("Error details: %s", e)
            return False
        except PermissionError as e:
            logger.error("Permission denied accessing server script: %s", server_script_path)
            logger.debug("Error details: %s", e)
            return False
        except Exception as e:
            logger.error("Failed to connect to MCP server: %s", e)
            logger.debug("Full error details:", exc_info=True)
            return False

    async def initialize(self) -> InitializeResult | None:
        """Initialize the MCP server session.

        Performs the MCP handshake and retrieves server capabilities and information.

        Returns:
            InitializeResult containing server info, capabilities, and protocol version,
            or None if initialization failed

        Note:
            Must be called after successfully connecting to a server

        """
        if not self.session:
            logger.error(ERROR_NO_ACTIVE_SESSION)
            return None

        try:
            init_result: InitializeResult = await self.session.initialize()
            return init_result
        except Exception:
            logger.exception("Failed to initialize MCP server")
            return None

    async def list_tools(self) -> list[Tool] | None:
        """List and display all available tools from the MCP server.

        Retrieves the server's tools and logs detailed information about
        each available tool, including name, description, and input schema.

        Note:
            Must be called after successfully initializing the server session

        """
        if not self.session:
            logger.error(ERROR_NO_ACTIVE_SESSION)
            return None

        try:
            response: ListToolsResult = await self.session.list_tools()
            # TODO: Add support for nextCursor
            return response.tools
        except Exception:
            logger.exception("Failed to list tools from the MCP server")
            return None

    async def list_resources(self) -> list[Resource] | None:
        """List and display all available resources from the MCP server.

        Retrieves the server's resources

        Note:
            Must be called after successfully initializing the server session

        """
        if not self.session:
            logger.error(ERROR_NO_ACTIVE_SESSION)
            return None

        try:
            response: ListResourcesResult = await self.session.list_resources()
            # TODO: Add support for nextCursor
            return response.resources
        except Exception:
            logger.exception("Failed to list resources from the MCP server")
            return None

    async def list_prompts(self) -> list[Prompt] | None:
        """List and display all available prompts from the MCP server.

        Retrieves the server's prompts

        Note:
            Must be called after successfully initializing the server session

        """
        if not self.session:
            logger.error(ERROR_NO_ACTIVE_SESSION)
            return None

        try:
            response: ListPromptsResult = await self.session.list_prompts()
            # TODO: Add support for nextCursor
            return response.prompts
        except Exception:
            logger.exception("Failed to list prompts from the MCP server")
            return None

    async def cleanup(self) -> None:
        """Clean up client resources and close all connections.

        Properly closes the async exit stack, which will:
        - Close the stdio transport
        - Close the client session
        - Clean up any other managed resources

        Should be called when the client is no longer needed to prevent resource leaks.
        """
        await self.exit_stack.aclose()
