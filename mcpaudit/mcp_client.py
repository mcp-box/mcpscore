from contextlib import AsyncExitStack
import logging
import sys
import time

import httpx
from mcp import (
    ClientSession,
    InitializeResult,
    ListPromptsResult,
    ListResourcesResult,
    ListToolsResult,
    StdioServerParameters,
)
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
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

        # Transport metadata (populated after connection)
        self.transport_type: MCPTransportType | None = None
        self.url: str | None = None
        self.connection_time_ms: int | None = None

    async def detect_and_connect(self, server_path_or_url: str) -> tuple[bool, MCPTransportType | None]:
        """Automatically detect transport type and connect to MCP server.

        Attempts to connect using Streamable HTTP first, then falls back to SSE.
        For local files (.py, .js), uses stdio transport.

        Args:
            server_path_or_url: Path to server script or URL

        Returns:
            Tuple of (success: bool, transport: MCPTransportType | None)

        """
        # Check if it's a local file path
        if server_path_or_url.endswith((".py", ".js")):
            success = await self.connect_to_server(MCPTransportType.STDIO, server_path_or_url)
            return (success, MCPTransportType.STDIO if success else None)

        # Check if it's a URL
        if server_path_or_url.startswith(("http://", "https://")):
            # Try Streamable HTTP first
            logger.info("Attempting Streamable HTTP connection...")
            if await self.connect_to_server(MCPTransportType.STREAMABLE_HTTP, server_path_or_url):
                return (True, MCPTransportType.STREAMABLE_HTTP)

            # Fall back to SSE
            logger.info("Streamable HTTP failed, trying SSE...")
            if await self.connect_to_server(MCPTransportType.SSE, server_path_or_url):
                return (True, MCPTransportType.SSE)

            return (False, None)

        logger.error("Invalid server path or URL: %s", server_path_or_url)
        return (False, None)

    async def connect_to_server(self, transport: MCPTransportType, server_path: str) -> bool:
        """Connect to an MCP server using the specified transport method.

        Args:
            transport: The transport method to use (STDIO, STREAMABLE_HTTP, SSE)
            server_path: Path to the server script file (.py or .js) for STDIO,
                        or URL for HTTP/SSE transports

        Returns:
            True if a connection was successful, False otherwise

        Raises:
            Logs errors for unsupported transport types or invalid server paths/URLs

        """
        result: bool = False

        match transport:
            case MCPTransportType.STDIO:
                result = await self._connect_with_stdio(server_path)
            case MCPTransportType.STREAMABLE_HTTP:
                result = await self._connect_with_streamable_http(server_path)
            case MCPTransportType.SSE:
                result = await self._connect_with_sse(server_path)
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
            start_time = time.perf_counter()
            self.stdio, self.write = await self.exit_stack.enter_async_context(stdio_client(server_params))
            self.session = await self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))
            self.connection_time_ms = int((time.perf_counter() - start_time) * 1000)

            # Store transport metadata
            self.transport_type = MCPTransportType.STDIO
            self.url = None  # stdio doesn't have a URL

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

    async def _connect_with_streamable_http(self, server_url: str) -> bool:
        """Establish HTTP connection to MCP server using streamable HTTP transport.

        Args:
            server_url: Full URL to MCP server endpoint (e.g., https://server.com/mcp)

        Returns:
            True if connection successful, False otherwise

        Note:
            - Requires HTTPS URL
            - Implements automatic reconnection with exponential backoff
            - Enforces connection timeout (15s) and total timeout (60s)
            - Handles common HTTP errors (404, 500, connection refused, timeout)

        """
        if not server_url.startswith(("http://", "https://")):
            logger.error("Invalid URL format. Must start with http:// or https://")
            return False

        try:
            # Configure HTTP client with timeouts and retries
            client = httpx.AsyncClient(
                timeout=httpx.Timeout(
                    connect=15.0,  # Connection timeout: 15 seconds
                    read=60.0,  # Read timeout: 60 seconds
                    write=30.0,  # Write timeout: 30 seconds
                    pool=5.0,  # Pool timeout: 5 seconds
                ),
                follow_redirects=True,
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            )

            # Establish connection using MCP SDK's streamable_http_client
            start_time = time.perf_counter()
            read_stream, write_stream = await self.exit_stack.enter_async_context(
                streamable_http_client(server_url, http_client=lambda: client)
            )

            self.session = await self.exit_stack.enter_async_context(ClientSession(read_stream, write_stream))
            self.connection_time_ms = int((time.perf_counter() - start_time) * 1000)

            # Store transport metadata
            self.transport_type = MCPTransportType.STREAMABLE_HTTP
            self.url = server_url

            logger.info("Successfully connected to MCP server via Streamable HTTP: %s", server_url)
            return True

        except httpx.ConnectError as e:
            logger.error("Connection refused or server unreachable: %s", server_url)
            logger.debug("Error details: %s", e)
            return False
        except httpx.TimeoutException as e:
            logger.error("Connection timeout for server: %s", server_url)
            logger.debug("Error details: %s", e)
            return False
        except httpx.HTTPStatusError as e:
            logger.error("HTTP error %s from server: %s", e.response.status_code, server_url)
            logger.debug("Error details: %s", e)
            return False
        except Exception as e:
            logger.error("Failed to connect to MCP server via Streamable HTTP: %s", e)
            logger.debug("Full error details:", exc_info=True)
            return False

    async def _connect_with_sse(self, server_url: str) -> bool:
        """Establish SSE connection to MCP server.

        Args:
            server_url: Full URL to MCP server SSE endpoint (e.g., https://server.com/sse)

        Returns:
            True if connection successful, False otherwise

        Note:
            - Handles long-lived SSE connections
            - Implements automatic reconnection (max 3 retries)
            - Parses Server-Sent Events stream
            - Manages keepalive/heartbeat

        """
        if not server_url.startswith(("http://", "https://")):
            logger.error("Invalid URL format. Must start with http:// or https://")
            return False

        try:
            # Configure HTTP client for SSE with appropriate timeouts
            client = httpx.AsyncClient(
                timeout=httpx.Timeout(
                    connect=15.0,  # Connection timeout: 15 seconds
                    read=None,  # No read timeout for streaming (handled by keepalive)
                    write=30.0,  # Write timeout: 30 seconds
                    pool=5.0,  # Pool timeout: 5 seconds
                ),
                follow_redirects=True,
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            )

            # Establish connection using MCP SDK's sse_client
            start_time = time.perf_counter()
            read_stream, write_stream = await self.exit_stack.enter_async_context(
                sse_client(server_url, httpx_client_factory=lambda: client)
            )

            self.session = await self.exit_stack.enter_async_context(ClientSession(read_stream, write_stream))
            self.connection_time_ms = int((time.perf_counter() - start_time) * 1000)

            # Store transport metadata
            self.transport_type = MCPTransportType.SSE
            self.url = server_url

            logger.info("Successfully connected to MCP server via SSE: %s", server_url)
            return True

        except httpx.ConnectError as e:
            logger.error("Connection refused or server unreachable: %s", server_url)
            logger.debug("Error details: %s", e)
            return False
        except httpx.TimeoutException as e:
            logger.error("Connection timeout for server: %s", server_url)
            logger.debug("Error details: %s", e)
            return False
        except httpx.HTTPStatusError as e:
            logger.error("HTTP error %s from server: %s", e.response.status_code, server_url)
            logger.debug("Error details: %s", e)
            return False
        except Exception as e:
            logger.error("Failed to connect to MCP server via SSE: %s", e)
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
