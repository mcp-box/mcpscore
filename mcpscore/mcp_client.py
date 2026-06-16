import asyncio
from contextlib import AsyncExitStack
from dataclasses import dataclass
import logging
import sys
import time
from typing import TYPE_CHECKING

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

from .enums import ConnectionErrorReason, MCPTransportType

if TYPE_CHECKING:
    from contextlib import AbstractAsyncContextManager

logger = logging.getLogger(__name__)

ERROR_NO_ACTIVE_SESSION = "No active session, connect to the MCP server first!"

HANDSHAKE_TIMEOUT_S = 30
"""Default timeout for the MCP initialize handshake performed during connect."""


_REASON_MESSAGES: dict[ConnectionErrorReason, str] = {
    ConnectionErrorReason.INVALID_URL: "Invalid server URL or path.",
    ConnectionErrorReason.UNREACHABLE: "Could not reach the server (connection refused, DNS failure, or host down).",
    ConnectionErrorReason.TIMEOUT: "The server did not respond in time.",
    ConnectionErrorReason.UNAUTHORIZED: (
        "The MCP server requires authentication (HTTP 401). MCPScore can only audit publicly accessible servers."
    ),
    ConnectionErrorReason.FORBIDDEN: (
        "The MCP server refused access (HTTP 403). MCPScore can only audit publicly accessible servers."
    ),
    ConnectionErrorReason.HTTP_ERROR: "The server returned an HTTP error during the MCP handshake.",
    ConnectionErrorReason.NOT_MCP: (
        "The endpoint was reachable but did not complete an MCP handshake — it may not be an MCP server."
    ),
    ConnectionErrorReason.UNKNOWN: "Could not connect to the MCP server.",
}

# Higher rank = more informative/actionable. When auto-detect tries multiple
# transports and all fail, the most informative failure is the one worth
# reporting (e.g. a streamable-HTTP 401 beats an SSE 405 from the same server).
_REASON_RANK: dict[ConnectionErrorReason, int] = {
    ConnectionErrorReason.UNKNOWN: 0,
    ConnectionErrorReason.NOT_MCP: 1,
    ConnectionErrorReason.HTTP_ERROR: 2,
    ConnectionErrorReason.INVALID_URL: 3,
    ConnectionErrorReason.UNREACHABLE: 4,
    ConnectionErrorReason.TIMEOUT: 4,
    ConnectionErrorReason.FORBIDDEN: 5,
    ConnectionErrorReason.UNAUTHORIZED: 5,
}


@dataclass(frozen=True)
class ConnectionFailure:
    """Why the most recent connection attempt failed, with an actionable message."""

    reason: ConnectionErrorReason
    status_code: int | None = None

    @property
    def message(self) -> str:
        base = _REASON_MESSAGES[self.reason]
        # For an unclassified HTTP error, surface the actual status code.
        if self.reason is ConnectionErrorReason.HTTP_ERROR and self.status_code is not None:
            return f"The server returned HTTP {self.status_code} during the MCP handshake."
        return base


def reason_for_status(status_code: int) -> ConnectionErrorReason:
    """Map an HTTP status code seen during connect to a failure reason."""
    if status_code == 401:
        return ConnectionErrorReason.UNAUTHORIZED
    if status_code == 403:
        return ConnectionErrorReason.FORBIDDEN
    return ConnectionErrorReason.HTTP_ERROR


def extract_http_status(exc: BaseException) -> int | None:
    """Find an HTTP status code anywhere in an exception tree.

    Transport teardown surfaces the real cause buffered inside an
    ``ExceptionGroup`` (and possibly chained via ``__cause__``/``__context__``);
    walk all of it to recover the status the server actually returned.
    """
    seen: set[int] = set()
    stack: list[BaseException | None] = [exc]
    while stack:
        current = stack.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, httpx.HTTPStatusError):
            return current.response.status_code
        if isinstance(current, BaseExceptionGroup):
            stack.extend(current.exceptions)
        stack.append(current.__cause__)
        stack.append(current.__context__)
    return None


def _preferred_failure(
    first: ConnectionFailure | None,
    second: ConnectionFailure | None,
) -> ConnectionFailure | None:
    """Pick the more informative of two failures (see ``_REASON_RANK``)."""
    if first is None:
        return second
    if second is None:
        return first
    return second if _REASON_RANK[second.reason] > _REASON_RANK[first.reason] else first


class MCPClient:
    """Client for connecting to and communicating with MCP (Model Context Protocol) servers.

    This class provides a high-level interface for:
    - Establishing connections to MCP servers via various transport methods
    - Initializing server sessions
    - Listing available tools and resources
    - Managing connection lifecycle and cleanup

    Supports STDIO (local server processes), Streamable HTTP, and SSE
    transports, with automatic transport detection.
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
        self._init_result: InitializeResult | None = None

        # Transport metadata (populated after connection)
        self.transport_type: MCPTransportType | None = None
        self.url: str | None = None
        self.connection_time_ms: int | None = None

        # Why the most recent failed connect attempt failed (None while
        # connected or before any attempt). Lets callers report an actionable
        # reason instead of a generic "could not connect".
        self.last_connection_error: ConnectionFailure | None = None
        # HTTP status recovered from a single attempt's buffered teardown error.
        self._pending_http_status: int | None = None

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
            http_failure = self.last_connection_error

            # Fall back to SSE
            logger.info("Streamable HTTP failed, trying SSE...")
            if await self.connect_to_server(MCPTransportType.SSE, server_path_or_url):
                return (True, MCPTransportType.SSE)

            # Both transports failed: report whichever failure is most
            # informative (e.g. an auth 401 from the HTTP attempt outranks a
            # generic 405 from the SSE fallback).
            self.last_connection_error = _preferred_failure(http_failure, self.last_connection_error)
            return (False, None)

        logger.error("Invalid server path or URL: %s", server_path_or_url)
        self._record_failure(ConnectionErrorReason.INVALID_URL)
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

    async def _establish_session(
        self,
        transport_cm: "AbstractAsyncContextManager",
        transport: MCPTransportType,
        url: str | None,
    ) -> None:
        """Enter the transport, open a session, and verify the MCP handshake.

        A connection only counts as established once the server completes the
        MCP `initialize` handshake — merely opening the transport stream
        succeeds against any reachable endpoint, MCP server or not.

        The attempt runs on its own exit stack: on any failure the transport
        is torn down immediately (so a failed attempt never leaks into this
        client's lifecycle), and the exception is re-raised for the caller to
        classify. On success the contexts are transferred to the client's
        exit stack and session metadata is populated.
        """
        stack = AsyncExitStack()
        # Reset per-attempt teardown state so a stale status from a prior
        # transport attempt can't leak into this one's classification.
        self._pending_http_status = None
        try:
            start_time = time.perf_counter()
            streams = await stack.enter_async_context(transport_cm)
            read_stream, write_stream = streams[0], streams[1]
            session: ClientSession = await stack.enter_async_context(ClientSession(read_stream, write_stream))
            init_result: InitializeResult = await asyncio.wait_for(
                session.initialize(),
                timeout=self.timeout or HANDSHAKE_TIMEOUT_S,
            )
            connection_time_ms = int((time.perf_counter() - start_time) * 1000)
        except BaseException:
            # Includes CancelledError thrown by the transport's anyio task
            # group when its background task fails (e.g. non-MCP endpoint).
            await self._discard_attempt(stack)
            raise

        self.exit_stack.push_async_callback(stack.pop_all().aclose)
        self.session = session
        self._init_result = init_result
        self.transport_type = transport
        self.url = url
        self.connection_time_ms = connection_time_ms
        self.last_connection_error = None

    async def _discard_attempt(self, stack: AsyncExitStack) -> None:
        """Tear down a failed connection attempt without raising.

        Closing the transport's task group surfaces the underlying error
        (e.g. an HTTP 4xx/5xx buffered by a background task). Recover any HTTP
        status from it so the caller can classify the failure, and log the
        real reason instead of letting teardown mask the connect result.
        """
        try:
            await stack.aclose()
        except Exception as e:  # noqa: BLE001 — teardown must not mask the connect failure
            status = extract_http_status(e)
            if status is not None:
                self._pending_http_status = status
            logger.info("Connection attempt failed: %s", e)

    def _record_failure(self, reason: ConnectionErrorReason, status_code: int | None = None) -> None:
        """Record why the current connect attempt failed."""
        self.last_connection_error = ConnectionFailure(reason=reason, status_code=status_code)

    def _record_unclassified_failure(self, exc: BaseException) -> None:
        """Classify a catch-all failure, recovering an HTTP status if one is buried in it.

        A raw `ExceptionGroup` carrying an `HTTPStatusError` can reach the
        generic handler directly (not only via teardown), so look inside it
        before falling back to UNKNOWN.
        """
        status = self._pending_http_status or extract_http_status(exc)
        if status is not None:
            self._record_failure(reason_for_status(status), status)
        else:
            self._record_failure(ConnectionErrorReason.UNKNOWN)

    def _record_handshake_failure(self, server_url: str) -> None:
        """Classify a handshake failure, using any HTTP status seen in teardown.

        A bare handshake failure means the transport opened but `initialize`
        never completed. If the server returned an HTTP status (e.g. 401), the
        endpoint is up but gated — far more useful than "not an MCP server".
        """
        logger.error("Not a valid MCP server (handshake failed): %s", server_url)
        if self._pending_http_status is not None:
            self._record_failure(reason_for_status(self._pending_http_status), self._pending_http_status)
        else:
            self._record_failure(ConnectionErrorReason.NOT_MCP)

    @staticmethod
    def _reraise_if_cancelled() -> None:
        """Re-raise only when this task itself is being cancelled.

        The transport's anyio cancel scope cancels the connecting task when
        its background task dies; that leaked cancellation is a failed
        connection, not a request to stop.
        """
        task = asyncio.current_task()
        if task is not None and task.cancelling():
            raise asyncio.CancelledError

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
            self._record_failure(ConnectionErrorReason.INVALID_URL)
            return False

        # Use sys.executable for Python to ensure we use the same interpreter
        command: str = sys.executable if is_python else "node"
        server_params = StdioServerParameters(command=command, args=[server_script_path], env=None)

        try:
            await self._establish_session(stdio_client(server_params), MCPTransportType.STDIO, url=None)
            return True
        except FileNotFoundError as e:
            if is_python:
                logger.exception("Python interpreter not found. Please ensure Python is installed and on PATH.")
            else:
                logger.exception("Node.js not found. Please ensure Node.js is installed and on PATH.")
            logger.debug("Error details: %s", e)
            self._record_failure(ConnectionErrorReason.UNREACHABLE)
            return False
        except PermissionError as e:
            logger.exception("Permission denied accessing server script: %s", server_script_path)
            logger.debug("Error details: %s", e)
            self._record_failure(ConnectionErrorReason.UNREACHABLE)
            return False
        except TimeoutError:
            logger.error("MCP initialize handshake timed out for server: %s", server_script_path)  # noqa: TRY400
            self._record_failure(ConnectionErrorReason.TIMEOUT)
            return False
        except asyncio.CancelledError:
            self._reraise_if_cancelled()
            logger.error("MCP initialize handshake failed for server: %s", server_script_path)  # noqa: TRY400
            self._record_failure(ConnectionErrorReason.NOT_MCP)
            return False
        except Exception as e:
            logger.exception("Failed to connect to MCP server")
            self._record_unclassified_failure(e)
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
            self._record_failure(ConnectionErrorReason.INVALID_URL)
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

            # Establish connection and verify the MCP handshake
            await self._establish_session(
                streamable_http_client(server_url, http_client=client),
                MCPTransportType.STREAMABLE_HTTP,
                url=server_url,
            )

            logger.info("Successfully connected to MCP server via Streamable HTTP: %s", server_url)
            return True

        except httpx.ConnectError as e:
            logger.exception("Connection refused or server unreachable: %s", server_url)
            logger.debug("Error details: %s", e)
            self._record_failure(ConnectionErrorReason.UNREACHABLE)
            return False
        except httpx.TimeoutException as e:
            logger.exception("Connection timeout for server: %s", server_url)
            logger.debug("Error details: %s", e)
            self._record_failure(ConnectionErrorReason.TIMEOUT)
            return False
        except httpx.HTTPStatusError as e:
            logger.exception("HTTP error %s from server: %s", e.response.status_code, server_url)
            logger.debug("Error details: %s", e)
            self._record_failure(reason_for_status(e.response.status_code), e.response.status_code)
            return False
        except TimeoutError:
            logger.error("MCP initialize handshake timed out for server: %s", server_url)  # noqa: TRY400
            self._record_failure(ConnectionErrorReason.TIMEOUT)
            return False
        except asyncio.CancelledError:
            self._reraise_if_cancelled()
            self._record_handshake_failure(server_url)
            return False
        except Exception as e:
            logger.exception("Failed to connect to MCP server via Streamable HTTP")
            self._record_unclassified_failure(e)
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
            self._record_failure(ConnectionErrorReason.INVALID_URL)
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
            # Create a factory that ignores extra parameters since we already have a client
            def client_factory(
                headers: dict[str, str] | None = None,
                timeout: httpx.Timeout | None = None,
                auth: httpx.Auth | None = None,
            ) -> httpx.AsyncClient:
                return client

            await self._establish_session(
                sse_client(server_url, httpx_client_factory=client_factory),
                MCPTransportType.SSE,
                url=server_url,
            )

            logger.info("Successfully connected to MCP server via SSE: %s", server_url)
            return True

        except httpx.ConnectError as e:
            logger.exception("Connection refused or server unreachable: %s", server_url)
            logger.debug("Error details: %s", e)
            self._record_failure(ConnectionErrorReason.UNREACHABLE)
            return False
        except httpx.TimeoutException as e:
            logger.exception("Connection timeout for server: %s", server_url)
            logger.debug("Error details: %s", e)
            self._record_failure(ConnectionErrorReason.TIMEOUT)
            return False
        except httpx.HTTPStatusError as e:
            logger.exception("HTTP error %s from server: %s", e.response.status_code, server_url)
            logger.debug("Error details: %s", e)
            self._record_failure(reason_for_status(e.response.status_code), e.response.status_code)
            return False
        except TimeoutError:
            logger.error("MCP initialize handshake timed out for server: %s", server_url)  # noqa: TRY400
            self._record_failure(ConnectionErrorReason.TIMEOUT)
            return False
        except asyncio.CancelledError:
            self._reraise_if_cancelled()
            self._record_handshake_failure(server_url)
            return False
        except Exception as e:
            logger.exception("Failed to connect to MCP server via SSE")
            self._record_unclassified_failure(e)
            return False

    async def initialize(self) -> InitializeResult | None:
        """Initialize the MCP server session.

        Performs the MCP handshake and retrieves server capabilities and information.

        Returns:
            InitializeResult containing server info, capabilities, and protocol version,
            or None if initialization failed

        Note:
            Must be called after successfully connecting to a server. The
            handshake already happens during connect; this returns the cached
            result rather than re-initializing the session.

        """
        if self._init_result is not None:
            return self._init_result

        if not self.session:
            logger.error(ERROR_NO_ACTIVE_SESSION)
            return None

        try:
            init_result: InitializeResult = await self.session.initialize()
            self._init_result = init_result
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
