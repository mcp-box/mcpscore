import asyncio
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
import logging
import shlex
import sys
import time
from typing import TYPE_CHECKING, Any
from uuid import uuid4

import httpx2
from mcp import (
    ClientSession,
    InitializeResult,
    ListPromptsResult,
    ListResourcesResult,
    ListToolsResult,
    StdioServerParameters,
)
from mcp.client.sse import sse_client
from mcp.client.stdio import get_default_environment, stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from mcp_types import (
    REQUEST_TIMEOUT,
    ListResourceTemplatesResult,
    PaginatedRequestParams,
    Prompt,
    Resource,
    ResourceTemplate,
    Tool,
)

from .enums import ConnectionErrorReason, MCPTransportType
from .probes import ERROR_INVALID_PARAMS, INVALID_CURSOR_PREFIX, ProbeOutcome, ProbeResult

if TYPE_CHECKING:
    from contextlib import AbstractAsyncContextManager

logger = logging.getLogger(__name__)

ERROR_NO_ACTIVE_SESSION = "No active session, connect to the MCP server first!"


@dataclass(frozen=True)
class StdioCommand:
    """A local MCP server launched as an arbitrary stdio command.

    Generalizes the ``.py``/``.js`` file targets to any language: a compiled
    Go binary, ``java -jar server.jar``, ``dotnet run --project …``, and so
    on. The command is executed directly (no shell), so arguments need no
    quoting and behave identically across platforms.

    Attributes:
        command: The executable to launch (resolved on PATH or a file path).
        args: Arguments passed to the executable, in order.
        env: Extra environment variables for the server process, merged over
            the SDK's minimal default environment. None inherits the default.
            Excluded from the repr — env values are secrets by assumption and
            must never surface in logs or tracebacks.

    """

    command: str
    args: tuple[str, ...] = ()
    env: Mapping[str, str] | None = field(default=None, hash=False, repr=False)

    @property
    def display(self) -> str:
        """Return the human-readable command line (for logs and the report)."""
        return shlex.join([self.command, *self.args])


HANDSHAKE_TIMEOUT_S = 30
"""Default timeout for the MCP initialize handshake performed during connect."""

REQUEST_TIMEOUT_S = 60.0
"""Deadline for every in-session request (catalog listings and re-initialize).

Passed to ``ClientSession(read_timeout_seconds=...)``, whose SDK default is
``None`` — without it a server that accepts a connection and then never answers
``tools/list`` stalls an audit forever. ``MAX_LISTING_PAGES`` bounds how many
pages can succeed; it bounds no time at all, and stdio and SSE have no
transport-level read timeout to fall back on.

Sized to match the HTTP transport's 60s read timeout, so the session deadline
does not fire before the transport's own on HTTP servers."""

LISTING_TIMEOUT_S = 180.0
"""Total budget for one paginated listing, across all of its pages.

Per-request deadlines alone still permit ``MAX_LISTING_PAGES`` times the request
deadline — a server that answers every page one second before the timeout would
hold an audit for hours. A partial listing is already a first-class outcome
(``incomplete_listings``), so exhausting this budget degrades rather than
fails."""

MAX_LISTING_PAGES = 100
"""Safety bound for a single paginated MCP listing."""

INVALID_CURSOR_PROBE_TIMEOUT_S = 10.0
"""Deadline for one in-session invalid-cursor observation."""


_REASON_MESSAGES: dict[ConnectionErrorReason, str] = {
    ConnectionErrorReason.INVALID_URL: "Invalid server URL or path.",
    ConnectionErrorReason.UNREACHABLE: "Could not reach the server (connection refused, DNS failure, or host down).",
    ConnectionErrorReason.TIMEOUT: "The server did not respond in time.",
    # Auth-gated servers are auditable: no session opens, but the caller runs a
    # partial audit of the observable surface (auth posture, TLS, transport).
    # These messages state the observation only — the actionable hint belongs to
    # the caller, which knows whether it can carry credentials at all (the CLI
    # suggests --token; the web service cannot).
    ConnectionErrorReason.UNAUTHORIZED: "The MCP server requires authentication (HTTP 401).",
    ConnectionErrorReason.FORBIDDEN: "The MCP server refused access (HTTP 403).",
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
        if isinstance(current, httpx2.HTTPStatusError):
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

    def __init__(self, timeout: int | None = None, headers: dict[str, str] | None = None) -> None:
        """Initialize a new MCP client instance.

        Args:
            timeout: Deadline in seconds for the MCP ``initialize`` handshake
                during connect (None uses ``HANDSHAKE_TIMEOUT_S``). It does not
                govern in-session requests, which are bounded by
                ``REQUEST_TIMEOUT_S`` and ``LISTING_TIMEOUT_S``.
            headers: Extra HTTP headers sent on every request to an HTTP(S)
                server, e.g. ``{"Authorization": "Bearer …"}`` to audit an
                auth-gated server. Ignored for stdio transports. Values are
                sensitive and are never logged or included in the report.

        Sets up the client with an empty session and async exit stack for resource management.

        """
        super().__init__()
        self.session: ClientSession | None = None
        self.exit_stack: AsyncExitStack = AsyncExitStack()
        self.timeout: int | None = timeout
        self.headers: dict[str, str] | None = headers or None
        self._init_result: InitializeResult | None = None
        self.incomplete_listings: set[str] = set()

        # Transport metadata (populated after connection)
        self.transport_type: MCPTransportType | None = None
        self.url: str | None = None
        self.connection_time_ms: int | None = None

        # Fully-resolved launch parameters of a stdio server, kept so the
        # sessionless probes can start their own short-lived processes. The
        # audit's own process has already completed a legacy handshake, and a
        # probe must observe the server, not this connection's history.
        self.stdio_params: StdioServerParameters | None = None

        # Why the most recent failed connect attempt failed (None while
        # connected or before any attempt). Lets callers report an actionable
        # reason instead of a generic "could not connect".
        self.last_connection_error: ConnectionFailure | None = None
        # HTTP status recovered from a single attempt's buffered teardown error.
        self._pending_http_status: int | None = None

    async def detect_and_connect(self, server_path_or_url: str | StdioCommand) -> tuple[bool, MCPTransportType | None]:
        """Automatically detect transport type and connect to MCP server.

        Attempts to connect using Streamable HTTP first, then falls back to SSE.
        For local files (.py, .js), uses stdio transport. A ``StdioCommand``
        launches an arbitrary local server command over stdio (any language).

        Args:
            server_path_or_url: Path to server script, URL, or a StdioCommand

        Returns:
            Tuple of (success: bool, transport: MCPTransportType | None)

        """
        if isinstance(server_path_or_url, StdioCommand):
            success = await self._connect_with_stdio_command(server_path_or_url)
            return (success, MCPTransportType.STDIO if success else None)

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

            # An auth challenge proves an HTTP server answers this endpoint —
            # the legacy SSE fallback would face the same gate (or a 405) and
            # only add misleading diagnostics. Skip it; the caller runs the
            # credential-free partial audit instead.
            if http_failure is not None and http_failure.reason in (
                ConnectionErrorReason.UNAUTHORIZED,
                ConnectionErrorReason.FORBIDDEN,
            ):
                logger.info(
                    "Endpoint requires authentication (HTTP %s) — skipping the legacy SSE fallback",
                    http_failure.status_code or "401/403",
                )
                return (False, None)

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
            session: ClientSession = await stack.enter_async_context(
                ClientSession(read_stream, write_stream, read_timeout_seconds=REQUEST_TIMEOUT_S)
            )
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
        missing_hint = (
            "Python interpreter not found. Please ensure Python is installed and on PATH."
            if is_python
            else "Node.js not found. Please ensure Node.js is installed and on PATH."
        )
        server_params = StdioServerParameters(command=command, args=[server_script_path], env=None)
        return await self._launch_stdio(server_params, display=server_script_path, missing_hint=missing_hint)

    async def _connect_with_stdio_command(self, command: StdioCommand) -> bool:
        """Launch an arbitrary local server command and connect over stdio.

        Args:
            command: The executable, its arguments, and optional extra
                environment variables (merged over the SDK's default env).

        Returns:
            True if a connection was successful, False otherwise

        """
        env = {**get_default_environment(), **command.env} if command.env else None
        server_params = StdioServerParameters(command=command.command, args=list(command.args), env=env)
        missing_hint = f"Command not found: '{command.command}'. Please ensure it is installed and on PATH."
        return await self._launch_stdio(server_params, display=command.display, missing_hint=missing_hint)

    async def _launch_stdio(self, server_params: StdioServerParameters, display: str, missing_hint: str) -> bool:
        """Start a stdio server process and perform the MCP handshake.

        Args:
            server_params: Fully-resolved command, arguments and environment.
            display: Human-readable target for log messages (script path or
                joined command line).
            missing_hint: Message logged when the launcher executable is not
                found on PATH.

        Returns:
            True if a connection was successful, False otherwise

        """
        try:
            await self._establish_session(stdio_client(server_params), MCPTransportType.STDIO, url=None)
            self.stdio_params = server_params
            return True
        except FileNotFoundError as e:
            logger.exception(missing_hint)
            logger.debug("Error details: %s", e)
            self._record_failure(ConnectionErrorReason.UNREACHABLE)
            return False
        except PermissionError as e:
            logger.exception("Permission denied launching server: %s", display)
            logger.debug("Error details: %s", e)
            self._record_failure(ConnectionErrorReason.UNREACHABLE)
            return False
        except TimeoutError:
            logger.error("MCP initialize handshake timed out for server: %s", display)  # noqa: TRY400
            self._record_failure(ConnectionErrorReason.TIMEOUT)
            return False
        except asyncio.CancelledError:
            self._reraise_if_cancelled()
            logger.error("MCP initialize handshake failed for server: %s", display)  # noqa: TRY400
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
            client = httpx2.AsyncClient(
                timeout=httpx2.Timeout(
                    connect=15.0,  # Connection timeout: 15 seconds
                    read=60.0,  # Read timeout: 60 seconds
                    write=30.0,  # Write timeout: 30 seconds
                    pool=5.0,  # Pool timeout: 5 seconds
                ),
                follow_redirects=True,
                headers=self.headers,
                limits=httpx2.Limits(max_connections=100, max_keepalive_connections=20),
            )

            # Establish connection and verify the MCP handshake
            await self._establish_session(
                streamable_http_client(server_url, http_client=client),
                MCPTransportType.STREAMABLE_HTTP,
                url=server_url,
            )

            logger.info("Successfully connected to MCP server via Streamable HTTP: %s", server_url)
            return True

        except httpx2.ConnectError as e:
            logger.exception("Connection refused or server unreachable: %s", server_url)
            logger.debug("Error details: %s", e)
            self._record_failure(ConnectionErrorReason.UNREACHABLE)
            return False
        except httpx2.TimeoutException as e:
            logger.exception("Connection timeout for server: %s", server_url)
            logger.debug("Error details: %s", e)
            self._record_failure(ConnectionErrorReason.TIMEOUT)
            return False
        except httpx2.HTTPStatusError as e:
            status = e.response.status_code
            if status in (401, 403):
                # An auth challenge is an expected observation, not an error —
                # the partial-audit path handles it. No traceback.
                logger.info("Server requires authentication (HTTP %s): %s", status, server_url)
            else:
                logger.exception("HTTP error %s from server: %s", status, server_url)
                logger.debug("Error details: %s", e)
            self._record_failure(reason_for_status(status), status)
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
            status = self._pending_http_status or extract_http_status(e)
            if status is None:
                # Some SDK failure shapes (e.g. a bare MCPError for a 401
                # whose body parses as an error response) carry no HTTP
                # status anywhere in the exception chain. Recover it with a
                # single anonymous request so an auth gate classifies as
                # UNAUTHORIZED instead of UNKNOWN. Only a recovered 401/403
                # is trusted: the recovery is a *different* request, so any
                # other status (a 200 from an HTTP-fine but MCP-broken
                # endpoint, say) must not relabel the original failure.
                recovered = await self._recover_http_status(server_url)
                if recovered in (401, 403):
                    status = recovered
            if status in (401, 403):
                logger.info("Server requires authentication (HTTP %s): %s", status, server_url)
                self._record_failure(reason_for_status(status), status)
            else:
                logger.exception("Failed to connect to MCP server via Streamable HTTP")
                self._record_unclassified_failure(e)
            return False

    async def _recover_http_status(self, server_url: str) -> int | None:
        """Recover the HTTP status of a failed connect attempt with one POST.

        Used only when a connect attempt failed without an HTTP status
        anywhere in its exception chain. It **mirrors the failed attempt's
        headers**, including any caller-supplied ``Authorization`` — this
        recovers the status *that attempt* would have reported, which is the
        only thing the caller may act on. Stripping the credential would
        answer a different question ("is this endpoint gated?") and make a
        401 from an anonymous request look like the user's own token being
        refused; that gated-endpoint question is already answered separately
        by the probe layer, whose unauthenticated probe runs anonymously by
        design (``observed_auth_status``).

        Invokes no tools and never raises — a network error simply returns
        None and classification falls back to UNKNOWN.
        """
        body = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "mcpscore", "version": "status-recovery"},
            },
        }
        try:
            async with httpx2.AsyncClient(timeout=10.0, headers=self.headers) as client:
                response = await client.post(
                    server_url,
                    json=body,
                    headers={"Accept": "application/json, text/event-stream"},
                )
                return response.status_code
        except Exception:  # noqa: BLE001 — recovery is best-effort
            return None

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
            client = httpx2.AsyncClient(
                timeout=httpx2.Timeout(
                    connect=15.0,  # Connection timeout: 15 seconds
                    read=None,  # No read timeout for streaming (handled by keepalive)
                    write=30.0,  # Write timeout: 30 seconds
                    pool=5.0,  # Pool timeout: 5 seconds
                ),
                follow_redirects=True,
                headers=self.headers,
                limits=httpx2.Limits(max_connections=100, max_keepalive_connections=20),
            )

            # Establish connection using MCP SDK's sse_client
            # Create a factory that ignores extra parameters since we already have a client
            def client_factory(
                headers: dict[str, str] | None = None,
                timeout: httpx2.Timeout | None = None,
                auth: httpx2.Auth | None = None,
            ) -> httpx2.AsyncClient:
                return client

            await self._establish_session(
                sse_client(server_url, httpx_client_factory=client_factory),
                MCPTransportType.SSE,
                url=server_url,
            )

            logger.info("Successfully connected to MCP server via SSE: %s", server_url)
            return True

        except httpx2.ConnectError as e:
            logger.exception("Connection refused or server unreachable: %s", server_url)
            logger.debug("Error details: %s", e)
            self._record_failure(ConnectionErrorReason.UNREACHABLE)
            return False
        except httpx2.TimeoutException as e:
            logger.exception("Connection timeout for server: %s", server_url)
            logger.debug("Error details: %s", e)
            self._record_failure(ConnectionErrorReason.TIMEOUT)
            return False
        except httpx2.HTTPStatusError as e:
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

        return await self._list_all_pages(self.session.list_tools, "tools", "tools")

    async def list_resources(self) -> list[Resource] | None:
        """List and display all available resources from the MCP server.

        Retrieves the server's resources

        Note:
            Must be called after successfully initializing the server session

        """
        if not self.session:
            logger.error(ERROR_NO_ACTIVE_SESSION)
            return None

        return await self._list_all_pages(self.session.list_resources, "resources", "resources")

    async def list_resource_templates(self) -> list[ResourceTemplate] | None:
        """List every available resource template from the MCP server."""
        if not self.session:
            logger.error(ERROR_NO_ACTIVE_SESSION)
            return None

        return await self._list_all_pages(
            self.session.list_resource_templates,
            "resource_templates",
            "resource_templates",
        )

    async def list_prompts(self) -> list[Prompt] | None:
        """List and display all available prompts from the MCP server.

        Retrieves the server's prompts

        Note:
            Must be called after successfully initializing the server session

        """
        if not self.session:
            logger.error(ERROR_NO_ACTIVE_SESSION)
            return None

        return await self._list_all_pages(self.session.list_prompts, "prompts", "prompts")

    async def probe_invalid_cursors(self, probe_ids: Mapping[str, str]) -> dict[str, ProbeResult]:
        """Observe invalid-cursor handling on the established session.

        ``probe_ids`` maps listing names to stable probe IDs. Only listings
        whose capabilities were declared are supplied by the auditor. Each
        request is read-only, bounded, and carries a cursor that this session
        could not have received from the server.
        """
        if not self.session:
            return {
                probe_id: ProbeResult(
                    probe_id,
                    ProbeOutcome.NOT_APPLICABLE,
                    {"reason": "no active session; cursor validation not observable"},
                )
                for probe_id in probe_ids.values()
            }

        fetch_pages: dict[str, Callable[..., Awaitable[Any]]] = {
            "tools": self.session.list_tools,
            "resources": self.session.list_resources,
            "resource_templates": self.session.list_resource_templates,
            "prompts": self.session.list_prompts,
        }

        async def observe(listing_name: str, probe_id: str) -> ProbeResult:
            cursor = f"{INVALID_CURSOR_PREFIX}{uuid4().hex}"
            try:
                await asyncio.wait_for(
                    fetch_pages[listing_name](params=PaginatedRequestParams(cursor=cursor)),
                    timeout=INVALID_CURSOR_PROBE_TIMEOUT_S,
                )
            except MCPError as exc:
                outcome = ProbeOutcome.SUPPORTED if exc.code == ERROR_INVALID_PARAMS else ProbeOutcome.UNSUPPORTED
                return ProbeResult(probe_id, outcome, {"error_code": exc.code})
            except Exception as exc:  # noqa: BLE001 — probes never abort an audit
                return ProbeResult(probe_id, ProbeOutcome.ERROR, {"exception": type(exc).__name__})
            return ProbeResult(probe_id, ProbeOutcome.UNSUPPORTED, {"error_code": None})

        results = await asyncio.gather(*(observe(name, probe_id) for name, probe_id in probe_ids.items()))
        return {result.probe_id: result for result in results}

    async def _list_all_pages(
        self,
        fetch_page: Callable[
            ...,
            Awaitable[ListToolsResult | ListResourcesResult | ListPromptsResult | ListResourceTemplatesResult],
        ],
        item_attribute: str,
        listing_name: str,
    ) -> list[Any] | None:
        """Collect a complete MCP listing while guarding against broken cursors."""
        items: list[Any] = []
        seen_cursors: set[str] = set()
        cursor: str | None = None
        self.incomplete_listings.discard(listing_name)
        deadline = time.monotonic() + LISTING_TIMEOUT_S

        for page_number in range(MAX_LISTING_PAGES):
            # Clamp each page to whatever budget is left; at zero, wait_for
            # raises immediately. One branch therefore covers both "this page
            # stalled" and "the budget is already spent" — an earlier version
            # had a separate pre-check that the clamp made unreachable.
            remaining = max(deadline - time.monotonic(), 0)
            try:
                response = await asyncio.wait_for(
                    fetch_page() if page_number == 0 else fetch_page(params=PaginatedRequestParams(cursor=cursor)),
                    timeout=remaining,
                )
            except Exception as exc:
                # One handler, three diagnoses. Timeouts are a server that
                # stopped answering, not a protocol fault, and must not read as
                # a crash — the SDK's own request timeout arrives as
                # MCPError(-32001) and is the *common* stall, so leaving it in
                # the generic branch made the ordinary case the noisiest line in
                # the log. Everything else keeps the original traceback.
                self.incomplete_listings.add(listing_name)
                if isinstance(exc, TimeoutError):
                    # Our clamp: the server kept answering, but the total budget
                    # for this listing ran out.
                    logger.warning(
                        "Stopped listing %s after %.0fs (%d page(s) collected) — listing budget exhausted",
                        listing_name,
                        LISTING_TIMEOUT_S,
                        page_number,
                    )
                elif isinstance(exc, MCPError) and exc.code == REQUEST_TIMEOUT:
                    # The session deadline: this server went silent on one request.
                    logger.warning(
                        "Stopped listing %s: server did not answer within %.0fs (%d page(s) collected)",
                        listing_name,
                        REQUEST_TIMEOUT_S,
                        page_number,
                    )
                else:
                    logger.exception("Failed to list %s from the MCP server", listing_name)
                # None means the listing yielded nothing at all; once any page
                # succeeded the collected items — even zero of them — are
                # partial evidence and must not degrade to "unavailable".
                return None if page_number == 0 else items

            items.extend(getattr(response, item_attribute))
            next_cursor = response.next_cursor
            if next_cursor is None:
                return items
            if next_cursor in seen_cursors:
                self.incomplete_listings.add(listing_name)
                logger.error("Stopped listing %s after the server repeated cursor %r", listing_name, next_cursor)
                return items
            seen_cursors.add(next_cursor)
            cursor = next_cursor

        self.incomplete_listings.add(listing_name)
        logger.error("Stopped listing %s after %d pages", listing_name, MAX_LISTING_PAGES)
        return items

    async def cleanup(self) -> None:
        """Clean up client resources and close all connections.

        Properly closes the async exit stack, which will:
        - Close the stdio transport
        - Close the client session
        - Clean up any other managed resources

        Should be called when the client is no longer needed to prevent resource leaks.
        """
        await self.exit_stack.aclose()
