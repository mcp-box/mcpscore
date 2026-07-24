"""Interactive browser OAuth flow for auditing OAuth-protected servers.

Implements the CLI's ``--oauth`` mode: discover the server's authorization
server (RFC 9728 → RFC 8414), register a client dynamically (RFC 7591) or
use a pre-registered ``--client-id`` where the authorization server offers
no dynamic registration, open the user's browser for the authorization-code
+ PKCE grant, catch the redirect on a loopback listener, and exchange the
code for a token.

The obtained access token is held **in memory only** — nothing is written
to disk, and the token value is never logged. After the flow completes, the
token feeds the same ``Authorization`` header plumbing as ``--token``, so
the audit pipeline (client, probes, anonymous-probe isolation) is identical
in both modes.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit
import webbrowser

import httpx2
from mcp.client.auth import OAuthClientProvider, OAuthRegistrationError, OAuthTokenError
from mcp.shared.auth import AuthorizationCodeResult, OAuthClientInformationFull, OAuthClientMetadata, OAuthToken
from pydantic import AnyUrl

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

CALLBACK_PATH = "/callback"
"""Path the loopback listener serves; part of the registered redirect URI."""

FLOW_TIMEOUT_S = 300.0
"""How long to wait for the user to complete the browser flow."""


def _http_response(status_line: str, body: str) -> bytes:
    return (
        f"HTTP/1.1 {status_line}\r\ncontent-type: text/html; charset=utf-8\r\nconnection: close\r\n\r\n"
        f"<html><body><p>{body}</p></body></html>"
    ).encode()


_SUCCESS_RESPONSE = _http_response("200 OK", "mcpscore received the authorization response. You can close this tab.")
_WAITING_RESPONSE = _http_response("200 OK", "mcpscore is waiting for the authorization response…")
_NOT_FOUND_RESPONSE = _http_response("404 Not Found", "Not found.")


class OAuthFlowError(RuntimeError):
    """The interactive OAuth flow could not produce a token.

    The message is user-facing and never contains token material.
    """


class _MemoryTokenStorage:
    """In-memory TokenStorage: tokens and client info live and die with the process."""

    def __init__(self) -> None:
        super().__init__()
        self._tokens: OAuthToken | None = None
        self._client_info: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self._tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self._client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._client_info = client_info


class _LoopbackCallbackServer:
    """Minimal one-shot HTTP listener for the authorization redirect.

    Binds an ephemeral port on 127.0.0.1 and resolves a future with the
    query parameters of the first request to the callback path.
    """

    def __init__(self, port: int | None = None) -> None:
        super().__init__()
        self._requested_port = port or 0
        self._server: asyncio.Server | None = None
        self._result: asyncio.Future[dict[str, str]] = asyncio.get_running_loop().create_future()
        self.port: int = 0

    @property
    def redirect_uri(self) -> str:
        return f"http://127.0.0.1:{self.port}{CALLBACK_PATH}"

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, host="127.0.0.1", port=self._requested_port)
        self.port = self._server.sockets[0].getsockname()[1]

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = await reader.readline()
            parts = request_line.decode("latin-1").split(" ")
            target = parts[1] if len(parts) >= 2 else "/"
            split = urlsplit(target)
            params = {key: values[0] for key, values in parse_qs(split.query).items()}
            is_callback = split.path == CALLBACK_PATH
            # Only an actual authorization response counts — a stray visit to
            # bare /callback (scanner, prefetch) must not consume the one-shot
            # future, and only a real response earns the success page.
            is_auth_response = is_callback and ("code" in params or "error" in params)
            if is_auth_response:
                writer.write(_SUCCESS_RESPONSE)
            elif is_callback:
                writer.write(_WAITING_RESPONSE)
            else:
                writer.write(_NOT_FOUND_RESPONSE)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
        if is_auth_response and not self._result.done():
            self._result.set_result(params)

    async def wait_for_callback(self, timeout_s: float) -> dict[str, str]:
        return await asyncio.wait_for(self._result, timeout=timeout_s)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


async def obtain_token_interactively(
    server_url: str,
    *,
    client_id: str | None = None,
    callback_port: int | None = None,
    flow_timeout_s: float = FLOW_TIMEOUT_S,
    open_browser: Callable[[str], object] = webbrowser.open,
    transport: httpx2.AsyncBaseTransport | None = None,
) -> str:
    """Run the browser OAuth flow against a server and return the access token.

    Args:
        server_url: The MCP endpoint URL the audit will target.
        client_id: Pre-registered OAuth client ID for authorization servers
            without dynamic client registration (e.g. GitHub's). When set,
            registration is skipped and this ID is used with the PKCE flow.
        callback_port: Fixed loopback port for the redirect URI. RFC 8252
            requires authorization servers to accept any port on loopback
            redirects, but some (non-compliant) ones demand the exact
            pre-registered URI — pin the port you registered here. Default:
            an ephemeral port.
        flow_timeout_s: Seconds to wait for the user to finish in the browser.
        open_browser: Injection point for tests; production uses the default
            browser.
        transport: Test-only httpx transport injection; None uses the network.

    Returns:
        The access token string (held in memory by the caller; never logged).

    Raises:
        OAuthFlowError: On any failure — discovery, registration, user
            timeout, or token exchange. The message says which step failed
            and, for registration failures, suggests ``--client-id``.

    """
    callback = _LoopbackCallbackServer(port=callback_port)
    try:
        await callback.start()
    except OSError as exc:
        raise OAuthFlowError(f"cannot bind a loopback port for the OAuth callback: {exc}") from exc
    try:
        storage = _MemoryTokenStorage()
        if client_id is not None:
            # Pre-seeding client info makes the SDK skip dynamic registration —
            # the escape hatch for authorization servers without RFC 7591.
            await storage.set_client_info(
                OAuthClientInformationFull(
                    client_id=client_id,
                    redirect_uris=[AnyUrl(callback.redirect_uri)],
                    token_endpoint_auth_method="none",  # noqa: S106 — public-client method name, not a secret
                )
            )

        async def redirect_handler(authorization_url: str) -> None:
            logger.info("Opening your browser to authorize (if nothing opens, visit the URL below):")
            logger.info("%s", authorization_url)
            open_browser(authorization_url)

        async def callback_handler() -> AuthorizationCodeResult:
            try:
                params = await callback.wait_for_callback(flow_timeout_s)
            except TimeoutError as exc:
                raise OAuthFlowError(
                    f"timed out after {flow_timeout_s:.0f}s waiting for the browser authorization"
                ) from exc
            if "error" in params:
                description = params.get("error_description", "")
                raise OAuthFlowError(f"authorization was refused: {params['error']} {description}".strip())
            # The listener only resolves with code or error, so code is present here.
            return AuthorizationCodeResult(code=params["code"], state=params.get("state"), iss=params.get("iss"))

        provider = OAuthClientProvider(
            server_url=server_url,
            client_metadata=OAuthClientMetadata(
                client_name="mcpscore",
                redirect_uris=[AnyUrl(callback.redirect_uri)],
                token_endpoint_auth_method="none",  # noqa: S106 — public-client method name, not a secret
            ),
            storage=storage,
            redirect_handler=redirect_handler,
            callback_handler=callback_handler,
            timeout=flow_timeout_s,
        )

        # One authenticated request drives the whole flow: the 401 triggers
        # discovery → (registration) → browser grant → token exchange, and the
        # provider retries the request with the token.
        try:
            async with httpx2.AsyncClient(
                auth=provider, follow_redirects=True, timeout=30.0, transport=transport
            ) as client:
                # A well-formed JSON-RPC request: servers that validate the
                # body before their auth middleware still answer 401 with the
                # WWW-Authenticate challenge discovery needs (an empty {} can
                # draw a 400 with no challenge from such servers).
                await client.post(
                    server_url,
                    json={"jsonrpc": "2.0", "id": 0, "method": "ping"},
                    headers={"Accept": "application/json, text/event-stream"},
                )
        except OAuthFlowError:
            raise
        except Exception as exc:
            # The retried request can fail after the grant and token exchange
            # already succeeded (network blip, server hiccup) — the flow's
            # purpose is the token, so salvage it before declaring failure.
            salvaged = await storage.get_tokens()
            if salvaged is not None and salvaged.access_token:
                logger.info("OAuth flow completed (the follow-up request failed, but the token was obtained).")
                return salvaged.access_token
            hint = ""
            if client_id is None and isinstance(exc, OAuthRegistrationError):
                hint = " (the authorization server may not support dynamic client registration — try --client-id)"
            # This message is logged. Known SDK OAuth errors carry summary-style
            # text that never includes token material; any other exception may
            # echo response bodies, so only its type is included (module
            # contract: errors never contain token material).
            detail = str(exc) if isinstance(exc, (OAuthRegistrationError, OAuthTokenError)) else type(exc).__name__
            raise OAuthFlowError(f"OAuth flow failed: {detail}{hint}") from exc

        tokens = await storage.get_tokens()
        if tokens is None or not tokens.access_token:
            # No hint here: this path has non-registration causes (an empty
            # token from the AS, a target that never requested auth) — the
            # --client-id hint lives on the typed registration-error path,
            # where it is accurate.
            raise OAuthFlowError(
                "the OAuth flow completed no token exchange (the server may not have requested authentication)"
            )
        return tokens.access_token
    finally:
        await callback.close()
