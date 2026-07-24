"""Tests for the interactive OAuth flow (--oauth).

The full loop runs hermetically: a MockTransport plays the gated MCP server
and its authorization server (discovery, registration, token exchange), the
real loopback listener catches the redirect, and a fake "user" completes the
authorization by following the authorize URL's redirect programmatically.
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest

from mcpscore.oauth import FLOW_TIMEOUT_S, OAuthFlowError, _LoopbackCallbackServer, obtain_token_interactively

SERVER_URL = "https://server.example/mcp"
AS_ISSUER = "https://auth.example"
ACCESS_TOKEN = "test-access-token-123"


class FakeAuthServer:
    """MockTransport handler covering the gated server and its AS."""

    def __init__(self, *, dynamic_registration: bool = True) -> None:
        super().__init__()
        self.dynamic_registration = dynamic_registration
        self.register_calls = 0
        self.token_calls: list[dict[str, str]] = []

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        url = str(request.url)
        if url.startswith(SERVER_URL):
            if request.headers.get("Authorization") == f"Bearer {ACCESS_TOKEN}":
                return httpx2.Response(200, json={})
            metadata_url = "https://server.example/.well-known/oauth-protected-resource/mcp"
            return httpx2.Response(
                401,
                headers={"WWW-Authenticate": f'Bearer resource_metadata="{metadata_url}"'},
            )
        if "oauth-protected-resource" in url:
            return httpx2.Response(200, json={"resource": SERVER_URL, "authorization_servers": [AS_ISSUER]})
        if "oauth-authorization-server" in url or "openid-configuration" in url:
            metadata = {
                "issuer": AS_ISSUER,
                "authorization_endpoint": f"{AS_ISSUER}/authorize",
                "token_endpoint": f"{AS_ISSUER}/token",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
            }
            if self.dynamic_registration:
                metadata["registration_endpoint"] = f"{AS_ISSUER}/register"
            return httpx2.Response(200, json=metadata)
        if url.startswith(f"{AS_ISSUER}/register"):
            self.register_calls += 1
            body = json.loads(request.content)
            return httpx2.Response(
                201,
                json={"client_id": "registered-client", **body},
            )
        if url.startswith(f"{AS_ISSUER}/token"):
            form = {key: values[0] for key, values in parse_qs(request.content.decode()).items()}
            self.token_calls.append(form)
            return httpx2.Response(
                200,
                json={"access_token": ACCESS_TOKEN, "token_type": "Bearer", "expires_in": 3600},
            )
        return httpx2.Response(404)


def _fake_user(loop_actions: list[asyncio.Task]) -> object:
    """Return an open_browser stand-in that "authorizes" via the loopback redirect."""

    def open_browser(authorization_url: str) -> None:
        async def complete() -> None:
            query = {key: values[0] for key, values in parse_qs(urlsplit(authorization_url).query).items()}
            redirect_uri = query["redirect_uri"]
            state = query.get("state", "")
            async with httpx2.AsyncClient() as browser:
                await browser.get(f"{redirect_uri}?code=fake-auth-code&state={state}")

        loop_actions.append(asyncio.create_task(complete()))

    return open_browser


async def test_full_flow_with_dynamic_registration():
    fake = FakeAuthServer()
    actions: list[asyncio.Task] = []

    token = await obtain_token_interactively(
        SERVER_URL,
        open_browser=_fake_user(actions),
        transport=httpx2.MockTransport(fake.handler),
    )

    assert token == ACCESS_TOKEN
    assert fake.register_calls == 1
    # PKCE was used in the exchange, with the public-client method.
    assert fake.token_calls[0]["grant_type"] == "authorization_code"
    assert "code_verifier" in fake.token_calls[0]
    await asyncio.gather(*actions)


async def test_client_id_skips_dynamic_registration():
    """--client-id pre-seeds client info so no registration request is made."""
    fake = FakeAuthServer(dynamic_registration=False)
    actions: list[asyncio.Task] = []

    token = await obtain_token_interactively(
        SERVER_URL,
        client_id="preregistered-app",
        open_browser=_fake_user(actions),
        transport=httpx2.MockTransport(fake.handler),
    )

    assert token == ACCESS_TOKEN
    assert fake.register_calls == 0
    assert fake.token_calls[0]["client_id"] == "preregistered-app"
    await asyncio.gather(*actions)


async def test_user_timeout_raises_flow_failed():
    fake = FakeAuthServer()

    with pytest.raises(OAuthFlowError, match="timed out"):
        await obtain_token_interactively(
            SERVER_URL,
            flow_timeout_s=0.2,
            open_browser=lambda _url: None,  # the "user" never authorizes
            transport=httpx2.MockTransport(fake.handler),
        )


async def test_authorization_refusal_raises_flow_failed():
    fake = FakeAuthServer()

    actions: list[asyncio.Task] = []

    def refuse(authorization_url: str) -> None:
        async def complete() -> None:
            query = {key: values[0] for key, values in parse_qs(urlsplit(authorization_url).query).items()}
            async with httpx2.AsyncClient() as browser:
                await browser.get(f"{query['redirect_uri']}?error=access_denied&state={query.get('state', '')}")

        actions.append(asyncio.create_task(complete()))

    with pytest.raises(OAuthFlowError, match="access_denied"):
        await obtain_token_interactively(
            SERVER_URL,
            open_browser=refuse,
            transport=httpx2.MockTransport(fake.handler),
        )
    await asyncio.gather(*actions)


def test_flow_timeout_default_is_generous():
    """A human completes a browser login; the default must allow minutes, not seconds."""
    assert FLOW_TIMEOUT_S >= 120


async def test_registration_failure_hints_client_id():
    """A 404 from the registration endpoint produces the --client-id hint."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        url = str(request.url)
        if url.startswith(SERVER_URL):
            metadata_url = "https://server.example/.well-known/oauth-protected-resource/mcp"
            return httpx2.Response(401, headers={"WWW-Authenticate": f'Bearer resource_metadata="{metadata_url}"'})
        if "oauth-protected-resource" in url:
            return httpx2.Response(200, json={"resource": SERVER_URL, "authorization_servers": [AS_ISSUER]})
        if "oauth-authorization-server" in url or "openid-configuration" in url:
            return httpx2.Response(
                200,
                json={
                    "issuer": AS_ISSUER,
                    "authorization_endpoint": f"{AS_ISSUER}/authorize",
                    "token_endpoint": f"{AS_ISSUER}/token",
                    "registration_endpoint": f"{AS_ISSUER}/register",
                    "response_types_supported": ["code"],
                    "code_challenge_methods_supported": ["S256"],
                },
            )
        if url.startswith(f"{AS_ISSUER}/register"):
            return httpx2.Response(404, text="404 page not found")
        return httpx2.Response(404)

    with pytest.raises(OAuthFlowError, match="try --client-id"):
        await obtain_token_interactively(
            SERVER_URL,
            open_browser=lambda _url: None,
            transport=httpx2.MockTransport(handler),
        )


async def test_stray_bare_callback_does_not_consume_the_flow():
    """A parameterless /callback visit (scanner, prefetch) must not end the wait."""
    fake = FakeAuthServer()
    actions: list[asyncio.Task] = []

    def stray_then_real(authorization_url: str) -> None:
        async def complete() -> None:
            query = {key: values[0] for key, values in parse_qs(urlsplit(authorization_url).query).items()}
            redirect_uri = query["redirect_uri"]
            async with httpx2.AsyncClient() as browser:
                stray = await browser.get(redirect_uri)  # no code, no error — ignored
                assert "waiting" in stray.text
                await browser.get(f"{redirect_uri}?code=fake-auth-code&state={query.get('state', '')}")

        actions.append(asyncio.create_task(complete()))

    token = await obtain_token_interactively(
        SERVER_URL,
        open_browser=stray_then_real,
        transport=httpx2.MockTransport(fake.handler),
    )
    assert token == ACCESS_TOKEN
    await asyncio.gather(*actions)


async def test_empty_token_response_raises_with_hint():
    """A token endpoint returning an empty access token yields the no-token error."""
    fake = FakeAuthServer()
    original = fake.handler

    def handler(request: httpx2.Request) -> httpx2.Response:
        if str(request.url).startswith(f"{AS_ISSUER}/token"):
            return httpx2.Response(200, json={"access_token": "", "token_type": "Bearer"})
        return original(request)

    actions: list[asyncio.Task] = []
    with pytest.raises(OAuthFlowError, match="no token exchange"):
        await obtain_token_interactively(
            SERVER_URL,
            open_browser=_fake_user(actions),
            transport=httpx2.MockTransport(handler),
        )
    await asyncio.gather(*actions)


async def test_loopback_unavailable_raises(monkeypatch: pytest.MonkeyPatch):
    async def failing_start(self) -> None:
        raise OSError(98, "Address already in use")

    monkeypatch.setattr(_LoopbackCallbackServer, "start", failing_start)
    with pytest.raises(OAuthFlowError, match="loopback port"):
        await obtain_token_interactively(SERVER_URL)


async def test_non_callback_requests_are_ignored():
    """A stray request (e.g. favicon) must not consume the one-shot callback."""
    fake = FakeAuthServer()
    actions: list[asyncio.Task] = []

    def browser_with_favicon(authorization_url: str) -> None:
        async def complete() -> None:
            query = {key: values[0] for key, values in parse_qs(urlsplit(authorization_url).query).items()}
            redirect_uri = query["redirect_uri"]
            base = redirect_uri.rsplit("/", 1)[0]
            async with httpx2.AsyncClient() as browser:
                favicon = await browser.get(f"{base}/favicon.ico")  # ignored by the listener
                assert favicon.status_code == 404
                success = await browser.get(f"{redirect_uri}?code=fake-auth-code&state={query.get('state', '')}")
                assert "close this tab" in success.text

        actions.append(asyncio.create_task(complete()))

    token = await obtain_token_interactively(
        SERVER_URL,
        open_browser=browser_with_favicon,
        transport=httpx2.MockTransport(fake.handler),
    )
    assert token == ACCESS_TOKEN
    await asyncio.gather(*actions)


async def test_second_callback_request_is_ignored():
    """The listener is one-shot: a duplicate redirect must not disturb the result."""
    listener = _LoopbackCallbackServer()
    await listener.start()
    try:
        async with httpx2.AsyncClient() as browser:
            await browser.get(f"{listener.redirect_uri}?code=first-code&state=s1")
            # The user double-clicks / the browser retries: same redirect again.
            await browser.get(f"{listener.redirect_uri}?code=stale-second-code&state=s2")
        params = await listener.wait_for_callback(timeout_s=2)
        assert params["code"] == "first-code"
    finally:
        await listener.close()


async def test_token_exchange_failure_has_no_client_id_hint():
    """A failure past registration (e.g. broken token endpoint) must not suggest --client-id."""
    fake = FakeAuthServer()
    original = fake.handler

    def handler(request: httpx2.Request) -> httpx2.Response:
        if str(request.url).startswith(f"{AS_ISSUER}/token"):
            return httpx2.Response(500, text="token endpoint exploded")
        return original(request)

    actions: list[asyncio.Task] = []
    with pytest.raises(OAuthFlowError) as exc:
        await obtain_token_interactively(
            SERVER_URL,
            open_browser=_fake_user(actions),
            transport=httpx2.MockTransport(handler),
        )
    assert "--client-id" not in str(exc.value)
    await asyncio.gather(*actions)


async def test_close_before_start_is_safe():
    await _LoopbackCallbackServer().close()  # must not raise


async def test_fixed_callback_port_is_used():
    """--callback-port pins the redirect URI for strict authorization servers."""
    import socket as socket_module

    with socket_module.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    fake = FakeAuthServer(dynamic_registration=False)
    actions: list[asyncio.Task] = []
    seen_redirects: list[str] = []

    def check_redirect(authorization_url: str) -> None:
        query = {key: values[0] for key, values in parse_qs(urlsplit(authorization_url).query).items()}
        seen_redirects.append(query["redirect_uri"])

        async def complete() -> None:
            async with httpx2.AsyncClient() as browser:
                await browser.get(f"{query['redirect_uri']}?code=fake-auth-code&state={query.get('state', '')}")

        actions.append(asyncio.create_task(complete()))

    token = await obtain_token_interactively(
        SERVER_URL,
        client_id="preregistered-app",
        callback_port=port,
        open_browser=check_redirect,
        transport=httpx2.MockTransport(fake.handler),
    )
    assert token == ACCESS_TOKEN
    assert seen_redirects == [f"http://127.0.0.1:{port}/callback"]
    await asyncio.gather(*actions)


async def test_flow_request_is_valid_json_rpc():
    """The flow-driving request must be valid JSON-RPC so strict servers still 401."""
    seen_bodies: list[dict] = []
    fake = FakeAuthServer()
    original = fake.handler

    def handler(request: httpx2.Request) -> httpx2.Response:
        if str(request.url).startswith(SERVER_URL) and request.content:
            seen_bodies.append(json.loads(request.content))
        return original(request)

    actions: list[asyncio.Task] = []
    await obtain_token_interactively(
        SERVER_URL,
        open_browser=_fake_user(actions),
        transport=httpx2.MockTransport(handler),
    )
    assert seen_bodies, "the flow must have posted to the server"
    assert seen_bodies[0].get("jsonrpc") == "2.0"
    assert "method" in seen_bodies[0]
    await asyncio.gather(*actions)


async def test_unknown_exception_text_is_not_echoed():
    """Arbitrary exception text may carry response bodies — only the type is safe to log."""

    class ExplodingTransport(httpx2.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
            raise RuntimeError("body dump with secret-sounding-content-xyz")

    with pytest.raises(OAuthFlowError) as exc:
        await obtain_token_interactively(
            SERVER_URL,
            open_browser=lambda _url: None,
            transport=ExplodingTransport(),
        )
    assert "secret-sounding-content-xyz" not in str(exc.value)
    assert "RuntimeError" in str(exc.value)


async def test_token_survives_failed_followup_request():
    """A network error on the retried request must not discard an obtained token."""
    fake = FakeAuthServer()
    actions: list[asyncio.Task] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        if str(request.url).startswith(SERVER_URL) and request.headers.get("Authorization"):
            raise httpx2.ConnectError("server hiccup on the authorized retry")
        return fake.handler(request)

    token = await obtain_token_interactively(
        SERVER_URL,
        open_browser=_fake_user(actions),
        transport=httpx2.MockTransport(handler),
    )
    assert token == ACCESS_TOKEN
    await asyncio.gather(*actions)
