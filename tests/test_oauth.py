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

from mcpscore.oauth import FLOW_TIMEOUT_S, OAuthFlowError, obtain_token_interactively

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

        loop_actions.append(asyncio.get_event_loop().create_task(complete()))

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
    for task in actions:
        await task


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
    for task in actions:
        await task


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

    def refuse(authorization_url: str) -> None:
        async def complete() -> None:
            query = {key: values[0] for key, values in parse_qs(urlsplit(authorization_url).query).items()}
            async with httpx2.AsyncClient() as browser:
                await browser.get(f"{query['redirect_uri']}?error=access_denied&state={query.get('state', '')}")

        asyncio.get_event_loop().create_task(complete())

    with pytest.raises(OAuthFlowError, match="access_denied"):
        await obtain_token_interactively(
            SERVER_URL,
            open_browser=refuse,
            transport=httpx2.MockTransport(fake.handler),
        )


def test_flow_timeout_default_is_generous():
    """A human completes a browser login; the default must allow minutes, not seconds."""
    assert FLOW_TIMEOUT_S >= 120
