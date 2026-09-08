"""Tests for the same-origin redirect policy the engine's raw HTTP requests apply."""

from __future__ import annotations

import httpx2
import pytest

from mcpscore.redirects import (
    REFUSED_CREDENTIALS,
    REFUSED_OFF_ORIGIN,
    RefusedRedirect,
    redirect_target,
    send_within_origin,
    unfollowed_redirect,
    within_origin,
)

ORIGIN = "https://server.example"
URL = f"{ORIGIN}/mcp"


def _url(value: str) -> httpx2.URL:
    return httpx2.URL(value)


class TestWithinOrigin:
    @pytest.mark.parametrize(
        ("sent", "location", "expected"),
        [
            (URL, f"{ORIGIN}/mcp/", True),  # trailing-slash normalisation
            (URL, f"{ORIGIN}:443/other", True),  # default port normalises to None
            (URL, "https://SERVER.example/mcp", True),  # hosts compare case-insensitively
            ("http://server.example/mcp", "https://server.example/mcp", True),  # https upgrade
            ("http://server.example:8080/mcp", "https://server.example/mcp", False),  # non-default port
            ("http://server.example/mcp", "https://server.example:8443/mcp", False),
            (URL, "http://server.example/mcp", False),  # downgrade
            (URL, "https://other.example/mcp", False),
            (URL, "https://server.example:8443/mcp", False),
            (URL, "https://mcp.server.example/mcp", False),  # a subdomain is another origin
        ],
    )
    def test_rule(self, sent: str, location: str, expected: bool):
        assert within_origin(_url(sent), _url(location)) is expected


def _redirect(status: int, location: str | None, *, method: str = "POST", url: str = URL) -> httpx2.Response:
    headers = {"location": location} if location is not None else {}
    return httpx2.Response(status, headers=headers, request=httpx2.Request(method, url))


class TestUnfollowedRedirect:
    def test_off_origin_redirect_reports_its_absolute_target_and_the_rule(self):
        assert unfollowed_redirect(_redirect(307, "https://other.example/mcp")) == RefusedRedirect(
            "https://other.example/mcp", "another origin"
        )

    def test_relative_location_is_resolved_against_the_request(self):
        refused = unfollowed_redirect(_redirect(303, "/mcp/"))
        assert refused is not None
        assert refused.target == f"{ORIGIN}/mcp/"

    def test_same_origin_method_keeping_redirect_is_followed_so_not_reported(self):
        assert unfollowed_redirect(_redirect(307, f"{ORIGIN}/mcp/")) is None
        assert unfollowed_redirect(_redirect(308, "/mcp/")) is None

    def test_same_origin_redirect_that_would_drop_the_post_body_is_reported(self):
        # httpx2 turns a POST into a body-less GET for 301/302/303 — the
        # message would be lost, so the policy does not follow it.
        assert unfollowed_redirect(_redirect(303, "/mcp/")) == RefusedRedirect(
            f"{ORIGIN}/mcp/", "the POST would become a GET"
        )

    def test_same_origin_get_redirect_of_any_status_is_followed(self):
        assert unfollowed_redirect(_redirect(302, "/mcp/", method="GET")) is None
        assert unfollowed_redirect(_redirect(301, "/mcp/", method="GET")) is None
        assert unfollowed_redirect(_redirect(303, "/mcp/", method="HEAD")) is None

    @pytest.mark.parametrize(
        ("status", "method", "followed"),
        [
            (301, "DELETE", True),  # httpx2 turns only a POST into a GET on a 301
            (301, "POST", False),
            (302, "DELETE", False),  # a 302 turns everything but HEAD/QUERY into a GET
            (302, "QUERY", True),
            (303, "DELETE", False),
            (307, "DELETE", True),
        ],
    )
    def test_method_rule_mirrors_httpx2(self, status: int, method: str, followed: bool):
        """The refusal tracks the method httpx2 would actually send, not "anything but GET"."""
        refused = unfollowed_redirect(_redirect(status, "/mcp/", method=method))
        assert (refused is None) is followed
        if refused is not None:
            assert refused.why == f"the {method} would become a GET"

    def test_off_origin_303_is_reported_as_off_origin_not_as_a_method_change(self):
        """Reasons that hold for any request come first, so a caller can tell them apart."""
        refused = unfollowed_redirect(_redirect(303, "https://other.example/mcp"))
        assert refused is not None
        assert refused.why == REFUSED_OFF_ORIGIN
        with_credentials = unfollowed_redirect(_redirect(303, "https://u:p@server.example/mcp/"))
        assert with_credentials is not None
        assert with_credentials.why == REFUSED_CREDENTIALS

    def test_userinfo_introduced_by_the_redirect_is_refused(self):
        assert unfollowed_redirect(_redirect(307, "https://user:pw@server.example/mcp")) == RefusedRedirect(
            "https://user:pw@server.example/mcp", "the target URL introduces credentials"
        )

    def test_userinfo_the_endpoint_already_carries_is_inherited_by_a_relative_redirect(self):
        """As in the SDK (#3450): a relative Location keeps the configured URL's userinfo unchanged."""
        endpoint = "https://user:pw@server.example/mcp"
        assert unfollowed_redirect(_redirect(307, "/mcp/", url=endpoint)) is None
        # Repeating it verbatim in an absolute Location is unchanged too.
        assert unfollowed_redirect(_redirect(308, "https://user:pw@server.example/mcp/", url=endpoint)) is None

    def test_userinfo_changed_by_the_redirect_is_refused(self):
        endpoint = "https://user:pw@server.example/mcp"
        refused = unfollowed_redirect(_redirect(307, "https://other:secret@server.example/mcp/", url=endpoint))
        assert refused is not None
        assert refused.why == "the target URL introduces credentials"

    def test_non_redirect_and_locationless_redirect_report_none(self):
        assert unfollowed_redirect(httpx2.Response(200, request=httpx2.Request("POST", URL))) is None
        assert unfollowed_redirect(_redirect(307, None)) is None
        assert redirect_target(_redirect(307, "")) is None


class TestSendWithinOrigin:
    async def _send(self, handler, *, method: str = "POST", url: str = URL, **client_kwargs):
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler), **client_kwargs) as client:
            request = client.build_request(method, url, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
            return await send_within_origin(client, request)

    async def test_follows_a_same_origin_redirect_chain_keeping_the_body(self):
        seen: list[tuple[str, bytes]] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            seen.append((request.url.path, request.content))
            if request.url.path == "/mcp":
                return httpx2.Response(307, headers={"location": "/mcp/"})
            if request.url.path == "/mcp/":
                return httpx2.Response(308, headers={"location": "/v2/mcp/"})
            return httpx2.Response(200, json={"ok": True})

        response = await self._send(handler)

        assert response.status_code == 200
        assert [path for path, _ in seen] == ["/mcp", "/mcp/", "/v2/mcp/"]
        assert len({content for _, content in seen}) == 1  # the POST body travelled with every hop

    async def test_returns_an_off_origin_redirect_unfollowed(self):
        hosts: list[str] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            hosts.append(request.url.host)
            if request.url.host == "server.example":
                return httpx2.Response(307, headers={"location": "https://other.example/mcp"})
            return httpx2.Response(200)

        response = await self._send(handler)

        assert response.status_code == 307
        assert hosts == ["server.example"]
        assert unfollowed_redirect(response) == RefusedRedirect("https://other.example/mcp", "another origin")

    async def test_ignores_the_clients_own_follow_redirects_setting(self):
        hosts: list[str] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            hosts.append(request.url.host)
            if request.url.host == "server.example":
                return httpx2.Response(307, headers={"location": "https://other.example/mcp"})
            return httpx2.Response(200)

        response = await self._send(handler, follow_redirects=True)

        assert response.status_code == 307
        assert hosts == ["server.example"]

    async def test_follows_an_https_upgrade_but_not_a_downgrade(self):
        def upgrade(request: httpx2.Request) -> httpx2.Response:
            if request.url.scheme == "http":
                return httpx2.Response(308, headers={"location": "https://server.example/mcp"})
            return httpx2.Response(200)

        def downgrade(request: httpx2.Request) -> httpx2.Response:
            if request.url.scheme == "https":
                return httpx2.Response(308, headers={"location": "http://server.example/mcp"})
            return httpx2.Response(200)

        assert (await self._send(upgrade, url="http://server.example/mcp")).status_code == 200
        assert (await self._send(downgrade)).status_code == 308

    async def test_does_not_follow_a_redirect_that_would_turn_the_post_into_a_get(self):
        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method == "POST":
                return httpx2.Response(303, headers={"location": "/mcp/"})
            return httpx2.Response(200)

        response = await self._send(handler)

        assert response.status_code == 303

    async def test_follows_a_relative_redirect_when_the_endpoint_carries_userinfo(self):
        seen: list[str] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            seen.append(str(request.url))
            if request.url.path == "/mcp":
                return httpx2.Response(307, headers={"location": "/mcp/"})
            return httpx2.Response(200)

        response = await self._send(handler, url="https://user:pw@server.example/mcp")

        assert response.status_code == 200
        assert seen == ["https://user:pw@server.example/mcp", "https://user:pw@server.example/mcp/"]

    async def test_stops_at_the_clients_redirect_budget(self):
        def handler(request: httpx2.Request) -> httpx2.Response:
            # Every hop is same-origin and method-keeping: only the budget ends it.
            return httpx2.Response(307, headers={"location": f"{request.url.path}x"})

        response = await self._send(handler, max_redirects=2)

        assert response.status_code == 307
        assert response.request.url.path == "/mcpxx"
        # Past the budget the policy would have followed: not an off-origin redirect.
        assert unfollowed_redirect(response) is None
