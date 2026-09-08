"""Tests for connection-failure classification on MCPClient.

A server that is up but auth-gated (HTTP 401/403) must be distinguishable from
one that is genuinely unreachable, so the CLI/backend can show an actionable
message instead of a flat "could not connect".
"""

from contextlib import AsyncExitStack
import logging
from unittest.mock import MagicMock, patch

import httpx2
import pytest

from mcpscore.enums import ConnectionErrorReason, MCPTransportType
from mcpscore.mcp_client import (
    ConnectionFailure,
    MCPClient,
    _preferred_failure,
    _safe_failure_detail,
    extract_http_status,
    reason_for_status,
)
from mcpscore.redirects import unfollowed_redirect


def _http_status_error(status_code: int) -> httpx2.HTTPStatusError:
    response = MagicMock()
    response.status_code = status_code
    return httpx2.HTTPStatusError("boom", request=MagicMock(), response=response)


class TestReasonForStatus:
    @pytest.mark.parametrize(
        ("status", "reason"),
        [
            (401, ConnectionErrorReason.UNAUTHORIZED),
            (403, ConnectionErrorReason.FORBIDDEN),
            (404, ConnectionErrorReason.HTTP_ERROR),
            (500, ConnectionErrorReason.HTTP_ERROR),
        ],
    )
    def test_maps_status_to_reason(self, status, reason):
        assert reason_for_status(status) == reason


class TestExtractHttpStatus:
    def test_direct_error(self):
        assert extract_http_status(_http_status_error(401)) == 401

    def test_inside_exception_group(self):
        # The MCP SDK's anyio task group surfaces the real cause this way.
        group = ExceptionGroup("transport", [_http_status_error(401)])
        assert extract_http_status(group) == 401

    def test_chained_via_cause(self):
        outer = RuntimeError("wrapper")
        outer.__cause__ = _http_status_error(403)
        assert extract_http_status(outer) == 403

    def test_none_when_absent(self):
        assert extract_http_status(RuntimeError("no http here")) is None


class TestConnectionFailureMessage:
    def test_unauthorized_mentions_authentication(self):
        msg = ConnectionFailure(ConnectionErrorReason.UNAUTHORIZED).message
        assert "authentication" in msg.lower()

    def test_forbidden_mentions_access(self):
        msg = ConnectionFailure(ConnectionErrorReason.FORBIDDEN).message
        assert "403" in msg

    def test_http_error_surfaces_status_code(self):
        msg = ConnectionFailure(ConnectionErrorReason.HTTP_ERROR, status_code=503).message
        assert "503" in msg

    def test_not_mcp_message(self):
        msg = ConnectionFailure(ConnectionErrorReason.NOT_MCP).message
        assert "MCP" in msg

    def test_generic_detail_is_included_in_public_message(self):
        msg = ConnectionFailure(ConnectionErrorReason.UNKNOWN, detail="ImportError: missing dependency").message
        assert msg == "Could not connect to the MCP server. Details: ImportError: missing dependency"


class TestSafeFailureDetail:
    def test_escapes_terminal_controls_without_destroying_unicode(self):
        detail = _safe_failure_detail(RuntimeError("\x1b[31m故障\x1b[0m\u202e\U000e0001"))

        assert detail == r"\x1b[31m故障\x1b[0m\u202e\U000e0001"
        assert "\x1b" not in detail

    def test_empty_exception_uses_type_name(self):
        assert _safe_failure_detail(RuntimeError()) == "RuntimeError"


class TestPreferredFailure:
    def test_picks_more_informative(self):
        auth = ConnectionFailure(ConnectionErrorReason.UNAUTHORIZED)
        http = ConnectionFailure(ConnectionErrorReason.HTTP_ERROR, 405)
        # Order-independent: the auth failure (higher rank) always wins.
        assert _preferred_failure(auth, http) is auth
        assert _preferred_failure(http, auth) is auth

    def test_handles_none(self):
        only = ConnectionFailure(ConnectionErrorReason.TIMEOUT)
        assert _preferred_failure(None, only) is only
        assert _preferred_failure(only, None) is only
        assert _preferred_failure(None, None) is None


class TestConnectRecordsFailure:
    @pytest.fixture
    def mcp_client(self):
        return MCPClient()

    async def test_streamable_http_401_is_unauthorized(self, mcp_client):
        with patch("mcpscore.mcp_client.streamable_http_client") as mock_client:
            mock_client.return_value.__aenter__.side_effect = _http_status_error(401)

            result = await mcp_client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, "https://example.com/mcp")

        assert result is False
        assert mcp_client.last_connection_error is not None
        assert mcp_client.last_connection_error.reason == ConnectionErrorReason.UNAUTHORIZED
        assert "authentication" in mcp_client.last_connection_error.message.lower()

    async def test_connect_error_is_unreachable(self, mcp_client):
        with patch("mcpscore.mcp_client.streamable_http_client") as mock_client:
            mock_client.return_value.__aenter__.side_effect = httpx2.ConnectError("refused")

            result = await mcp_client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, "https://example.com/mcp")

        assert result is False
        assert mcp_client.last_connection_error.reason == ConnectionErrorReason.UNREACHABLE

    async def test_invalid_url_recorded(self, mcp_client):
        result = await mcp_client.connect_to_server(MCPTransportType.SSE, "not-a-url")
        assert result is False
        assert mcp_client.last_connection_error.reason == ConnectionErrorReason.INVALID_URL


class TestHandshakeFailureClassification:
    """Transport opens, then a buffered HTTP status surfaces during teardown as a cancellation."""

    @pytest.fixture
    def mcp_client(self):
        return MCPClient()

    async def test_discard_attempt_recovers_buffered_status(self, mcp_client):
        stack = AsyncExitStack()

        async def teardown_raises():
            raise ExceptionGroup("transport teardown", [_http_status_error(401)])

        stack.push_async_callback(teardown_raises)

        await mcp_client._discard_attempt(stack)

        assert mcp_client._pending_http_status == 401

    def test_handshake_failure_uses_buffered_status(self, mcp_client):
        mcp_client._pending_http_status = 401
        mcp_client._record_handshake_failure("https://example.com/mcp")
        assert mcp_client.last_connection_error.reason == ConnectionErrorReason.UNAUTHORIZED

    def test_handshake_failure_without_status_is_not_mcp(self, mcp_client):
        mcp_client._pending_http_status = None
        mcp_client._record_handshake_failure("https://example.com/mcp")
        assert mcp_client.last_connection_error.reason == ConnectionErrorReason.NOT_MCP


class TestDetectAndConnectPrefersInformativeFailure:
    @pytest.fixture
    def mcp_client(self):
        return MCPClient()

    async def test_http_401_beats_sse_405(self, mcp_client):
        # Streamable HTTP fails with 401; SSE fallback fails with a generic 405.
        async def fake_streamable(_url):
            mcp_client._record_failure(ConnectionErrorReason.UNAUTHORIZED, 401)
            return False

        async def fake_sse(_url):
            mcp_client._record_failure(ConnectionErrorReason.HTTP_ERROR, 405)
            return False

        with (
            patch.object(mcp_client, "_connect_with_streamable_http", side_effect=fake_streamable),
            patch.object(mcp_client, "_connect_with_sse", side_effect=fake_sse),
        ):
            success, transport = await mcp_client.detect_and_connect("https://example.com/mcp")

        assert success is False
        assert transport is None
        assert mcp_client.last_connection_error.reason == ConnectionErrorReason.UNAUTHORIZED


class TestAuthGatedHttpFallback:
    """Airtable-shaped gates: 401 evidence must skip SSE and classify cleanly."""

    async def test_sse_skipped_when_http_attempt_classifies_unauthorized(self, caplog):
        client = MCPClient()

        async def fail_http(url):
            client._record_failure(ConnectionErrorReason.UNAUTHORIZED, 401)
            return False

        with (
            patch.object(client, "_connect_with_streamable_http", side_effect=fail_http),
            patch.object(client, "_connect_with_sse") as sse,
            caplog.at_level(logging.INFO),
        ):
            success, transport = await client.detect_and_connect("https://gated.example/mcp")

        assert success is False
        assert transport is None
        sse.assert_not_called()
        assert "skipping the legacy SSE fallback" in caplog.text
        assert client.last_connection_error.reason is ConnectionErrorReason.UNAUTHORIZED

    async def test_sse_fallback_preserved_for_non_auth_failures(self):
        client = MCPClient()

        async def fail_http(url):
            client._record_failure(ConnectionErrorReason.NOT_MCP)
            return False

        async def fail_sse(url):
            client._record_failure(ConnectionErrorReason.UNREACHABLE)
            return False

        with (
            patch.object(client, "_connect_with_streamable_http", side_effect=fail_http),
            patch.object(client, "_connect_with_sse", side_effect=fail_sse) as sse,
        ):
            success, _ = await client.detect_and_connect("https://down.example/mcp")

        assert success is False
        sse.assert_called_once()

    async def test_statusless_sdk_error_recovers_401_and_skips_sse(self, caplog):
        """The Airtable shape: an SDK error with no HTTP status anywhere.

        One status-recovery POST recovers the 401, classification lands
        UNAUTHORIZED, no traceback is logged, and the SSE fallback is skipped.
        """
        client = MCPClient()

        async def recovered_401(url):
            return httpx2.Response(401)

        with (
            patch("mcpscore.mcp_client.streamable_http_client") as mock_http,
            patch.object(client, "_recover_http_response", side_effect=recovered_401) as recover,
            patch.object(client, "_connect_with_sse") as sse,
            caplog.at_level(logging.INFO),
        ):
            # A statusless SDK failure: no HTTP status in the exception chain.
            mock_http.return_value.__aenter__.side_effect = RuntimeError("Server returned an error response")
            success, transport = await client.detect_and_connect("https://airtable.example/mcp")

        assert success is False
        assert transport is None
        recover.assert_awaited_once()
        sse.assert_not_called()
        assert client.last_connection_error.reason is ConnectionErrorReason.UNAUTHORIZED
        assert "Traceback" not in caplog.text
        assert "requires authentication" in caplog.text

    async def test_recovered_non_auth_status_does_not_relabel_the_failure(self, caplog):
        """Never relabel the original failure with a recovered non-auth status.

        A recovered 200 (HTTP-fine, MCP-broken endpoint) leaves classification
        unclassified and the SSE fallback still runs.
        """
        client = MCPClient()

        async def recovered_200(url):
            return httpx2.Response(200)

        with (
            patch("mcpscore.mcp_client.streamable_http_client") as mock_http,
            patch.object(client, "_recover_http_response", side_effect=recovered_200),
            patch.object(client, "_connect_with_sse") as sse,
            caplog.at_level(logging.INFO),
        ):
            mock_http.return_value.__aenter__.side_effect = RuntimeError("bad MCP payload")
            sse.return_value = False
            success, _ = await client.detect_and_connect("https://broken.example/mcp")

        assert success is False
        # Non-auth failure: the fallback ladder is preserved.
        sse.assert_called_once()
        assert client.last_connection_error.reason is ConnectionErrorReason.UNKNOWN
        assert client.last_connection_error.status_code is None

    async def test_status_already_in_the_exception_skips_recovery(self):
        """Skip the recovery request when the failure already carries a status.

        A 500 buried in the exception chain classifies directly; spending an
        extra request on it would be pointless traffic.
        """
        client = MCPClient()

        with (
            patch("mcpscore.mcp_client.streamable_http_client") as mock_http,
            patch.object(client, "_recover_http_response") as recover,
        ):
            mock_http.return_value.__aenter__.side_effect = ExceptionGroup("transport", [_http_status_error(500)])
            result = await client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, "https://boom.example/mcp")

        assert result is False
        recover.assert_not_called()
        assert client.last_connection_error.reason is ConnectionErrorReason.HTTP_ERROR
        assert client.last_connection_error.status_code == 500

    async def test_recovery_mirrors_the_failed_attempt_headers(self):
        """Recovery must send the caller's headers, credentials included.

        It recovers the status *the failed attempt* would have reported. An
        anonymous retry would answer a different question and could report a
        gated endpoint's 401 as the caller's own token being refused — the
        probe layer answers that question separately, anonymously by design.
        """
        client = MCPClient(headers={"Authorization": "Bearer caller-token", "X-Trace": "1"})

        with patch("mcpscore.mcp_client.httpx2.AsyncClient") as mock_cls:
            instance = mock_cls.return_value.__aenter__.return_value
            instance.post.return_value = httpx2.Response(401)
            response = await client._recover_http_response("https://gated.example/mcp")

        assert response is not None
        assert response.status_code == 401
        assert mock_cls.call_args.kwargs["headers"] == {
            "Authorization": "Bearer caller-token",
            "X-Trace": "1",
        }

    async def test_recover_http_response_returns_none_on_network_error(self):
        """Recovery is best-effort: a network error yields None, not an exception."""
        client = MCPClient()

        with patch("mcpscore.mcp_client.httpx2.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.side_effect = httpx2.ConnectError("refused")
            response = await client._recover_http_response("https://unreachable.example/mcp")

        assert response is None


def _redirect_error(status: int, location: str, *, url: str = "https://server.example/mcp") -> httpx2.HTTPStatusError:
    """Build an ``HTTPStatusError`` for a real redirect response, as ``raise_for_status`` does."""
    request = httpx2.Request("POST", url)
    response = httpx2.Response(status, headers={"location": location}, request=request)
    return httpx2.HTTPStatusError("redirect", request=request, response=response)


class TestOffOriginRedirect:
    """Since mcp 2.2.0 the SDK follows a redirect only within the endpoint's origin.

    A URL that sends every request elsewhere used to be audited *at the
    redirect target*; now the session fails, and the failure must name the
    target so the user can audit it directly instead of reading "HTTP 307".
    """

    async def test_statusless_sdk_refusal_with_recovered_off_origin_redirect(self, caplog):
        """The 2.2.0 shape: the SDK raises a bare MCPError with no HTTP status in it."""
        client = MCPClient()

        async def recovered_redirect(url):
            return _redirect_error(307, "https://other.example/mcp").response

        with (
            patch("mcpscore.mcp_client.streamable_http_client") as mock_http,
            patch.object(client, "_recover_http_response", side_effect=recovered_redirect) as recover,
            patch.object(client, "_connect_with_sse", return_value=False) as sse,
            caplog.at_level(logging.INFO),
        ):
            mock_http.return_value.__aenter__.side_effect = RuntimeError(
                "Redirect to https://other.example/mcp not followed; use that URL as the endpoint"
            )
            success, transport = await client.detect_and_connect("https://server.example/mcp")

        assert success is False
        assert transport is None
        recover.assert_awaited_once()
        failure = client.last_connection_error
        assert failure is not None
        assert failure.reason is ConnectionErrorReason.REDIRECTED
        assert failure.status_code == 307
        assert failure.location == "https://other.example/mcp"
        assert failure.redirect_reason == "another origin"
        # Redirects can differ by method: the SSE fallback's GET gets its own attempt.
        sse.assert_called_once()
        assert "Traceback" not in caplog.text
        assert "a redirect mcpscore does not follow" in caplog.text

    async def test_failed_recovery_leaves_the_failure_unclassified(self):
        """Recovery is best-effort: when it yields nothing, the original failure stands as UNKNOWN."""
        client = MCPClient()

        async def nothing_recovered(url):
            return None

        with (
            patch("mcpscore.mcp_client.streamable_http_client") as mock_http,
            patch.object(client, "_recover_http_response", side_effect=nothing_recovered),
        ):
            mock_http.return_value.__aenter__.side_effect = RuntimeError("Redirect to https://x not followed")
            result = await client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, "https://server.example/mcp")

        assert result is False
        assert client.last_connection_error is not None
        assert client.last_connection_error.reason is ConnectionErrorReason.UNKNOWN
        assert client.last_connection_error.location is None

    async def test_recovered_same_origin_redirect_does_not_relabel_the_failure(self):
        """A trailing-slash 307 is one the SDK followed; whatever failed, it was not the redirect."""
        client = MCPClient()

        async def recovered_same_origin(url):
            return _redirect_error(307, "https://server.example/mcp/").response

        with (
            patch("mcpscore.mcp_client.streamable_http_client") as mock_http,
            patch.object(client, "_recover_http_response", side_effect=recovered_same_origin),
            patch.object(client, "_connect_with_sse") as sse,
        ):
            mock_http.return_value.__aenter__.side_effect = RuntimeError("bad MCP payload")
            sse.return_value = False
            success, _ = await client.detect_and_connect("https://server.example/mcp")

        assert success is False
        sse.assert_called_once()
        assert client.last_connection_error is not None
        assert client.last_connection_error.reason is ConnectionErrorReason.UNKNOWN

    async def test_sse_redirect_status_error_is_redirected_without_a_traceback(self, caplog):
        """The SSE transport raises ``HTTPStatusError`` for the redirect it left unfollowed."""
        client = MCPClient()

        with (
            patch("mcpscore.mcp_client.sse_client") as mock_sse,
            caplog.at_level(logging.INFO),
        ):
            mock_sse.return_value.__aenter__.side_effect = _redirect_error(308, "https://other.example/sse")
            result = await client.connect_to_server(MCPTransportType.SSE, "https://server.example/sse")

        assert result is False
        failure = client.last_connection_error
        assert failure is not None
        assert failure.reason is ConnectionErrorReason.REDIRECTED
        assert failure.status_code == 308
        assert failure.location == "https://other.example/sse"
        assert "Traceback" not in caplog.text

    async def test_redirect_buried_in_an_exception_group_needs_no_recovery(self):
        client = MCPClient()

        with (
            patch("mcpscore.mcp_client.streamable_http_client") as mock_http,
            patch.object(client, "_recover_http_response") as recover,
        ):
            mock_http.return_value.__aenter__.side_effect = ExceptionGroup(
                "transport", [_redirect_error(307, "https://other.example/mcp")]
            )
            result = await client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, "https://server.example/mcp")

        assert result is False
        recover.assert_not_called()
        assert client.last_connection_error is not None
        assert client.last_connection_error.reason is ConnectionErrorReason.REDIRECTED
        assert client.last_connection_error.location == "https://other.example/mcp"

    async def test_redirect_seen_in_teardown_classifies_the_handshake_failure(self):
        """A redirect surfaced by the transport's task group at teardown carries its target."""
        client = MCPClient()
        stack = AsyncExitStack()

        async def surface_redirect() -> None:
            raise ExceptionGroup("transport", [_redirect_error(307, "https://other.example/mcp")])

        stack.push_async_callback(surface_redirect)
        await client._discard_attempt(stack)
        client._record_handshake_failure("https://server.example/mcp")

        failure = client.last_connection_error
        assert failure is not None
        assert failure.reason is ConnectionErrorReason.REDIRECTED
        assert failure.status_code == 307
        assert failure.location == "https://other.example/mcp"

    async def test_same_origin_redirect_status_stays_a_plain_http_error(self):
        """Past the redirect budget the response is a 307 the policy would have followed: not REDIRECTED."""
        client = MCPClient()

        with patch("mcpscore.mcp_client.sse_client") as mock_sse:
            mock_sse.return_value.__aenter__.side_effect = _redirect_error(307, "https://server.example/sse/")
            await client.connect_to_server(MCPTransportType.SSE, "https://server.example/sse")

        assert client.last_connection_error is not None
        assert client.last_connection_error.reason is ConnectionErrorReason.HTTP_ERROR
        assert client.last_connection_error.status_code == 307

    async def test_a_method_refusal_on_the_post_still_gets_the_sse_attempt(self):
        """The SSE fallback opens with a GET, which the SDK follows through a same-origin 303 unchanged."""
        client = MCPClient()

        async def fail_http(url):
            client._record_status_failure(303, unfollowed_redirect(_redirect_error(303, f"{url}/").response))
            return False

        with (
            patch.object(client, "_connect_with_streamable_http", side_effect=fail_http),
            patch.object(client, "_connect_with_sse", return_value=True) as sse,
        ):
            success, transport = await client.detect_and_connect("https://server.example/mcp")

        assert success is True
        assert transport is MCPTransportType.SSE
        sse.assert_called_once()

    async def test_an_off_origin_refusal_still_tries_sse_and_keeps_the_diagnosis(self):
        """A legacy endpoint may redirect POST /mcp elsewhere yet serve SSE on GET /mcp; the GET is tried.

        When that attempt fails for less (a 404), the redirect stays the reported failure.
        """
        client = MCPClient()

        async def fail_http(url):
            client._record_status_failure(
                303, unfollowed_redirect(_redirect_error(303, "https://other.example/mcp").response)
            )
            return False

        async def fail_sse(url):
            client._record_failure(ConnectionErrorReason.HTTP_ERROR, 404)
            return False

        with (
            patch.object(client, "_connect_with_streamable_http", side_effect=fail_http),
            patch.object(client, "_connect_with_sse", side_effect=fail_sse) as sse,
        ):
            success, _ = await client.detect_and_connect("https://server.example/mcp")

        assert success is False
        sse.assert_called_once()
        assert client.last_connection_error is not None
        assert client.last_connection_error.reason is ConnectionErrorReason.REDIRECTED
        assert client.last_connection_error.location == "https://other.example/mcp"

    async def test_sse_served_directly_behind_a_redirecting_post_connects(self):
        client = MCPClient()

        async def fail_http(url):
            client._record_status_failure(
                307, unfollowed_redirect(_redirect_error(307, "https://other.example/mcp").response)
            )
            return False

        with (
            patch.object(client, "_connect_with_streamable_http", side_effect=fail_http),
            patch.object(client, "_connect_with_sse", return_value=True),
        ):
            success, transport = await client.detect_and_connect("https://server.example/mcp")

        assert success is True
        assert transport is MCPTransportType.SSE

    def test_message_names_the_target_the_rule_and_the_fix(self):
        failure = ConnectionFailure(
            ConnectionErrorReason.REDIRECTED,
            307,
            location="https://other.example/mcp",
            redirect_reason="another origin",
        )
        assert failure.message == (
            "The server redirected (HTTP 307) to https://other.example/mcp, which mcpscore does not follow "
            "(another origin) — audit that URL instead if it is the intended server."
        )
        # A same-origin 303 is refused for a different reason, and the message must not claim another origin.
        same_origin = ConnectionFailure(
            ConnectionErrorReason.REDIRECTED,
            303,
            location="https://server.example/mcp/",
            redirect_reason="the POST would become a GET",
        )
        assert "another origin" not in same_origin.message
        assert "(the POST would become a GET)" in same_origin.message
        bare = ConnectionFailure(ConnectionErrorReason.REDIRECTED, 307, location="https://other.example/mcp")
        assert bare.message.endswith("does not follow — audit that URL instead if it is the intended server.")
        assert "keeps the request as sent" in ConnectionFailure(ConnectionErrorReason.REDIRECTED).message

    async def test_downgrade_message_suggests_the_https_form_never_the_plaintext_target(self):
        """A server must not be able to make the CLI recommend a URL where the token would travel in the clear."""
        client = MCPClient()

        with patch("mcpscore.mcp_client.sse_client") as mock_sse:
            mock_sse.return_value.__aenter__.side_effect = _redirect_error(307, "http://server.example/mcp/")
            await client.connect_to_server(MCPTransportType.SSE, "https://server.example/mcp")

        failure = client.last_connection_error
        assert failure is not None
        assert failure.reason is ConnectionErrorReason.REDIRECTED
        assert failure.redirect_reason == "it would downgrade this HTTPS endpoint to plain HTTP"
        assert failure.location == "http://server.example/mcp/"
        assert "try https://server.example/mcp/ instead" in failure.message
        assert "TLS-terminating proxy" in failure.message
        assert "audit that URL" not in failure.message

    async def test_same_origin_303_on_the_post_is_redirected_with_its_own_reason(self):
        """The SDK refuses a same-origin 303 too (it would drop the message); the diagnosis must say so."""
        client = MCPClient()

        with patch("mcpscore.mcp_client.sse_client") as mock_sse:
            mock_sse.return_value.__aenter__.side_effect = _redirect_error(303, "https://server.example/mcp/")
            await client.connect_to_server(MCPTransportType.SSE, "https://server.example/mcp")

        failure = client.last_connection_error
        assert failure is not None
        assert failure.reason is ConnectionErrorReason.REDIRECTED
        assert failure.redirect_reason == "the POST would become a GET"
        assert "another origin" not in failure.message

    def test_outranks_the_http_error_the_other_transport_reports(self):
        redirected = ConnectionFailure(ConnectionErrorReason.REDIRECTED, 307, location="https://other.example/mcp")
        http = ConnectionFailure(ConnectionErrorReason.HTTP_ERROR, 307)
        assert _preferred_failure(http, redirected) is redirected
        assert _preferred_failure(redirected, http) is redirected

    @pytest.mark.parametrize("transport_reason", [ConnectionErrorReason.TIMEOUT, ConnectionErrorReason.UNREACHABLE])
    def test_outranks_a_transport_failure_seen_first(self, transport_reason: ConnectionErrorReason):
        """A timed-out POST followed by a redirected SSE GET must report the redirect, not the timeout."""
        first = ConnectionFailure(transport_reason)
        redirected = ConnectionFailure(ConnectionErrorReason.REDIRECTED, 307, location="https://other.example/mcp")
        assert _preferred_failure(first, redirected) is redirected

    def test_auth_still_outranks_a_redirect(self):
        redirected = ConnectionFailure(ConnectionErrorReason.REDIRECTED, 307, location="https://other.example/mcp")
        for auth_reason in (ConnectionErrorReason.UNAUTHORIZED, ConnectionErrorReason.FORBIDDEN):
            auth = ConnectionFailure(auth_reason)
            assert _preferred_failure(redirected, auth) is auth
            assert _preferred_failure(auth, redirected) is auth

    async def test_timed_out_post_then_redirected_sse_get_reports_the_redirect(self):
        client = MCPClient()

        async def time_out(url):
            client._record_failure(ConnectionErrorReason.TIMEOUT)
            return False

        async def redirected_get(url):
            client._record_status_failure(
                307, unfollowed_redirect(_redirect_error(307, "https://other.example/sse").response)
            )
            return False

        with (
            patch.object(client, "_connect_with_streamable_http", side_effect=time_out),
            patch.object(client, "_connect_with_sse", side_effect=redirected_get),
        ):
            success, _ = await client.detect_and_connect("https://server.example/mcp")

        assert success is False
        assert client.last_connection_error is not None
        assert client.last_connection_error.reason is ConnectionErrorReason.REDIRECTED
        assert client.last_connection_error.location == "https://other.example/sse"
