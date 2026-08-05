"""Tests for the sessionless HTTP probe layer."""

import json

import httpx2
import pytest

from mcpscore.probes import (
    ERROR_HEADER_MISMATCH,
    ERROR_INVALID_PARAMS,
    ERROR_LEGACY_RESOURCE_NOT_FOUND,
    ERROR_UNSUPPORTED_PROTOCOL_VERSION,
    META_PREFIX,
    PROBE_AUTH_METADATA,
    PROBE_DISCOVER,
    PROBE_HEADER_MISMATCH,
    PROBE_IDS,
    PROBE_MALFORMED_META,
    PROBE_MISSING_RESOURCE,
    PROBE_REMOVED_METHOD,
    PROBE_SESSION_ID_ECHO,
    PROBE_STATELESS_LIST,
    PROBE_UNAUTHENTICATED,
    PROBE_UNKNOWN_VERSION,
    ProbeOutcome,
    ProbeResult,
    _fetch_auth_server_metadata,
    _well_known_urls,
    not_applicable_results,
    run_all_probes,
)

URL = "https://server.example/mcp"


def _rpc_error(request_id, code: int, message: str, data: dict | None = None, http_status: int = 400):
    error: dict = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return httpx2.Response(
        http_status,
        json={"jsonrpc": "2.0", "id": request_id, "error": error},
    )


def _rpc_result(request_id, result: dict):
    return httpx2.Response(200, json={"jsonrpc": "2.0", "id": request_id, "result": result})


AUTH_SERVERS = ["https://auth.example"]


def _modern_server_handler(request: httpx2.Request) -> httpx2.Response:
    """Simulate a server implementing the 2026-07-28 behaviors the probes check."""
    if request.method == "GET":
        # RFC 9728 path-aware well-known location for URL's /mcp path.
        if request.url.path == "/.well-known/oauth-protected-resource/mcp":
            return httpx2.Response(200, json={"resource": URL, "authorization_servers": AUTH_SERVERS})
        return httpx2.Response(404)
    body = json.loads(request.content)
    request_id = body.get("id")
    method = body["method"]
    meta = body.get("params", {}).get("_meta", {})

    # SEP-2243: header/body mismatch → 400 + HeaderMismatch
    if request.headers.get("Mcp-Method") != method:
        return _rpc_error(request_id, ERROR_HEADER_MISMATCH, "HeaderMismatch")

    # Unknown protocol version → 400 + UnsupportedProtocolVersion
    if meta.get(f"{META_PREFIX}protocolVersion") == "2099-01-01":
        return _rpc_error(
            request_id,
            ERROR_UNSUPPORTED_PROTOCOL_VERSION,
            "UnsupportedProtocolVersion",
            data={"supported": ["2026-07-28"], "requested": "2099-01-01"},
        )

    # Missing required _meta field → 400 + Invalid params
    required = (f"{META_PREFIX}protocolVersion", f"{META_PREFIX}clientInfo", f"{META_PREFIX}clientCapabilities")
    if any(key not in meta for key in required):
        return _rpc_error(request_id, ERROR_INVALID_PARAMS, "Invalid params")

    if method == "server/discover":
        return _rpc_result(
            request_id,
            {
                "resultType": "complete",
                "supportedVersions": ["2025-11-25", "2026-07-28"],
                "capabilities": {},
                # 2026-07-28 carries serverInfo in the result's `_meta`;
                # DiscoverResult has no top-level field. Keep fixtures
                # spec-accurate — a legacy-shaped one hid a real extraction
                # bug until 2026-08-04.
                "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "modern", "version": "1.0"}},
                "ttlMs": 60000,
                "cacheScope": "public",
            },
        )
    if method == "tools/list":
        return _rpc_result(
            request_id,
            {"resultType": "complete", "tools": [], "ttlMs": 60000, "cacheScope": "public"},
        )
    if method == "resources/read":
        return _rpc_error(request_id, ERROR_INVALID_PARAMS, "Unknown resource", http_status=400)
    return _rpc_error(request_id, -32601, "Method not found", http_status=404)


def _legacy_server_handler(request: httpx2.Request) -> httpx2.Response:
    """Simulate a stateful 2025-11-25 server: no session → everything is an error."""
    if request.method == "GET":
        return httpx2.Response(404)
    body = json.loads(request.content)
    if body["method"] == "resources/read":
        return _rpc_error(body.get("id"), ERROR_LEGACY_RESOURCE_NOT_FOUND, "Resource not found", http_status=200)
    return httpx2.Response(
        400,
        json={"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32600, "message": "Bad Request: no session"}},
    )


def _client(handler) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(transport=httpx2.MockTransport(handler))


async def _run(handler) -> dict[str, ProbeResult]:
    async with _client(handler) as client:
        return await run_all_probes(URL, client=client)


async def test_modern_server_supports_all_probed_behaviors():
    results = await _run(_modern_server_handler)

    assert set(results) == set(PROBE_IDS)
    for probe_id in PROBE_IDS:
        assert results[probe_id].outcome is ProbeOutcome.SUPPORTED, probe_id

    discover = results[PROBE_DISCOVER].details
    assert discover["supported_versions"] == ["2025-11-25", "2026-07-28"]
    assert discover["ttl_ms"] == 60000
    assert discover["cache_scope"] == "public"

    stateless = results[PROBE_STATELESS_LIST].details
    assert stateless["result_type"] == "complete"

    unknown = results[PROBE_UNKNOWN_VERSION].details
    assert unknown["supported"] == ["2026-07-28"]
    assert unknown["requested"] == "2099-01-01"
    assert unknown["data_well_formed"] is True

    assert results[PROBE_MISSING_RESOURCE].details["legacy_code_emitted"] is False


async def test_legacy_server_is_unsupported_but_observed():
    results = await _run(_legacy_server_handler)

    for probe_id in (
        PROBE_DISCOVER,
        PROBE_STATELESS_LIST,
        PROBE_MALFORMED_META,
        PROBE_HEADER_MISMATCH,
        PROBE_UNKNOWN_VERSION,
        PROBE_MISSING_RESOURCE,
        PROBE_SESSION_ID_ECHO,
        PROBE_REMOVED_METHOD,
    ):
        assert results[probe_id].outcome is ProbeOutcome.UNSUPPORTED, probe_id

    # The observation probe still succeeds against a legacy server.
    assert results[PROBE_UNAUTHENTICATED].outcome is ProbeOutcome.SUPPORTED
    assert results[PROBE_UNAUTHENTICATED].details["http_status"] == 400

    # The legacy resource-not-found code is recorded for the migration rule.
    assert results[PROBE_MISSING_RESOURCE].details["error_code"] == ERROR_LEGACY_RESOURCE_NOT_FOUND
    assert results[PROBE_MISSING_RESOURCE].details["legacy_code_emitted"] is True

    # No well-known metadata anywhere → UNSUPPORTED, with both locations tried.
    auth = results[PROBE_AUTH_METADATA]
    assert auth.outcome is ProbeOutcome.UNSUPPORTED
    assert len(auth.details["urls_tried"]) == 2


class TestWellKnownUrls:
    def test_path_aware_form_first_then_root(self):
        assert _well_known_urls("https://server.example/mcp") == [
            "https://server.example/.well-known/oauth-protected-resource/mcp",
            "https://server.example/.well-known/oauth-protected-resource",
        ]

    def test_root_resource_has_single_location(self):
        assert _well_known_urls("https://server.example") == [
            "https://server.example/.well-known/oauth-protected-resource",
        ]

    def test_trailing_slash_is_normalized(self):
        assert _well_known_urls("https://server.example/mcp/") == [
            "https://server.example/.well-known/oauth-protected-resource/mcp",
            "https://server.example/.well-known/oauth-protected-resource",
        ]


class TestAuthMetadataProbe:
    async def test_modern_server_serves_path_aware_metadata(self):
        results = await _run(_modern_server_handler)
        auth = results[PROBE_AUTH_METADATA]
        assert auth.outcome is ProbeOutcome.SUPPORTED
        assert auth.details["metadata_url"].endswith("/oauth-protected-resource/mcp")
        assert auth.details["resource"] == URL
        assert auth.details["authorization_servers"] == AUTH_SERVERS
        assert auth.payload == {"resource": URL, "authorization_servers": AUTH_SERVERS}

    async def test_falls_back_to_origin_root_location(self):
        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method == "GET" and request.url.path == "/.well-known/oauth-protected-resource":
                return httpx2.Response(200, json={"resource": URL})
            if request.method == "GET":
                return httpx2.Response(404)
            return _modern_server_handler(request)

        results = await _run(handler)
        auth = results[PROBE_AUTH_METADATA]
        assert auth.outcome is ProbeOutcome.SUPPORTED
        assert auth.details["metadata_url"] == "https://server.example/.well-known/oauth-protected-resource"
        assert auth.details["authorization_servers"] is None

    async def test_walks_to_authorization_server_metadata(self):
        """PRM → first authorization server's RFC 8414 metadata (endpoints + PKCE)."""

        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method != "GET":
                return _modern_server_handler(request)
            path = request.url.path
            if path == "/.well-known/oauth-protected-resource/mcp":
                return httpx2.Response(200, json={"resource": URL, "authorization_servers": ["https://auth.example"]})
            if request.url.host == "auth.example" and path == "/.well-known/oauth-authorization-server":
                return httpx2.Response(
                    200,
                    json={
                        "issuer": "https://auth.example",
                        "authorization_endpoint": "https://auth.example/authorize",
                        "token_endpoint": "https://auth.example/token",
                        "code_challenge_methods_supported": ["S256"],
                    },
                )
            return httpx2.Response(404)

        results = await _run(handler)
        d = results[PROBE_AUTH_METADATA].details
        assert d["auth_server_metadata_present"] is True
        assert d["auth_server_has_endpoints"] is True
        assert d["auth_server_pkce_s256"] is True
        assert d["auth_server_issuer"] == "https://auth.example"

    async def test_authorization_server_without_pkce(self):
        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method != "GET":
                return _modern_server_handler(request)
            path = request.url.path
            if path == "/.well-known/oauth-protected-resource/mcp":
                return httpx2.Response(200, json={"resource": URL, "authorization_servers": ["https://auth.example"]})
            if request.url.host == "auth.example":
                # OIDC fallback path, no PKCE advertised.
                if path == "/.well-known/openid-configuration":
                    return httpx2.Response(
                        200,
                        json={
                            "issuer": "https://auth.example",
                            "authorization_endpoint": "https://auth.example/authorize",
                            "token_endpoint": "https://auth.example/token",
                        },
                    )
                return httpx2.Response(404)
            return httpx2.Response(404)

        results = await _run(handler)
        d = results[PROBE_AUTH_METADATA].details
        assert d["auth_server_metadata_present"] is True  # found via OIDC fallback
        assert d["auth_server_has_endpoints"] is True
        assert d["auth_server_pkce_s256"] is False

    async def test_unreachable_authorization_server_preserves_resource_metadata(self):
        """An unreachable AS is a finding about the AS — it must not void the PRM.

        Regression: the RFC 8414 walk leaves the audited server's origin, so a
        ConnectError there used to propagate out of the probe and discard the
        protected-resource metadata already collected, silently skipping six
        auth rules (and shrinking max_score) for a correctly-configured server.
        """

        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method != "GET":
                return _modern_server_handler(request)
            if request.url.host == "auth.example":
                raise httpx2.ConnectError("name resolution failed")
            if request.url.path == "/.well-known/oauth-protected-resource/mcp":
                return httpx2.Response(
                    200,
                    json={
                        "resource": URL,
                        "authorization_servers": ["https://auth.example"],
                        "scopes_supported": ["read"],
                    },
                )
            return httpx2.Response(404)

        results = await _run(handler)
        auth = results[PROBE_AUTH_METADATA]
        assert auth.outcome is ProbeOutcome.SUPPORTED
        # Everything established before the failing hop survives.
        assert auth.details["resource"] == URL
        assert auth.details["metadata_url"].endswith("/oauth-protected-resource/mcp")
        assert auth.details["scopes_supported"] == ["read"]
        # The unreachable issuer is recorded as data, not as a lost observation.
        assert auth.details["auth_server_issuer"] == "https://auth.example"
        assert auth.details["auth_server_metadata_present"] is False
        assert auth.details["auth_server_metadata_error"] == "ConnectError"

    async def test_authorization_server_timeout_is_recorded_not_raised(self):
        """A merely slow authorization server degrades the same way as an absent one."""

        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method != "GET":
                return _modern_server_handler(request)
            if request.url.host == "auth.example":
                raise httpx2.ReadTimeout("too slow")
            if request.url.path == "/.well-known/oauth-protected-resource/mcp":
                return httpx2.Response(200, json={"resource": URL, "authorization_servers": ["https://auth.example"]})
            return httpx2.Response(404)

        results = await _run(handler)
        auth = results[PROBE_AUTH_METADATA]
        assert auth.outcome is ProbeOutcome.SUPPORTED
        assert auth.details["auth_server_metadata_present"] is False
        assert auth.details["auth_server_metadata_error"] == "ReadTimeout"

    async def test_reachable_issuer_publishing_nothing_records_no_transport_error(self):
        """A 404 from the second AS location must clear the first one's transport error.

        ``auth_server_metadata_error`` means "the issuer could not be contacted
        at all". An issuer that answers one location — even with a 404 — is
        reachable and simply publishes no usable document there; reporting a
        stale transport error would misattribute that to an unreachable host.
        """

        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method != "GET":
                return _modern_server_handler(request)
            path = request.url.path
            if request.url.host == "auth.example":
                if path == "/.well-known/oauth-authorization-server":
                    raise httpx2.ConnectError("refused")
                return httpx2.Response(404)  # reachable, just nothing published
            if path == "/.well-known/oauth-protected-resource/mcp":
                return httpx2.Response(200, json={"resource": URL, "authorization_servers": ["https://auth.example"]})
            return httpx2.Response(404)

        results = await _run(handler)
        d = results[PROBE_AUTH_METADATA].details
        assert d["auth_server_metadata_present"] is False
        assert "auth_server_metadata_error" not in d

    async def test_oidc_fallback_recovers_after_first_candidate_transport_error(self):
        """A transport error on the RFC 8414 URL still lets the OIDC location answer."""

        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method != "GET":
                return _modern_server_handler(request)
            path = request.url.path
            if request.url.host == "auth.example":
                if path == "/.well-known/oauth-authorization-server":
                    raise httpx2.ConnectError("refused")
                return httpx2.Response(
                    200,
                    json={
                        "issuer": "https://auth.example",
                        "authorization_endpoint": "https://auth.example/authorize",
                        "token_endpoint": "https://auth.example/token",
                        "code_challenge_methods_supported": ["S256"],
                    },
                )
            if path == "/.well-known/oauth-protected-resource/mcp":
                return httpx2.Response(200, json={"resource": URL, "authorization_servers": ["https://auth.example"]})
            return httpx2.Response(404)

        results = await _run(handler)
        d = results[PROBE_AUTH_METADATA].details
        assert d["auth_server_metadata_present"] is True
        assert d["auth_server_pkce_s256"] is True
        # A recovered candidate leaves no stale error behind.
        assert "auth_server_metadata_error" not in d

    async def test_well_known_transport_error_falls_through_to_origin_root(self):
        """A transport error on the path-aware PRM location must not abort discovery."""

        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method != "GET":
                return _modern_server_handler(request)
            if request.url.path == "/.well-known/oauth-protected-resource/mcp":
                raise httpx2.ConnectError("refused")
            if request.url.path == "/.well-known/oauth-protected-resource":
                return httpx2.Response(200, json={"resource": URL})
            return httpx2.Response(404)

        results = await _run(handler)
        auth = results[PROBE_AUTH_METADATA]
        assert auth.outcome is ProbeOutcome.SUPPORTED
        assert auth.details["metadata_url"] == "https://server.example/.well-known/oauth-protected-resource"

    async def test_all_well_known_locations_unreachable_stays_error(self):
        """Unreachable ≠ "publishes no metadata" — the rules must skip, not fail.

        Only the well-known fetches fail here, so the probe cannot claim the
        server lacks a PRM document; ERROR keeps the dependent rules on
        insufficient-data rather than scoring the server down for something
        that was never observed.
        """

        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method == "GET":
                raise httpx2.ConnectError("refused")
            return _modern_server_handler(request)

        results = await _run(handler)
        auth = results[PROBE_AUTH_METADATA]
        assert auth.outcome is ProbeOutcome.ERROR
        assert auth.details["exception"] == "ConnectError"
        # An ERROR outcome is the case that most needs diagnostic context, so
        # the details established before the failure must survive it.
        assert auth.details["urls_tried"] == _well_known_urls(URL)
        assert auth.details["unreachable_locations"] == _well_known_urls(URL)

    async def test_partially_unreachable_locations_are_recorded(self):
        """A firewalled location must stay distinguishable from one that answered 404.

        The mixed case: one well-known location cannot be contacted, another
        answers but carries no metadata. The outcome is UNSUPPORTED either way,
        but silently dropping the transport error makes an unreachable location
        look identical to an absent document.
        """

        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method != "GET":
                return _modern_server_handler(request)
            if request.url.path == "/.well-known/oauth-protected-resource/mcp":
                raise httpx2.ConnectError("refused")
            return httpx2.Response(404)

        results = await _run(handler)
        auth = results[PROBE_AUTH_METADATA]
        assert auth.outcome is ProbeOutcome.UNSUPPORTED
        assert auth.details["http_status"] == 404
        assert auth.details["unreachable_locations"] == [
            "https://server.example/.well-known/oauth-protected-resource/mcp"
        ]

    async def test_reachable_locations_record_no_unreachable_list(self):
        """The diagnostic key is absent entirely when every location answered."""
        results = await _run(_modern_server_handler)
        assert "unreachable_locations" not in results[PROBE_AUTH_METADATA].details

    @pytest.mark.parametrize(
        "issuer",
        [
            "https://256.256.256.256",  # invalid IPv4 literal
            "https://999.999.999.999",
            "https://::1",  # bare IPv6, unbracketed
            "http://[::1",  # unterminated bracket
        ],
    )
    async def test_unusable_issuer_url_is_a_finding_not_an_exception(self, issuer: str):
        """A syntactically plausible but unusable issuer must not void the audit.

        ``authorization_servers`` is server-controlled and only prefix-checked,
        so these values raise httpx2.InvalidURL — which does NOT derive from
        HTTPError. Letting it escape would hand a server a way to skip the six
        auth rules out of its own max_score by advertising a malformed issuer.

        Hermetic: URL parsing fails before any connection is attempted, so the
        real client here never touches the network.
        """
        details: dict[str, object] = {}
        async with httpx2.AsyncClient(follow_redirects=True) as client:
            await _fetch_auth_server_metadata(client, issuer, details)
        assert details["auth_server_issuer"] == issuer
        assert details["auth_server_metadata_present"] is False
        assert details["auth_server_metadata_error"] == "InvalidURL"

    async def test_invalid_json_is_unsupported(self):
        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method == "GET":
                return httpx2.Response(200, text="<html>not metadata</html>")
            return _modern_server_handler(request)

        results = await _run(handler)
        assert results[PROBE_AUTH_METADATA].outcome is ProbeOutcome.UNSUPPORTED

    async def test_metadata_without_resource_field_is_unsupported(self):
        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method == "GET":
                return httpx2.Response(200, json={"authorization_servers": AUTH_SERVERS})
            return _modern_server_handler(request)

        results = await _run(handler)
        assert results[PROBE_AUTH_METADATA].outcome is ProbeOutcome.UNSUPPORTED


async def test_network_failure_yields_error_outcomes_not_exceptions():
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("connection refused")

    results = await _run(handler)

    for probe_id in PROBE_IDS:
        assert results[probe_id].outcome is ProbeOutcome.ERROR, probe_id
        assert results[probe_id].details["exception"] == "ConnectError"


async def test_non_mcp_endpoint_is_unsupported():
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, text="<html>not an MCP server</html>")

    results = await _run(handler)

    assert results[PROBE_DISCOVER].outcome is ProbeOutcome.UNSUPPORTED
    assert results[PROBE_STATELESS_LIST].outcome is ProbeOutcome.UNSUPPORTED


async def test_sse_response_body_is_parsed():
    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        if body["method"] != "server/discover" or request.headers.get("Mcp-Method") != "server/discover":
            return httpx2.Response(
                400, json={"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32600, "message": "bad"}}
            )
        message = {
            "jsonrpc": "2.0",
            "id": body["id"],
            "result": {
                "resultType": "complete",
                "supportedVersions": ["2026-07-28"],
                "ttlMs": 0,
                "cacheScope": "private",
            },
        }
        return httpx2.Response(
            200,
            headers={"content-type": "text/event-stream"},
            text=f"event: message\ndata: {json.dumps(message)}\n\n",
        )

    results = await _run(handler)

    assert results[PROBE_DISCOVER].outcome is ProbeOutcome.SUPPORTED
    assert results[PROBE_DISCOVER].details["supported_versions"] == ["2026-07-28"]
    assert results[PROBE_DISCOVER].details["cache_scope"] == "private"


async def test_unauthenticated_probe_records_challenge():
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            401,
            headers={
                "WWW-Authenticate": 'Bearer resource_metadata="https://server.example/.well-known/oauth-protected-resource"'
            },
            json={"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "unauthorized"}},
        )

    results = await _run(handler)

    unauth = results[PROBE_UNAUTHENTICATED]
    assert unauth.outcome is ProbeOutcome.SUPPORTED
    assert unauth.details["http_status"] == 401
    assert "resource_metadata" in unauth.details["www_authenticate"]


def test_not_applicable_results_cover_all_probes():
    results = not_applicable_results(reason="stdio transport")

    assert set(results) == set(PROBE_IDS)
    for probe_id, result in results.items():
        assert result.probe_id == probe_id
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE
        assert result.details == {"reason": "stdio transport"}


def test_probe_result_to_dict():
    result = ProbeResult(PROBE_DISCOVER, ProbeOutcome.SUPPORTED, {"http_status": 200})
    assert result.to_dict() == {
        "probe_id": PROBE_DISCOVER,
        "outcome": "supported",
        "details": {"http_status": 200},
    }


async def test_auditor_records_not_applicable_probes_for_stdio(monkeypatch):
    from mcpscore.mcp_auditor import MCPAuditor

    auditor = MCPAuditor()
    auditor.audit_data.url = None

    await auditor._collect_probes()

    assert auditor.audit_data.probes is not None
    assert set(auditor.audit_data.probes) == set(PROBE_IDS)
    for result in auditor.audit_data.probes.values():
        assert result.outcome is ProbeOutcome.NOT_APPLICABLE


async def test_auditor_runs_probes_for_http_url(monkeypatch):
    from mcpscore import mcp_auditor
    from mcpscore.mcp_auditor import MCPAuditor

    seen: dict = {}

    async def fake_run_all_probes(url: str, client=None, headers=None):
        seen["url"] = url
        return {PROBE_DISCOVER: ProbeResult(PROBE_DISCOVER, ProbeOutcome.SUPPORTED, {})}

    monkeypatch.setattr(mcp_auditor, "run_all_probes", fake_run_all_probes)
    auditor = MCPAuditor()
    auditor.audit_data.url = URL

    await auditor._collect_probes()

    assert seen["url"] == URL
    assert auditor.audit_data.probes is not None
    assert auditor.audit_data.probes[PROBE_DISCOVER].outcome is ProbeOutcome.SUPPORTED


async def test_leaky_modern_server_is_detected():
    """A server speaking the modern lifecycle but leaking legacy artifacts."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        request_id = body.get("id")
        method = body["method"]
        if method == "ping":  # removed method, still served
            return _rpc_result(request_id, {})
        if method == "tools/list":
            response = _rpc_result(
                request_id, {"resultType": "complete", "tools": [], "ttlMs": 0, "cacheScope": "public"}
            )
            response.headers["Mcp-Session-Id"] = "leaked-session"  # minted session id
            return response
        if method == "server/discover":
            return _rpc_result(
                request_id,
                {"resultType": "complete", "supportedVersions": ["2026-07-28"], "ttlMs": 0, "cacheScope": "public"},
            )
        return _rpc_error(request_id, -32601, "Method not found", http_status=404)

    results = await _run(handler)

    assert results[PROBE_DISCOVER].outcome is ProbeOutcome.SUPPORTED
    session = results[PROBE_SESSION_ID_ECHO]
    assert session.outcome is ProbeOutcome.UNSUPPORTED
    assert session.details["response_session_id"] == "leaked-session"
    removed = results[PROBE_REMOVED_METHOD]
    assert removed.outcome is ProbeOutcome.UNSUPPORTED
    assert removed.details["method_served"] is True


async def test_probe_payloads_are_captured_for_data_extraction():
    results = await _run(_modern_server_handler)

    discover_payload = results[PROBE_DISCOVER].payload
    assert discover_payload is not None
    # The extractor reads the spec location; assert the shape it consumes.
    assert discover_payload["_meta"]["io.modelcontextprotocol/serverInfo"] == {
        "name": "modern",
        "version": "1.0",
    }
    stateless_payload = results[PROBE_STATELESS_LIST].payload
    assert stateless_payload is not None
    assert stateless_payload["tools"] == []
    # Payloads never leak into report serialization.
    assert "payload" not in results[PROBE_DISCOVER].to_dict()


async def test_sse_response_without_data_line_is_unsupported():
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, headers={"content-type": "text/event-stream"}, text="event: ping\n\n")

    results = await _run(handler)
    assert results[PROBE_DISCOVER].outcome is ProbeOutcome.UNSUPPORTED


async def test_error_without_message_field_is_handled():
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(400, json={"jsonrpc": "2.0", "id": 1, "error": {"code": -32600}})

    results = await _run(handler)
    details = results[PROBE_DISCOVER].details
    assert details["error_code"] == -32600
    assert "error_message" not in details


def _unknown_version_handler(data: object) -> object:
    """Build a handler answering every request with -32022 carrying the given error data.

    ``data`` is spliced into the error verbatim; the sentinel ``_OMIT`` leaves
    the data member out entirely (a bare -32022).
    """

    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        error: dict = {"code": ERROR_UNSUPPORTED_PROTOCOL_VERSION, "message": "nope"}
        if data is not _OMIT:
            error["data"] = data
        return httpx2.Response(400, json={"jsonrpc": "2.0", "id": body.get("id"), "error": error})

    return handler


_OMIT = object()


async def test_unknown_version_error_with_non_dict_data():
    # The error code alone is not enough (schema requires data.supported +
    # data.requested); before the tightening this outcome was SUPPORTED.
    results = await _run(_unknown_version_handler("not-a-dict"))
    unknown = results[PROBE_UNKNOWN_VERSION]
    assert unknown.outcome is ProbeOutcome.UNSUPPORTED
    assert unknown.details["supported"] is None
    assert unknown.details["data_well_formed"] is False


async def test_unknown_version_error_without_data():
    results = await _run(_unknown_version_handler(_OMIT))
    unknown = results[PROBE_UNKNOWN_VERSION]
    assert unknown.outcome is ProbeOutcome.UNSUPPORTED
    assert unknown.details["data_well_formed"] is False


async def test_unknown_version_error_with_empty_supported_list():
    results = await _run(_unknown_version_handler({"supported": [], "requested": "2099-01-01"}))
    unknown = results[PROBE_UNKNOWN_VERSION]
    assert unknown.outcome is ProbeOutcome.UNSUPPORTED
    assert unknown.details["data_well_formed"] is False


async def test_unknown_version_error_without_requested_echo():
    results = await _run(_unknown_version_handler({"supported": ["2026-07-28"]}))
    unknown = results[PROBE_UNKNOWN_VERSION]
    assert unknown.outcome is ProbeOutcome.UNSUPPORTED
    assert unknown.details["supported"] == ["2026-07-28"]
    assert unknown.details["data_well_formed"] is False


async def test_run_all_probes_creates_its_own_client_when_none_given(monkeypatch):
    from mcpscore import probes as probes_module

    def make_stub(probe_id: str):
        async def stub(client: httpx2.AsyncClient, url: str) -> ProbeResult:
            return ProbeResult(probe_id, ProbeOutcome.SUPPORTED, {"stubbed": True})

        return stub

    monkeypatch.setattr(probes_module, "_PROBES", {pid: make_stub(pid) for pid in PROBE_IDS})

    results = await run_all_probes(URL)  # no client injected -> own-client branch

    assert set(results) == set(PROBE_IDS)


class TestAnonymousProbes:
    """The unauthenticated and metadata probes must not send a caller's bearer."""

    async def test_own_client_path_keeps_all_caller_headers_off_anonymous_probes(self, monkeypatch):
        """Anonymous probes run on a client with no caller headers at all.

        --header can carry non-Authorization credentials (API keys, cookies);
        they must not reach the unauthenticated probe or the auth-discovery
        fetches — the latter can leave the server's origin entirely.
        """
        requests_log: list[httpx2.Request] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            requests_log.append(request)
            if request.url.path.startswith("/.well-known/"):
                return httpx2.Response(200, json={"resource": URL, "authorization_servers": ["https://as.example"]})
            return httpx2.Response(401, headers={"WWW-Authenticate": "Bearer"}, json={})

        transport = httpx2.MockTransport(handler)
        real_async_client = httpx2.AsyncClient

        def patched_client(**kwargs):
            kwargs.setdefault("transport", transport)
            return real_async_client(**kwargs)

        monkeypatch.setattr(httpx2, "AsyncClient", patched_client)

        await run_all_probes(URL, headers={"X-Api-Key": "sekret", "Authorization": "Bearer tok"})

        wellknown = [r for r in requests_log if r.url.path.startswith("/.well-known/")]
        assert wellknown, "auth-metadata discovery should have run"
        for request in wellknown:
            assert "X-Api-Key" not in request.headers
            assert "Authorization" not in request.headers
        # The unauthenticated probe's request reached the server with neither header.
        assert any(
            r.url.path == "/mcp" and "X-Api-Key" not in r.headers and "Authorization" not in r.headers
            for r in requests_log
        )
        # Authenticated probes still carry the caller's headers.
        assert any(r.headers.get("X-Api-Key") == "sekret" for r in requests_log)

    async def test_unauthenticated_probe_strips_authorization(self):
        from mcpscore.probes import _probe_unauthenticated

        seen_auth: dict[str, str | None] = {}

        def handler(request: httpx2.Request) -> httpx2.Response:
            seen_auth["post"] = request.headers.get("Authorization")
            return httpx2.Response(401, headers={"WWW-Authenticate": "Bearer"}, json={})

        # Client carries a default bearer, as if --token was passed.
        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler), headers={"Authorization": "Bearer secret"}
        ) as client:
            result = await _probe_unauthenticated(client, URL)

        # The probe reached the server without the bearer, so it saw the 401 challenge.
        assert seen_auth["post"] is None
        assert result.details["http_status"] == 401
        assert result.details["www_authenticate"] == "Bearer"

    async def test_unauthenticated_probe_survives_oauth_error_body(self):
        """An RFC 6750 401 body must not crash the probe.

        Its ``error`` field is a string (``"invalid_token"``), not a JSON-RPC
        error object.
        """
        from mcpscore.probes import _probe_unauthenticated

        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(
                401,
                headers={"WWW-Authenticate": "Bearer"},
                json={"error": "invalid_token", "error_description": "Authentication required"},
            )

        async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
            result = await _probe_unauthenticated(client, URL)

        assert result.outcome is ProbeOutcome.SUPPORTED
        assert result.details["http_status"] == 401
        assert result.details["www_authenticate"] == "Bearer"
        # The string "error" is not a JSON-RPC error object, so no error_code.
        assert "error_code" not in result.details

    async def test_auth_metadata_probe_strips_authorization(self):
        seen_auth: dict[str, str | None] = {}

        def handler(request: httpx2.Request) -> httpx2.Response:
            if request.method == "GET":
                seen_auth["get"] = request.headers.get("Authorization")
                return httpx2.Response(200, json={"resource": URL})
            return httpx2.Response(401)

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler), headers={"Authorization": "Bearer secret"}
        ) as client:
            results = await run_all_probes(URL, client=client)

        assert seen_auth["get"] is None
        assert results[PROBE_AUTH_METADATA].outcome is ProbeOutcome.SUPPORTED
