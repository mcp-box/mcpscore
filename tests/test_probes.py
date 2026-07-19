"""Tests for the sessionless HTTP probe layer."""

import json

import httpx2

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
                "serverInfo": {"name": "modern", "version": "1.0"},
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

    async def fake_run_all_probes(url: str, client=None):
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
    assert discover_payload["serverInfo"] == {"name": "modern", "version": "1.0"}
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


async def test_unknown_version_error_with_non_dict_data():
    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        return httpx2.Response(
            400,
            json={
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {"code": ERROR_UNSUPPORTED_PROTOCOL_VERSION, "message": "nope", "data": "not-a-dict"},
            },
        )

    results = await _run(handler)
    unknown = results[PROBE_UNKNOWN_VERSION]
    assert unknown.outcome is ProbeOutcome.SUPPORTED
    assert "supported" not in unknown.details


async def test_run_all_probes_creates_its_own_client_when_none_given(monkeypatch):
    from mcpscore import probes as probes_module

    def make_stub(probe_id: str):
        async def stub(client: httpx2.AsyncClient, url: str) -> ProbeResult:
            return ProbeResult(probe_id, ProbeOutcome.SUPPORTED, {"stubbed": True})

        return stub

    monkeypatch.setattr(probes_module, "_PROBES", {pid: make_stub(pid) for pid in PROBE_IDS})

    results = await run_all_probes(URL)  # no client injected -> own-client branch

    assert set(results) == set(PROBE_IDS)
