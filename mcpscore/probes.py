"""Sessionless HTTP probes for spec behaviors outside the negotiated session.

The SDK session in `mcp_client` speaks one negotiated protocol version; it
cannot observe what *else* a server supports (e.g. "does this stateful
2025-11-25 server also answer a stateless 2026-07-28 request?"). Probes fill
that gap: each one issues raw JSON-RPC-over-HTTP requests (no SDK session)
and records an observation for rules to consume via ``AuditData.probes``.

Probe outcomes are data, never errors: a server rejecting a probe is exactly
as informative as one accepting it. Network failures become
``ProbeOutcome.ERROR`` so dependent rules can degrade to "could not verify"
instead of failing the server.

Probes target the newest draft spec revision from the registry
(:data:`mcpscore.spec.DRAFT`), falling back to the latest final revision.
All probes are HTTP-only: for stdio servers the auditor records
``NOT_APPLICABLE`` results instead of running them.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import StrEnum
from importlib.metadata import PackageNotFoundError, version as package_version
import json
import logging
from typing import Any
from urllib.parse import urlsplit

import httpx2

from mcpscore.spec import DRAFT, LATEST, Era

logger = logging.getLogger(__name__)

__all__ = [
    "GATEWAY_PROBE_IDS",
    "PROBE_IDS",
    "ProbeOutcome",
    "ProbeResult",
    "detect_era",
    "has_modern_support",
    "run_all_probes",
]

PROBE_TIMEOUT_S = 10.0
"""Per-request timeout for a single probe."""

META_PREFIX = "io.modelcontextprotocol/"
"""Prefix of the reserved ``_meta`` keys carrying per-request context (2026-07-28)."""

AUTH_GATED_STATUSES = frozenset({401, 403})
"""HTTP statuses that mark an access-controlled server whose auth posture the
auth-posture rules examine. Kept in sync with the CLI's partial-audit trigger
(ConnectionErrorReason.UNAUTHORIZED / FORBIDDEN)."""

ERROR_HEADER_MISMATCH = -32020
"""JSON-RPC error code for HTTP header/body mismatches (2026-07-28)."""

ERROR_INVALID_PARAMS = -32602
"""Standard JSON-RPC Invalid params — also the 2026-07-28 missing-resource code."""

ERROR_UNSUPPORTED_PROTOCOL_VERSION = -32022
"""JSON-RPC error code for an unsupported protocol version (2026-07-28)."""

ERROR_LEGACY_RESOURCE_NOT_FOUND = -32002
"""Legacy resource-not-found code (2025-11-25 and earlier); MUST NOT be emitted from 2026-07-28."""

ERROR_METHOD_NOT_FOUND = -32601
"""Standard JSON-RPC Method not found — required (with HTTP 404) for unknown/removed methods."""

SESSION_ID_PROBE_VALUE = "mcpscore-spurious-session-id"
"""Deliberately bogus session ID sent by the session-id-echo probe; modern servers
must ignore it ("ignore it, and do not mint or echo session IDs")."""

REMOVED_METHOD = "ping"
"""A method removed in 2026-07-28, used to probe for leaked legacy surface."""

UNKNOWN_VERSION = "2099-01-01"
"""Deliberately unsupported version used by the unknown-version probe."""

MISSING_RESOURCE_URI = "resource://mcpscore/does-not-exist"
"""Deliberately nonexistent resource URI used by the missing-resource probe."""

PROBE_DISCOVER = "probe_discover"
PROBE_STATELESS_LIST = "probe_stateless_list"
PROBE_MALFORMED_META = "probe_malformed_meta"
PROBE_HEADER_MISMATCH = "probe_header_mismatch"
PROBE_UNKNOWN_VERSION = "probe_unknown_version"
PROBE_MISSING_RESOURCE = "probe_missing_resource"
PROBE_UNAUTHENTICATED = "probe_unauthenticated"
PROBE_SESSION_ID_ECHO = "probe_session_id_echo"
PROBE_REMOVED_METHOD = "probe_removed_method"
PROBE_AUTH_METADATA = "probe_auth_metadata"

PROBE_IDS: tuple[str, ...] = (
    PROBE_DISCOVER,
    PROBE_STATELESS_LIST,
    PROBE_MALFORMED_META,
    PROBE_HEADER_MISMATCH,
    PROBE_UNKNOWN_VERSION,
    PROBE_MISSING_RESOURCE,
    PROBE_UNAUTHENTICATED,
    PROBE_SESSION_ID_ECHO,
    PROBE_REMOVED_METHOD,
    PROBE_AUTH_METADATA,
)
"""Stable identifiers of all probes."""


class ProbeOutcome(StrEnum):
    """Classification of a probe observation."""

    SUPPORTED = "supported"
    """The server exhibited the probed (modern-correct) behavior."""

    UNSUPPORTED = "unsupported"
    """The server responded, but without the probed behavior."""

    ERROR = "error"
    """The observation could not be made (network failure, timeout).
    Dependent rules degrade to "could not verify" instead of failing."""

    NOT_APPLICABLE = "not_applicable"
    """The probe does not apply to this server (e.g. stdio transport)."""


@dataclass(frozen=True)
class ProbeResult:
    """Recorded observation of one probe."""

    probe_id: str
    """Stable identifier of the probe that produced this result."""

    outcome: ProbeOutcome

    details: dict[str, Any] = field(default_factory=dict)
    """Raw observations (HTTP status, JSON-RPC error codes, result fields)
    for rules to inspect and cite in their messages."""

    payload: dict[str, Any] | None = None
    """Full result payload (e.g. the DiscoverResult, a tools list) for data
    extraction by the modern-only audit path. Deliberately excluded from
    to_dict — payloads can be large and belong in AuditData, not reports."""

    def to_dict(self) -> dict:
        """Serialize this result for machine-readable reports."""
        return {"probe_id": self.probe_id, "outcome": self.outcome.value, "details": self.details}


@dataclass(frozen=True)
class _ProbeResponse:
    """Parsed HTTP response to a probe request."""

    status_code: int
    headers: dict[str, str]
    payload: dict[str, Any] | None
    """The JSON-RPC message, parsed from a JSON body or the first SSE data
    event; None when the body is neither."""

    @property
    def error(self) -> dict[str, Any] | None:
        return self.payload.get("error") if isinstance(self.payload, dict) else None

    @property
    def error_code(self) -> int | None:
        error = self.error
        code = error.get("code") if error else None
        return code if isinstance(code, int) else None

    @property
    def result(self) -> dict[str, Any] | None:
        result = self.payload.get("result") if isinstance(self.payload, dict) else None
        return result if isinstance(result, dict) else None


def _client_version() -> str:
    try:
        return package_version("mcpscore")
    except PackageNotFoundError:  # pragma: no cover - installed in all real environments
        return "0.0.0"


def _target_version() -> str:
    """Spec version the probes speak: the draft if one exists, else the latest final."""
    return (DRAFT or LATEST).version


def _modern_meta(protocol_version: str) -> dict[str, Any]:
    """Build the three required per-request ``_meta`` fields of the stateless lifecycle."""
    return {
        f"{META_PREFIX}protocolVersion": protocol_version,
        f"{META_PREFIX}clientInfo": {"name": "mcpscore", "version": _client_version()},
        f"{META_PREFIX}clientCapabilities": {},
    }


def _request_body(method: str, request_id: int, meta: dict[str, Any], params: dict[str, Any] | None = None) -> dict:
    body_params: dict[str, Any] = dict(params or {})
    body_params["_meta"] = meta
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": body_params}


def _request_headers(protocol_version: str, method: str, name: str | None = None) -> dict[str, str]:
    """Build the standard headers of a modern Streamable HTTP POST (SEP-2243)."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": protocol_version,
        "Mcp-Method": method,
    }
    if name is not None:
        headers["Mcp-Name"] = name
    return headers


def _parse_payload(response: httpx2.Response) -> dict[str, Any] | None:
    """Extract the JSON-RPC message from a JSON or SSE response body."""
    content_type = response.headers.get("content-type", "")
    try:
        if "text/event-stream" in content_type:
            for line in response.text.splitlines():
                if line.startswith("data:"):
                    parsed = json.loads(line[len("data:") :].strip())
                    return parsed if isinstance(parsed, dict) else None
            return None
        parsed = response.json()
    except (json.JSONDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


async def _post(
    client: httpx2.AsyncClient,
    url: str,
    body: dict,
    headers: dict[str, str],
    *,
    anonymous: bool = False,
) -> _ProbeResponse:
    """POST a probe request, optionally stripping the caller's Authorization.

    When ``anonymous``, remove any caller-supplied ``Authorization`` header so
    the probe observes the server's unauthenticated behavior even when a token
    was provided via --token/--header.
    """
    request = client.build_request("POST", url, json=body, headers=headers, timeout=PROBE_TIMEOUT_S)
    if anonymous:
        request.headers.pop("Authorization", None)
    response = await client.send(request)
    return _ProbeResponse(
        status_code=response.status_code,
        headers=dict(response.headers),
        payload=_parse_payload(response),
    )


def _base_details(response: _ProbeResponse) -> dict[str, Any]:
    details: dict[str, Any] = {"http_status": response.status_code}
    if response.error is not None:
        details["error_code"] = response.error_code
        message = response.error.get("message")
        if isinstance(message, str):
            details["error_message"] = message
    return details


async def _probe_discover(client: httpx2.AsyncClient, url: str) -> ProbeResult:
    """``server/discover`` — mandatory for modern servers (SEP-2567).

    SUPPORTED when the server returns a DiscoverResult carrying
    ``supportedVersions``; the details also record the caching hints so the
    cache-metadata rule can check them.
    """
    target = _target_version()
    response = await _post(
        client,
        url,
        _request_body("server/discover", 1, _modern_meta(target)),
        _request_headers(target, "server/discover"),
    )
    details = _base_details(response)
    result = response.result
    if result is not None and isinstance(result.get("supportedVersions"), list):
        details["supported_versions"] = result["supportedVersions"]
        details["ttl_ms"] = result.get("ttlMs")
        details["cache_scope"] = result.get("cacheScope")
        details["result_type"] = result.get("resultType")
        return ProbeResult(PROBE_DISCOVER, ProbeOutcome.SUPPORTED, details, payload=result)
    return ProbeResult(PROBE_DISCOVER, ProbeOutcome.UNSUPPORTED, details)


async def _probe_stateless_list(client: httpx2.AsyncClient, url: str) -> ProbeResult:
    """Modern ``tools/list`` with required ``_meta``, no prior ``initialize`` (SEP-2575).

    SUPPORTED when the server returns a tools result; details record
    ``resultType`` and the caching hints for the dependent rules.
    """
    target = _target_version()
    response = await _post(
        client,
        url,
        _request_body("tools/list", 2, _modern_meta(target)),
        _request_headers(target, "tools/list"),
    )
    details = _base_details(response)
    result = response.result
    if result is not None and isinstance(result.get("tools"), list):
        details["result_type"] = result.get("resultType")
        details["ttl_ms"] = result.get("ttlMs")
        details["cache_scope"] = result.get("cacheScope")
        return ProbeResult(PROBE_STATELESS_LIST, ProbeOutcome.SUPPORTED, details, payload=result)
    return ProbeResult(PROBE_STATELESS_LIST, ProbeOutcome.UNSUPPORTED, details)


async def _probe_malformed_meta(client: httpx2.AsyncClient, url: str) -> ProbeResult:
    """Send a modern request missing a required ``_meta`` field.

    The spec: a request missing any required field MUST be rejected with
    JSON-RPC ``-32602`` and HTTP 400. SUPPORTED when the server does exactly
    that; anything else (including happily serving the request) is UNSUPPORTED.
    """
    target = _target_version()
    meta = _modern_meta(target)
    del meta[f"{META_PREFIX}clientCapabilities"]
    response = await _post(
        client,
        url,
        _request_body("tools/list", 3, meta),
        _request_headers(target, "tools/list"),
    )
    details = _base_details(response)
    correct = response.status_code == 400 and response.error_code == ERROR_INVALID_PARAMS
    outcome = ProbeOutcome.SUPPORTED if correct else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_MALFORMED_META, outcome, details)


async def _probe_header_mismatch(client: httpx2.AsyncClient, url: str) -> ProbeResult:
    """Send a request whose ``Mcp-Method`` header contradicts the body method (SEP-2243).

    Servers MUST reject header/body mismatches with HTTP 400 and JSON-RPC
    ``-32020`` (HeaderMismatch). Uses ``tools/list`` in the body (never
    ``tools/call`` — probes must not risk invoking real tools).
    """
    target = _target_version()
    headers = _request_headers(target, "prompts/list")  # deliberately != body method
    response = await _post(
        client,
        url,
        _request_body("tools/list", 4, _modern_meta(target)),
        headers,
    )
    details = _base_details(response)
    correct = response.status_code == 400 and response.error_code == ERROR_HEADER_MISMATCH
    outcome = ProbeOutcome.SUPPORTED if correct else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_HEADER_MISMATCH, outcome, details)


async def _probe_unknown_version(client: httpx2.AsyncClient, url: str) -> ProbeResult:
    """Send a modern request naming a fabricated protocol version.

    Modern servers MUST reject it with ``-32022`` (UnsupportedProtocolVersion)
    whose ``data`` lists ``supported`` and ``requested`` versions.
    """
    response = await _post(
        client,
        url,
        _request_body("tools/list", 5, _modern_meta(UNKNOWN_VERSION)),
        _request_headers(UNKNOWN_VERSION, "tools/list"),
    )
    details = _base_details(response)
    error = response.error
    if error is not None and response.error_code == ERROR_UNSUPPORTED_PROTOCOL_VERSION:
        data = error.get("data")
        if isinstance(data, dict):
            details["supported"] = data.get("supported")
            details["requested"] = data.get("requested")
        return ProbeResult(PROBE_UNKNOWN_VERSION, ProbeOutcome.SUPPORTED, details)
    return ProbeResult(PROBE_UNKNOWN_VERSION, ProbeOutcome.UNSUPPORTED, details)


async def _probe_missing_resource(client: httpx2.AsyncClient, url: str) -> ProbeResult:
    """``resources/read`` for a deliberately nonexistent URI (SEP-2164).

    From 2026-07-28 the missing-resource error is standard ``-32602``; the
    legacy ``-32002`` MUST NOT be emitted. SUPPORTED when the modern code is
    observed; the raw code is always recorded (the error-code-migration rule
    also flags undefined codes in the reserved -32020..-32099 range).
    """
    target = _target_version()
    response = await _post(
        client,
        url,
        _request_body("resources/read", 6, _modern_meta(target), params={"uri": MISSING_RESOURCE_URI}),
        _request_headers(target, "resources/read", name=MISSING_RESOURCE_URI),
    )
    details = _base_details(response)
    details["legacy_code_emitted"] = response.error_code == ERROR_LEGACY_RESOURCE_NOT_FOUND
    outcome = ProbeOutcome.SUPPORTED if response.error_code == ERROR_INVALID_PARAMS else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_MISSING_RESOURCE, outcome, details)


async def _probe_unauthenticated(client: httpx2.AsyncClient, url: str) -> ProbeResult:
    """One unauthenticated request, recording status and ``WWW-Authenticate``.

    This is a pure observation probe (it feeds the auth-posture rules):
    SUPPORTED means "an HTTP response was observed", whatever its status —
    the details carry the status code and any authentication challenge.
    """
    target = _target_version()
    response = await _post(
        client,
        url,
        _request_body("tools/list", 7, _modern_meta(target)),
        _request_headers(target, "tools/list"),
        anonymous=True,
    )
    details = _base_details(response)
    details["www_authenticate"] = response.headers.get("www-authenticate")
    return ProbeResult(PROBE_UNAUTHENTICATED, ProbeOutcome.SUPPORTED, details)


def _well_known_urls(url: str) -> list[str]:
    """RFC 9728 §3 well-known locations for a protected resource URL.

    For a resource with a path component the path-aware form (path appended
    after the well-known prefix) is tried first, then the origin-root form.
    """
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    path = parts.path.rstrip("/")
    candidates = []
    if path:
        candidates.append(f"{origin}/.well-known/oauth-protected-resource{path}")
    candidates.append(f"{origin}/.well-known/oauth-protected-resource")
    return candidates


async def _probe_auth_metadata(client: httpx2.AsyncClient, url: str) -> ProbeResult:
    """Fetch RFC 9728 protected resource metadata from its well-known locations.

    Observation probe feeding the auth-posture rules: SUPPORTED when a
    well-known location returns HTTP 200 with a JSON object carrying the
    REQUIRED ``resource`` field (RFC 9728 §2); details record what was found
    where. Servers without authentication commonly 404 here — the dependent
    rules skip unless the endpoint demanded auth in the first place.
    """
    details: dict[str, Any] = {"urls_tried": []}
    for candidate in _well_known_urls(url):
        details["urls_tried"].append(candidate)
        # The protected-resource metadata is a public well-known document;
        # fetch it without any caller-supplied Authorization header.
        request = client.build_request(
            "GET", candidate, headers={"Accept": "application/json"}, timeout=PROBE_TIMEOUT_S
        )
        request.headers.pop("Authorization", None)
        response = await client.send(request)
        details["http_status"] = response.status_code
        if response.status_code != 200:
            continue
        try:
            metadata = response.json()
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(metadata, dict) and isinstance(metadata.get("resource"), str):
            servers = metadata.get("authorization_servers")
            details["metadata_url"] = candidate
            details["resource"] = metadata["resource"]
            details["authorization_servers"] = servers if isinstance(servers, list) else None
            return ProbeResult(PROBE_AUTH_METADATA, ProbeOutcome.SUPPORTED, details, payload=metadata)
    return ProbeResult(PROBE_AUTH_METADATA, ProbeOutcome.UNSUPPORTED, details)


async def _probe_session_id_echo(client: httpx2.AsyncClient, url: str) -> ProbeResult:
    """Send a modern request carrying a spurious ``Mcp-Session-Id`` header.

    ``Mcp-Session-Id`` is removed in 2026-07-28; servers serving modern
    requests must "ignore it, and do not mint or echo session IDs". SUPPORTED
    when the request is served normally with no session ID in the response —
    echoing/minting one is leaked legacy session bookkeeping.
    """
    target = _target_version()
    headers = _request_headers(target, "tools/list")
    headers["Mcp-Session-Id"] = SESSION_ID_PROBE_VALUE
    response = await _post(client, url, _request_body("tools/list", 8, _modern_meta(target)), headers)
    details = _base_details(response)
    result = response.result
    served = result is not None and isinstance(result.get("tools"), list)
    response_session_id = response.headers.get("mcp-session-id")
    details["request_served"] = served
    details["response_session_id"] = response_session_id
    correct = served and response_session_id is None
    outcome = ProbeOutcome.SUPPORTED if correct else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_SESSION_ID_ECHO, outcome, details)


async def _probe_removed_method(client: httpx2.AsyncClient, url: str) -> ProbeResult:
    """Send a modern request for a method removed in the target revision (``ping``).

    Removed methods are unknown methods: the server MUST respond with HTTP 404
    and JSON-RPC ``-32601`` (Method not found). A server that still *serves*
    the method is leaking removed legacy surface.
    """
    target = _target_version()
    response = await _post(
        client,
        url,
        _request_body(REMOVED_METHOD, 9, _modern_meta(target)),
        _request_headers(target, REMOVED_METHOD),
    )
    details = _base_details(response)
    details["method_served"] = response.payload is not None and "result" in response.payload
    correct = response.status_code == 404 and response.error_code == ERROR_METHOD_NOT_FOUND
    outcome = ProbeOutcome.SUPPORTED if correct else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_REMOVED_METHOD, outcome, details)


_PROBES = {
    PROBE_DISCOVER: _probe_discover,
    PROBE_STATELESS_LIST: _probe_stateless_list,
    PROBE_MALFORMED_META: _probe_malformed_meta,
    PROBE_HEADER_MISMATCH: _probe_header_mismatch,
    PROBE_UNKNOWN_VERSION: _probe_unknown_version,
    PROBE_MISSING_RESOURCE: _probe_missing_resource,
    PROBE_UNAUTHENTICATED: _probe_unauthenticated,
    PROBE_SESSION_ID_ECHO: _probe_session_id_echo,
    PROBE_REMOVED_METHOD: _probe_removed_method,
    PROBE_AUTH_METADATA: _probe_auth_metadata,
}


def not_applicable_results(reason: str) -> dict[str, ProbeResult]:
    """NOT_APPLICABLE results for every probe (e.g. for stdio servers)."""
    return {probe_id: ProbeResult(probe_id, ProbeOutcome.NOT_APPLICABLE, {"reason": reason}) for probe_id in PROBE_IDS}


GATEWAY_PROBE_IDS: tuple[str, ...] = (PROBE_DISCOVER, PROBE_STATELESS_LIST)
"""Probes whose support indicates the server speaks the modern lifecycle at all."""


def has_modern_support(probes: dict[str, ProbeResult] | None) -> bool:
    """Whether the probes observed any modern-lifecycle support.

    True when the server answered ``server/discover`` or a stateless request —
    the gateway condition for the detail readiness rules.
    """
    if not probes:
        return False
    return any(
        probes[probe_id].outcome is ProbeOutcome.SUPPORTED for probe_id in GATEWAY_PROBE_IDS if probe_id in probes
    )


def detect_era(session_protocol_version: str | None, probes: dict[str, ProbeResult] | None) -> Era | None:
    """Classify which lifecycle era(s) the server supports.

    Follows the spec's own client guidance: a ``DiscoverResult`` — or a
    recognized modern JSON-RPC error such as ``-32022`` — identifies a modern
    server; a completed legacy ``initialize`` handshake identifies a legacy
    server; both together mean dual-era.

    Args:
        session_protocol_version: The version negotiated by the legacy SDK
            session, or None when the handshake never completed
        probes: Probe observations from run_all_probes, or None

    Returns:
        The observed era, or None when there is no evidence either way
        (e.g. stdio servers, where probes do not run)

    """
    modern = has_modern_support(probes) or (
        probes is not None
        and PROBE_UNKNOWN_VERSION in probes
        and probes[PROBE_UNKNOWN_VERSION].outcome is ProbeOutcome.SUPPORTED
    )
    legacy = session_protocol_version is not None

    if modern and legacy:
        return Era.DUAL
    if modern:
        return Era.MODERN
    if legacy:
        return Era.LEGACY
    return None


async def run_all_probes(
    url: str,
    client: httpx2.AsyncClient | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, ProbeResult]:
    """Run every probe against an HTTP(S) MCP endpoint.

    Probes run concurrently; a probe that fails at the network level yields
    ``ProbeOutcome.ERROR`` with the exception name in its details — probes
    never raise.

    Args:
        url: The MCP endpoint URL (http:// or https://)
        client: Optional preconfigured httpx client (tests inject a
            MockTransport-backed one); a short-lived client is created
            otherwise
        headers: Extra HTTP headers (e.g. an ``Authorization`` bearer) merged
            into the short-lived client's defaults. Ignored when ``client`` is
            supplied (the caller configures it). Sensitive — never logged.

    Returns:
        Mapping of probe_id to its ProbeResult, covering all PROBE_IDS

    """

    async def run_one(probe_id: str, http_client: httpx2.AsyncClient) -> ProbeResult:
        try:
            return await _PROBES[probe_id](http_client, url)
        except Exception as e:  # noqa: BLE001 — a probe failure is data, never an audit abort
            logger.info("Probe %s failed against %s: %s", probe_id, url, e)
            return ProbeResult(probe_id, ProbeOutcome.ERROR, {"exception": type(e).__name__})

    async def run_with(http_client: httpx2.AsyncClient) -> dict[str, ProbeResult]:
        results = await asyncio.gather(*(run_one(probe_id, http_client) for probe_id in PROBE_IDS))
        return {result.probe_id: result for result in results}

    if client is not None:
        return await run_with(client)
    async with httpx2.AsyncClient(follow_redirects=True, headers=headers) as own_client:
        return await run_with(own_client)
