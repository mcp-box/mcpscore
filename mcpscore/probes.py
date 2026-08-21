"""Sessionless probes for spec behaviors outside the negotiated session.

The SDK session in `mcp_client` speaks one negotiated protocol version; it
cannot observe what *else* a server supports (e.g. "does this stateful
2025-11-25 server also answer a stateless 2026-07-28 request?"). Probes fill
that gap: each one issues raw JSON-RPC requests (no SDK session) and records
an observation for rules to consume via ``AuditData.probes``.

Probe outcomes are data, never errors: a server rejecting a probe is exactly
as informative as one accepting it. Network failures become
``ProbeOutcome.ERROR`` so dependent rules can degrade to "could not verify"
instead of failing the server.

Probes target the newest draft spec revision from the registry
(:data:`mcpscore.spec.DRAFT`), falling back to the latest final revision.

**Transports.** The modern lifecycle is stateless — a request carries its own
``_meta`` envelope and needs no handshake — so most probes are questions about
JSON-RPC, not about HTTP, and run over stdio just as well. Probes therefore
take a *target* (:class:`_HttpTarget` or :class:`_StdioTarget`) rather than an
HTTP client. The exceptions are the probes whose subject *is* an HTTP
construct — headers, status codes, ``Origin``, the well-known auth documents:
those are listed in :data:`HTTP_ONLY_PROBE_IDS` and record
``NOT_APPLICABLE`` on stdio.

Because there is no HTTP status over stdio, ``_ProbeResponse.status_code`` is
``None`` there and paired "HTTP 4xx *and* JSON-RPC code" requirements reduce to
their JSON-RPC half — see :func:`_http_status_is`.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import StrEnum
from importlib.metadata import PackageNotFoundError, version as package_version
import json
import logging
from subprocess import DEVNULL
from typing import TYPE_CHECKING, Any, Protocol, TextIO, cast

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterable

    from mcp import StdioServerParameters
from urllib.parse import urlsplit
from uuid import uuid4

import httpx2
from mcp.client.stdio import stdio_client
from mcp.shared.message import SessionMessage
from mcp_types import JSONRPCRequest

from mcpscore.spec import DRAFT, LATEST, Era

logger = logging.getLogger(__name__)

__all__ = [
    "AUTH_GATED_STATUSES",
    "GATEWAY_PROBE_IDS",
    "HTTP_ONLY_PROBE_IDS",
    "PROBE_IDS",
    "ProbeOutcome",
    "ProbeResult",
    "detect_era",
    "has_modern_support",
    "not_applicable_results",
    "run_all_probes",
    "run_stdio_probes",
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

UNKNOWN_METHOD_PREFIX = "mcpscore/unknown-method-"
"""Prefix of the deliberately unimplemented method sent by the unknown-method
probe; a random suffix is appended per probe so it cannot be pre-implemented."""

ORIGIN_PROBE_VALUE = "https://mcpscore.invalid"
"""Foreign Origin sent by the Origin-validation probe; must never be an origin
a real deployment would allow."""

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
PROBE_ORIGIN_VALIDATION = "probe_origin_validation"
PROBE_UNKNOWN_METHOD = "probe_unknown_method"
PROBE_JSONRPC_BATCH = "probe_jsonrpc_batch"
PROBE_MALFORMED_JSON = "probe_malformed_json"

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
    PROBE_ORIGIN_VALIDATION,
    PROBE_UNKNOWN_METHOD,
    PROBE_JSONRPC_BATCH,
    PROBE_MALFORMED_JSON,
)
"""Stable identifiers of all probes."""

HTTP_ONLY_PROBE_IDS: frozenset[str] = frozenset(
    {
        PROBE_HEADER_MISMATCH,
        PROBE_UNAUTHENTICATED,
        PROBE_SESSION_ID_ECHO,
        PROBE_AUTH_METADATA,
        PROBE_ORIGIN_VALIDATION,
        PROBE_JSONRPC_BATCH,
        PROBE_MALFORMED_JSON,
    }
)
"""Probes whose *subject* is an HTTP construct, so they cannot run over stdio.

Not "probes that happen to use HTTP" — every probe does that over an HTTP
target. These ask questions that only exist in HTTP: the ``Mcp-Method`` header
contradicting the body (SEP-2243), the unauthenticated status and
``WWW-Authenticate`` challenge, the removed ``Mcp-Session-Id`` header, the
RFC 9728/8414 well-known documents, and ``Origin`` validation against DNS
rebinding, plus the one-message-per-HTTP-POST body contract. Over stdio they
record ``NOT_APPLICABLE``, which is the honest answer: there is no such thing
to get wrong.
"""

STDIO_PROBE_IDS: tuple[str, ...] = tuple(p for p in PROBE_IDS if p not in HTTP_ONLY_PROBE_IDS)
"""Probes that run over stdio — the ones judging JSON-RPC, not HTTP."""

_ANONYMOUS_PROBE_IDS = frozenset({PROBE_UNAUTHENTICATED, PROBE_AUTH_METADATA})
"""Probes that must see the server as an unauthenticated client does.

These run on a client that carries none of the caller's headers: --header may
hold non-Authorization credentials (API keys, cookies) that would defeat the
unauthenticated observation, and auth-metadata discovery (RFC 8414) can leave
the server's origin for the authorization server's.
"""


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
    """Parsed response to a probe request, from either transport."""

    status_code: int | None
    """HTTP status, or None when the transport has no HTTP layer (stdio).

    None is not "unknown" — it means the question does not exist for this
    transport, and paired status/JSON-RPC requirements reduce to their
    JSON-RPC half (:func:`_http_status_is`)."""

    headers: dict[str, str]
    payload: dict[str, Any] | None
    """The JSON-RPC message, parsed from a JSON body or the first SSE data
    event; None when the body is neither."""

    @property
    def error(self) -> dict[str, Any] | None:
        # Only a JSON-RPC error *object* counts. A non-dict "error" (e.g. an
        # OAuth/RFC 6750 body's string `"error": "invalid_token"` on a 401)
        # must not be treated as one — error_code/_base_details call .get() on
        # it, which would raise AttributeError on a string.
        if not isinstance(self.payload, dict):
            return None
        error = self.payload.get("error")
        return error if isinstance(error, dict) else None

    @property
    def error_code(self) -> int | None:
        error = self.error
        code = error.get("code") if error else None
        return code if isinstance(code, int) else None

    @property
    def result(self) -> dict[str, Any] | None:
        result = self.payload.get("result") if isinstance(self.payload, dict) else None
        return result if isinstance(result, dict) else None


@dataclass(frozen=True)
class _HttpProbeResponse(_ProbeResponse):
    """A response from an HTTP target, where a status code always exists.

    Narrowing the field here (rather than asserting at each use) is what lets
    the HTTP-only probes keep comparing statuses directly while the shared
    ``_ProbeResponse`` stays honest that stdio has none.
    """

    status_code: int


def _client_version() -> str:
    try:
        return package_version("mcpscore")
    except PackageNotFoundError:  # pragma: no cover - installed in all real environments
        return "0.0.0"


def _target_version() -> str:
    """Spec version the probes speak: the draft if one exists, else the latest final."""
    return (DRAFT or LATEST).version


def _modern_meta(protocol_version: str) -> dict[str, Any]:
    """Build the standard per-request ``_meta`` envelope for the modern lifecycle.

    ``protocolVersion`` and ``clientCapabilities`` are required. ``clientInfo``
    is a SHOULD in the final 2026-07-28 revision, and mcpscore sends it so the
    request identifies its origin without treating omission as invalid.
    """
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


class _ProbeTarget(Protocol):
    """What a probe needs to ask a server one sessionless question."""

    async def post(
        self,
        body: dict,
        headers: dict[str, str],
        *,
        anonymous: bool = False,
        follow_redirects: bool = True,
    ) -> _ProbeResponse:
        """Send one JSON-RPC request and return the parsed response."""
        raise NotImplementedError


@dataclass(frozen=True)
class _HttpTarget:
    """A probe target reached over HTTP(S)."""

    client: httpx2.AsyncClient
    url: str

    async def post(
        self,
        body: dict,
        headers: dict[str, str],
        *,
        anonymous: bool = False,
        follow_redirects: bool = True,
    ) -> _HttpProbeResponse:
        """POST a probe request, optionally stripping the caller's Authorization.

        When ``anonymous``, remove any caller-supplied ``Authorization`` header
        so the probe observes the server's unauthenticated behavior even when a
        token was provided via --token/--header. When ``run_all_probes`` created
        the clients itself, anonymous probes additionally run on a client that
        carries no caller headers at all (see ``_ANONYMOUS_PROBE_IDS``); the pop
        here also covers caller-injected clients whose defaults it cannot
        control. ``follow_redirects`` may be disabled for security checks that
        must judge the target endpoint itself without forwarding caller context
        elsewhere.
        """
        request = self.client.build_request("POST", self.url, json=body, headers=headers, timeout=PROBE_TIMEOUT_S)
        if anonymous:
            request.headers.pop("Authorization", None)
        response = await self.client.send(request, follow_redirects=follow_redirects)
        return _HttpProbeResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            payload=_parse_payload(response),
        )

    async def post_raw(self, content: bytes, headers: dict[str, str]) -> _HttpProbeResponse:
        """POST an intentionally invalid raw body without following redirects.

        Only HTTP-specific negative probes use this path. Redirects stay off so
        caller-supplied credentials cannot leave the audited endpoint while
        mcpscore is sending malformed input.
        """
        request = self.client.build_request(
            "POST",
            self.url,
            content=content,
            headers=headers,
            timeout=PROBE_TIMEOUT_S,
        )
        response = await self.client.send(request, follow_redirects=False)
        return _HttpProbeResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            payload=_parse_payload(response),
        )


@dataclass(frozen=True)
class _StdioTarget:
    """A probe target reached through the SDK's cross-platform stdio transport.

    One sibling process is used for the whole probe suite. It is separate from
    the audit's SDK session, which has already sent ``initialize`` and pinned
    that connection to the legacy lifecycle, but modern requests do not require
    a fresh process apiece. Reusing one no-handshake connection avoids starting
    the audited command seven times — important for servers with expensive or
    externally visible startup behavior — while every request still carries
    its own complete modern envelope.
    """

    read_stream: Any
    write_stream: Any

    async def post(
        self,
        body: dict,
        headers: dict[str, str],
        *,
        anonymous: bool = False,
        follow_redirects: bool = True,
    ) -> _ProbeResponse:
        """Exchange one JSON-RPC message on the no-handshake connection.

        ``headers``, ``anonymous`` and ``follow_redirects`` are HTTP concepts
        with no stdio equivalent and are accepted only to satisfy the shared
        target interface. They are deliberately ignored: probes that actually
        depend on them are HTTP-only (:data:`HTTP_ONLY_PROBE_IDS`) and never
        reach this transport.
        """
        del headers, anonymous, follow_redirects
        payload = await asyncio.wait_for(self._exchange(body), timeout=PROBE_TIMEOUT_S)
        return _ProbeResponse(status_code=None, headers={}, payload=payload)

    async def _exchange(self, body: dict) -> dict[str, Any]:
        """Write one request and read until the matching response arrives.

        Non-matching messages and parse errors are skipped rather than treated
        as the answer: a server may emit notifications or accidental stdout
        noise before its response.
        """
        request_id = body.get("id")
        request = JSONRPCRequest.model_validate(body)
        await self.write_stream.send(SessionMessage(request))
        async for incoming in self.read_stream:
            if isinstance(incoming, Exception):
                continue
            message = incoming.message
            if getattr(message, "id", None) == request_id:
                return message.model_dump(mode="json", by_alias=True, exclude_none=True)

        # No answer at all is ERROR ("could not verify"), not UNSUPPORTED. A
        # refusal nobody observed must not become a scored protocol failure.
        msg = "server closed its output without answering the probe"
        raise ConnectionError(msg)


def _http_status_is(response: _ProbeResponse, expected: int) -> bool:
    """Whether the HTTP status matches — vacuously true when there is no HTTP.

    Several spec requirements pair a JSON-RPC error code with an HTTP status
    ("MUST be rejected with -32602 and HTTP 400"). Over stdio only the
    JSON-RPC half of that requirement exists, so the status half is satisfied
    rather than failed. Judging a stdio server against an HTTP status it has
    no way to send is exactly the bug this transport split exists to fix.
    """
    return response.status_code is None or response.status_code == expected


def _base_details(response: _ProbeResponse) -> dict[str, Any]:
    details: dict[str, Any] = {"http_status": response.status_code}
    if response.error is not None:
        details["error_code"] = response.error_code
        message = response.error.get("message")
        if isinstance(message, str):
            details["error_message"] = message
    return details


async def _probe_discover(target: _ProbeTarget) -> ProbeResult:
    """``server/discover`` — mandatory for modern servers (SEP-2575).

    SUPPORTED when the server returns a DiscoverResult carrying
    ``supportedVersions``; the details also record the caching hints so the
    cache-metadata rule can check them.
    """
    target_version = _target_version()
    response = await target.post(
        _request_body("server/discover", 1, _modern_meta(target_version)),
        _request_headers(target_version, "server/discover"),
    )
    details = _base_details(response)
    details["content_type"] = response.headers.get("content-type")
    result = response.result
    if result is not None and isinstance(result.get("supportedVersions"), list):
        details["supported_versions"] = result["supportedVersions"]
        details["ttl_ms"] = result.get("ttlMs")
        details["cache_scope"] = result.get("cacheScope")
        details["result_type"] = result.get("resultType")
        return ProbeResult(PROBE_DISCOVER, ProbeOutcome.SUPPORTED, details, payload=result)
    return ProbeResult(PROBE_DISCOVER, ProbeOutcome.UNSUPPORTED, details)


async def _probe_stateless_list(target: _ProbeTarget) -> ProbeResult:
    """Modern ``tools/list`` with required ``_meta``, no prior ``initialize`` (SEP-2575).

    SUPPORTED when the server returns a tools result; details record
    ``resultType`` and the caching hints for the dependent rules.
    """
    target_version = _target_version()
    response = await target.post(
        _request_body("tools/list", 2, _modern_meta(target_version)),
        _request_headers(target_version, "tools/list"),
    )
    details = _base_details(response)
    details["content_type"] = response.headers.get("content-type")
    result = response.result
    if result is not None and isinstance(result.get("tools"), list):
        details["result_type"] = result.get("resultType")
        details["ttl_ms"] = result.get("ttlMs")
        details["cache_scope"] = result.get("cacheScope")
        return ProbeResult(PROBE_STATELESS_LIST, ProbeOutcome.SUPPORTED, details, payload=result)
    return ProbeResult(PROBE_STATELESS_LIST, ProbeOutcome.UNSUPPORTED, details)


async def _probe_malformed_meta(target: _ProbeTarget) -> ProbeResult:
    """Send a modern request missing a required ``_meta`` field.

    The spec: a request missing any required field MUST be rejected with
    JSON-RPC ``-32602`` and HTTP 400. SUPPORTED when the server does exactly
    that; anything else (including happily serving the request) is UNSUPPORTED.
    """
    target_version = _target_version()
    meta = _modern_meta(target_version)
    del meta[f"{META_PREFIX}clientCapabilities"]
    response = await target.post(
        _request_body("tools/list", 3, meta),
        _request_headers(target_version, "tools/list"),
    )
    details = _base_details(response)
    correct = _http_status_is(response, 400) and response.error_code == ERROR_INVALID_PARAMS
    outcome = ProbeOutcome.SUPPORTED if correct else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_MALFORMED_META, outcome, details)


async def _probe_header_mismatch(target: _HttpTarget) -> ProbeResult:
    """Send a request whose ``Mcp-Method`` header contradicts the body method (SEP-2243).

    Servers MUST reject header/body mismatches with HTTP 400 and JSON-RPC
    ``-32020`` (HeaderMismatch). Uses ``tools/list`` in the body (never
    ``tools/call`` — probes must not risk invoking real tools).
    """
    target_version = _target_version()
    headers = _request_headers(target_version, "prompts/list")  # deliberately != body method
    response = await target.post(
        _request_body("tools/list", 4, _modern_meta(target_version)),
        headers,
    )
    details = _base_details(response)
    correct = response.status_code == 400 and response.error_code == ERROR_HEADER_MISMATCH
    outcome = ProbeOutcome.SUPPORTED if correct else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_HEADER_MISMATCH, outcome, details)


async def _probe_unknown_version(target: _ProbeTarget) -> ProbeResult:
    """Send a modern request naming a fabricated protocol version.

    Modern servers MUST reject it with ``-32022`` (UnsupportedProtocolVersion)
    whose ``data`` lists ``supported`` and ``requested`` versions. SUPPORTED
    requires the full error shape: the ``data`` block is what tells a client
    which version to retry with, so a bare ``-32022`` records
    ``data_well_formed: false`` and stays UNSUPPORTED.
    """
    response = await target.post(
        _request_body("tools/list", 5, _modern_meta(UNKNOWN_VERSION)),
        _request_headers(UNKNOWN_VERSION, "tools/list"),
    )
    details = _base_details(response)
    error = response.error
    if error is not None and response.error_code == ERROR_UNSUPPORTED_PROTOCOL_VERSION:
        raw_data = error.get("data")
        data = raw_data if isinstance(raw_data, dict) else {}
        supported = data.get("supported")
        requested = data.get("requested")
        details["supported"] = supported
        details["requested"] = requested
        well_formed = (
            isinstance(supported, list)
            and bool(supported)
            and all(isinstance(v, str) for v in supported)
            and isinstance(requested, str)
        )
        details["data_well_formed"] = well_formed
        outcome = ProbeOutcome.SUPPORTED if well_formed else ProbeOutcome.UNSUPPORTED
        return ProbeResult(PROBE_UNKNOWN_VERSION, outcome, details)
    return ProbeResult(PROBE_UNKNOWN_VERSION, ProbeOutcome.UNSUPPORTED, details)


async def _probe_missing_resource(target: _ProbeTarget) -> ProbeResult:
    """``resources/read`` for a deliberately nonexistent URI (SEP-2164).

    From 2026-07-28 the missing-resource error is standard ``-32602``; the
    legacy ``-32002`` MUST NOT be emitted. SUPPORTED when the modern code is
    observed; the raw code is always recorded (the error-code-migration rule
    also flags undefined codes in the reserved -32020..-32099 range).
    """
    target_version = _target_version()
    response = await target.post(
        _request_body("resources/read", 6, _modern_meta(target_version), params={"uri": MISSING_RESOURCE_URI}),
        _request_headers(target_version, "resources/read", name=MISSING_RESOURCE_URI),
    )
    details = _base_details(response)
    details["legacy_code_emitted"] = response.error_code == ERROR_LEGACY_RESOURCE_NOT_FOUND
    outcome = ProbeOutcome.SUPPORTED if response.error_code == ERROR_INVALID_PARAMS else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_MISSING_RESOURCE, outcome, details)


async def _probe_unauthenticated(target: _HttpTarget) -> ProbeResult:
    """One unauthenticated request, recording status and ``WWW-Authenticate``.

    This is a pure observation probe (it feeds the auth-posture rules):
    SUPPORTED means "an HTTP response was observed", whatever its status —
    the details carry the status code and any authentication challenge.
    """
    target_version = _target_version()
    response = await target.post(
        _request_body("tools/list", 7, _modern_meta(target_version)),
        _request_headers(target_version, "tools/list"),
        anonymous=True,
    )
    details = _base_details(response)
    details["www_authenticate"] = response.headers.get("www-authenticate")
    return ProbeResult(PROBE_UNAUTHENTICATED, ProbeOutcome.SUPPORTED, details)


def observed_auth_status(probes: dict[str, ProbeResult] | None) -> int | None:
    """HTTP status of an auth gate the probes observed, or None if they saw no gate.

    The unauthenticated probe records whatever the server answered, so this is
    the evidence that a server is gated even when the *session* failed for an
    unrelated reason — a legacy SSE fallback answering ``405``, say. Without it
    a gated server that rejects the legacy handshake looks simply unreachable.
    """
    result = (probes or {}).get(PROBE_UNAUTHENTICATED)
    if result is None:
        return None
    status = result.details.get("http_status")
    return status if status in (401, 403) else None


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


async def _get_json_anonymous(client: httpx2.AsyncClient, url: str) -> tuple[int, dict[str, Any] | None]:
    """GET a public well-known JSON document, stripping any caller Authorization.

    Returns (http_status, parsed_dict_or_None). Auth-discovery documents (RFC
    9728, RFC 8414) are public — and RFC 8414 discovery can leave the server's
    origin for the authorization server's — so no caller credential may be
    sent. When ``run_all_probes`` created the clients, these fetches already
    run on a header-free client (``_ANONYMOUS_PROBE_IDS``); the pop here also
    covers caller-injected clients.
    """
    request = client.build_request("GET", url, headers={"Accept": "application/json"}, timeout=PROBE_TIMEOUT_S)
    request.headers.pop("Authorization", None)
    response = await client.send(request)
    if response.status_code != 200:
        return response.status_code, None
    try:
        parsed = response.json()
    except (json.JSONDecodeError, ValueError):
        return response.status_code, None
    return response.status_code, parsed if isinstance(parsed, dict) else None


async def _try_get_json_anonymous(
    client: httpx2.AsyncClient, url: str
) -> tuple[int | None, dict[str, Any] | None, str | None]:
    """``_get_json_anonymous`` that reports transport failures as data, never raises.

    The auth-discovery chain spans hosts the audited server does not control —
    RFC 8414 discovery leaves the server's origin for the authorization
    server's. An unreachable, slow or TLS-broken hop there is a finding about
    *that* hop, so it must not discard what earlier hops already established.

    ``InvalidURL`` is caught alongside ``HTTPError`` (it derives from
    ``Exception``, not from it): these URLs are built from the audited server's
    own ``authorization_servers`` values, and a syntactically plausible but
    unusable one — ``https://256.256.256.256``, a bare IPv6 host, a zero-width
    space in the hostname — must be a finding about that server, not an
    exception that voids the audit's other observations.

    Returns (http_status, parsed_dict_or_None, exception_name_or_None); status
    is None when the request never completed.
    """
    try:
        status, parsed = await _get_json_anonymous(client, url)
    except (httpx2.HTTPError, httpx2.InvalidURL) as e:
        return None, None, type(e).__name__
    return status, parsed, None


def _is_http_url(value: object) -> bool:
    """Whether a value is an http(s) URL string."""
    return isinstance(value, str) and value.startswith(("https://", "http://"))


def _auth_server_metadata_urls(issuer: str) -> list[str]:
    """RFC 8414 / OIDC well-known locations for an authorization server issuer."""
    base = issuer.rstrip("/")
    return [
        f"{base}/.well-known/oauth-authorization-server",
        f"{base}/.well-known/openid-configuration",
    ]


async def _fetch_auth_server_metadata(client: httpx2.AsyncClient, issuer: str, details: dict[str, Any]) -> None:
    """Fetch the authorization server's RFC 8414 metadata; record posture in details.

    Records whether the metadata document was found, whether it advertises the
    required authorization/token endpoints, and whether it advertises PKCE with
    S256 (`code_challenge_methods_supported`) — the OAuth security BCP (RFC
    9700) / MCP-auth requirement.

    An authorization server that cannot be reached at all (DNS failure,
    refused connection, timeout, TLS error, unusable URL) leaves
    ``auth_server_metadata_present`` False and records the transport failure in
    ``auth_server_metadata_error``: "the issuer this server advertises is
    unreachable" is itself the finding, and it must not void the
    protected-resource metadata already collected by the caller.

    ``auth_server_metadata_error`` means *no* candidate location was contacted.
    An issuer that answers one location (even with a 404 or a non-JSON body) is
    reachable and simply publishes nothing usable there, so it records no
    transport error — reporting one would misattribute a missing document to an
    unreachable host.
    """
    details["auth_server_issuer"] = issuer
    details["auth_server_metadata_present"] = False
    reached = False
    last_error: str | None = None
    for candidate in _auth_server_metadata_urls(issuer):
        _status, metadata, error = await _try_get_json_anonymous(client, candidate)
        if error is not None:
            last_error = error
            continue
        reached = True
        if metadata is None:
            continue
        methods = metadata.get("code_challenge_methods_supported")
        details["auth_server_metadata_url"] = candidate
        details["auth_server_metadata_present"] = True
        details["auth_server_has_endpoints"] = isinstance(metadata.get("authorization_endpoint"), str) and isinstance(
            metadata.get("token_endpoint"), str
        )
        details["auth_server_pkce_s256"] = isinstance(methods, list) and "S256" in methods
        return
    if not reached:
        details["auth_server_metadata_error"] = last_error


async def _probe_auth_metadata(target: _HttpTarget) -> ProbeResult:
    """Fetch the auth-discovery chain (RFC 9728 PRM → RFC 8414 AS metadata).

    Observation probe feeding the auth-posture rules: SUPPORTED when a
    well-known location returns HTTP 200 with a JSON object carrying the
    REQUIRED ``resource`` field (RFC 9728 §2); details record what was found
    where, plus the authorization server's endpoint/PKCE posture. Servers
    without authentication commonly 404 here — the dependent rules skip unless
    the endpoint demanded auth in the first place.

    A transport error on one well-known location does not abort discovery of
    the next, but "every location failed to connect" stays ERROR rather than
    UNSUPPORTED: an unreachable host is *unverified*, not proof that the
    server publishes no metadata, and the dependent rules must skip rather
    than fail it. Locations that could not be contacted are listed in
    ``unreachable_locations`` whatever the outcome, so a firewalled location is
    distinguishable from one that simply answered 404.
    """
    details: dict[str, Any] = {"urls_tried": []}
    reached = False
    last_error: str | None = None
    for candidate in _well_known_urls(target.url):
        details["urls_tried"].append(candidate)
        status, metadata, error = await _try_get_json_anonymous(target.client, candidate)
        if error is not None:
            last_error = error
            details.setdefault("unreachable_locations", []).append(candidate)
            continue
        reached = True
        details["http_status"] = status
        if metadata is None:
            continue
        if isinstance(metadata.get("resource"), str):
            servers = metadata.get("authorization_servers")
            servers = servers if isinstance(servers, list) else None
            details["metadata_url"] = candidate
            details["resource"] = metadata["resource"]
            details["authorization_servers"] = servers
            details["scopes_supported"] = metadata.get("scopes_supported")
            # Walk to the first authorization server's RFC 8414 metadata. The
            # document is public and fetched anonymously; whether the AS URL is
            # HTTPS is scored separately by auth_authorization_servers_https, so
            # observe http too rather than skipping the metadata check entirely.
            first = next((s for s in (servers or []) if _is_http_url(s)), None)
            if first is not None:
                await _fetch_auth_server_metadata(target.client, first, details)
            return ProbeResult(PROBE_AUTH_METADATA, ProbeOutcome.SUPPORTED, details, payload=metadata)
    if not reached:
        # Keep what was established (urls_tried, unreachable_locations) — an
        # ERROR outcome is the case that most needs the diagnostic context.
        return ProbeResult(PROBE_AUTH_METADATA, ProbeOutcome.ERROR, details | {"exception": last_error})
    return ProbeResult(PROBE_AUTH_METADATA, ProbeOutcome.UNSUPPORTED, details)


async def _probe_session_id_echo(target: _HttpTarget) -> ProbeResult:
    """Send a modern request carrying a spurious ``Mcp-Session-Id`` header.

    ``Mcp-Session-Id`` is removed in 2026-07-28; servers serving modern
    requests must "ignore it, and do not mint or echo session IDs". SUPPORTED
    when the request is served normally with no session ID in the response —
    echoing/minting one is leaked legacy session bookkeeping.
    """
    target_version = _target_version()
    headers = _request_headers(target_version, "tools/list")
    headers["Mcp-Session-Id"] = SESSION_ID_PROBE_VALUE
    response = await target.post(_request_body("tools/list", 8, _modern_meta(target_version)), headers)
    details = _base_details(response)
    result = response.result
    served = result is not None and isinstance(result.get("tools"), list)
    response_session_id = response.headers.get("mcp-session-id")
    details["request_served"] = served
    details["response_session_id"] = response_session_id
    correct = served and response_session_id is None
    outcome = ProbeOutcome.SUPPORTED if correct else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_SESSION_ID_ECHO, outcome, details)


async def _probe_removed_method(target: _ProbeTarget) -> ProbeResult:
    """Send a modern request for a method removed in the target revision (``ping``).

    Removed methods are unknown methods: the server MUST respond with HTTP 404
    and JSON-RPC ``-32601`` (Method not found). A server that still *serves*
    the method is leaking removed legacy surface.
    """
    target_version = _target_version()
    response = await target.post(
        _request_body(REMOVED_METHOD, 9, _modern_meta(target_version)),
        _request_headers(target_version, REMOVED_METHOD),
    )
    details = _base_details(response)
    details["method_served"] = response.payload is not None and "result" in response.payload
    correct = _http_status_is(response, 404) and response.error_code == ERROR_METHOD_NOT_FOUND
    outcome = ProbeOutcome.SUPPORTED if correct else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_REMOVED_METHOD, outcome, details)


async def _probe_origin_validation(target: _HttpTarget) -> ProbeResult:
    """Send a harmless list request with an invalid foreign ``Origin``.

    Streamable HTTP servers MUST validate every supplied Origin to prevent DNS
    rebinding and MUST reject an invalid one with HTTP 403. The request uses
    ``tools/list`` and cannot invoke server-side tool behavior.

    **A single 403 proves nothing**, because 403 is also how an access-controlled
    server refuses everyone. Judged on its own, every server that rejects
    unauthenticated callers would pass a CRITICAL security check it has not
    earned — measured against the registry, 54 servers answer 403 to any
    unauthenticated request. So this sends a control request *without* the
    foreign Origin first, and only judges the server when that control shows the
    same request would otherwise be accepted.
    """
    target_version = _target_version()
    body = _request_body("tools/list", 10, _modern_meta(target_version))
    control = await target.post(
        body,
        _request_headers(target_version, "tools/list"),
        follow_redirects=False,
    )

    # Decide on the control before sending anything spoofed. When the answer is
    # already unknowable, the second request would add security-relevant traffic
    # (and another timeout) to a server we cannot judge anyway.
    if control.status_code in AUTH_GATED_STATUSES:
        # The endpoint refuses the control too, so a 403 to the foreign Origin
        # would say nothing about Origin handling. Not a failure — an
        # unanswerable question.
        unjudged: dict[str, Any] = {
            "control_http_status": control.status_code,
            "reason": "control request is access-controlled; Origin handling not observable",
        }
        return ProbeResult(PROBE_ORIGIN_VALIDATION, ProbeOutcome.NOT_APPLICABLE, unjudged)
    if not 200 <= control.status_code < 300:
        unjudged = {
            "control_http_status": control.status_code,
            "reason": f"control request was not accepted (HTTP {control.status_code})",
        }
        return ProbeResult(PROBE_ORIGIN_VALIDATION, ProbeOutcome.NOT_APPLICABLE, unjudged)

    headers = _request_headers(target_version, "tools/list")
    headers["Origin"] = ORIGIN_PROBE_VALUE
    response = await target.post(body, headers, follow_redirects=False)

    details = _base_details(response)
    details["control_http_status"] = control.status_code
    outcome = ProbeOutcome.SUPPORTED if response.status_code == 403 else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_ORIGIN_VALIDATION, outcome, details)


async def _probe_unknown_method(target: _ProbeTarget) -> ProbeResult:
    """Send a side-effect-free request for a deliberately unknown RPC method.

    Modern Streamable HTTP servers MUST return HTTP 404 together with JSON-RPC
    ``-32601`` (Method not found). The deliberately non-standard method name is
    namespaced to mcpscore to avoid colliding with a core MCP method.
    """
    target_version = _target_version()
    # Randomised per probe: a fixed name could be implemented — deliberately or
    # by accident — and would then pass the rule without the server actually
    # handling unknown methods correctly. The readable prefix is kept so the
    # request is identifiable in a server operator's logs.
    method = f"{UNKNOWN_METHOD_PREFIX}{uuid4().hex[:12]}"
    response = await target.post(
        _request_body(method, 11, _modern_meta(target_version)),
        _request_headers(target_version, method),
    )
    details = _base_details(response)
    if response.status_code in AUTH_GATED_STATUSES:
        # The request never reached method dispatch, so how this server answers
        # an unknown method is unobservable. Auth-gated servers are healthy;
        # failing them here would report an auth posture as a transport defect.
        details["reason"] = "request is access-controlled; method dispatch not observable"
        return ProbeResult(PROBE_UNKNOWN_METHOD, ProbeOutcome.NOT_APPLICABLE, details)
    correct = _http_status_is(response, 404) and response.error_code == ERROR_METHOD_NOT_FOUND
    outcome = ProbeOutcome.SUPPORTED if correct else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_UNKNOWN_METHOD, outcome, details)


def _invalid_http_payload_result(probe_id: str, response: _HttpProbeResponse) -> ProbeResult:
    """Classify an intentionally invalid HTTP payload without overclaiming.

    The Streamable HTTP spec requires one JSON-RPC message per POST, but does
    not prescribe one response body or 4xx status for every parser failure.
    Any client-error status is therefore compliant; accepting the body, a
    redirect, or a server error is not.
    """
    details = _base_details(response)
    if response.status_code in AUTH_GATED_STATUSES:
        details["reason"] = "request is access-controlled; payload validation not observable"
        return ProbeResult(probe_id, ProbeOutcome.NOT_APPLICABLE, details)
    outcome = ProbeOutcome.SUPPORTED if 400 <= response.status_code < 500 else ProbeOutcome.UNSUPPORTED
    return ProbeResult(probe_id, outcome, details)


async def _probe_jsonrpc_batch(target: _HttpTarget) -> ProbeResult:
    """Send a one-element JSON-RPC batch, which Streamable HTTP forbids."""
    target_version = _target_version()
    body = [_request_body("tools/list", 12, _modern_meta(target_version))]
    response = await target.post_raw(
        json.dumps(body, separators=(",", ":")).encode(),
        _request_headers(target_version, "tools/list"),
    )
    return _invalid_http_payload_result(PROBE_JSONRPC_BATCH, response)


async def _probe_malformed_json(target: _HttpTarget) -> ProbeResult:
    """Send truncated JSON and require a client-error response, never a 5xx."""
    target_version = _target_version()
    response = await target.post_raw(
        b'{"jsonrpc":"2.0","id":13,"method":"tools/list",',
        _request_headers(target_version, "tools/list"),
    )
    return _invalid_http_payload_result(PROBE_MALFORMED_JSON, response)


_TRANSPORT_AGNOSTIC_PROBES: dict[str, Callable[[_ProbeTarget], Awaitable[ProbeResult]]] = {
    PROBE_DISCOVER: _probe_discover,
    PROBE_STATELESS_LIST: _probe_stateless_list,
    PROBE_MALFORMED_META: _probe_malformed_meta,
    PROBE_UNKNOWN_VERSION: _probe_unknown_version,
    PROBE_MISSING_RESOURCE: _probe_missing_resource,
    PROBE_REMOVED_METHOD: _probe_removed_method,
    PROBE_UNKNOWN_METHOD: _probe_unknown_method,
}
"""Probes that judge JSON-RPC behavior, and so run over any transport."""

_HTTP_ONLY_PROBES: dict[str, Callable[[_HttpTarget], Awaitable[ProbeResult]]] = {
    PROBE_HEADER_MISMATCH: _probe_header_mismatch,
    PROBE_UNAUTHENTICATED: _probe_unauthenticated,
    PROBE_SESSION_ID_ECHO: _probe_session_id_echo,
    PROBE_AUTH_METADATA: _probe_auth_metadata,
    PROBE_ORIGIN_VALIDATION: _probe_origin_validation,
    PROBE_JSONRPC_BATCH: _probe_jsonrpc_batch,
    PROBE_MALFORMED_JSON: _probe_malformed_json,
}
"""Probes whose subject is an HTTP construct (see HTTP_ONLY_PROBE_IDS)."""

# A probe accepting any target also accepts an HTTP one, so the merged map is
# keyed on the narrower parameter type.
_HTTP_PROBES: dict[str, Callable[[_HttpTarget], Awaitable[ProbeResult]]] = {
    **_TRANSPORT_AGNOSTIC_PROBES,
    **_HTTP_ONLY_PROBES,
}


def not_applicable_results(reason: str, probe_ids: Iterable[str] = PROBE_IDS) -> dict[str, ProbeResult]:
    """NOT_APPLICABLE results for the given probes (all of them by default)."""
    return {probe_id: ProbeResult(probe_id, ProbeOutcome.NOT_APPLICABLE, {"reason": reason}) for probe_id in probe_ids}


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
        (e.g. the handshake and modern probes both failed)

    """
    # Recognition of the modern error is about the CODE: a server answering
    # -32022 speaks the modern vocabulary even when the error's data block is
    # malformed (the probe then reports UNSUPPORTED for the readiness rule,
    # which judges the shape — that must not demote the server's era).
    unknown = (probes or {}).get(PROBE_UNKNOWN_VERSION)
    modern = has_modern_support(probes) or (
        unknown is not None
        and (
            unknown.outcome is ProbeOutcome.SUPPORTED
            or unknown.details.get("error_code") == ERROR_UNSUPPORTED_PROTOCOL_VERSION
        )
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
            MockTransport-backed one); short-lived clients are created
            otherwise. An injected client is used for every probe, including
            the anonymous ones — the caller configures its headers.
        headers: Extra HTTP headers (e.g. an ``Authorization`` bearer) merged
            into the short-lived authenticated client's defaults; probes in
            ``_ANONYMOUS_PROBE_IDS`` run on a separate client that carries
            none of them. Ignored when ``client`` is supplied. Sensitive —
            never logged.

    Returns:
        Mapping of probe_id to its ProbeResult, covering all PROBE_IDS

    """

    async def run_one(probe_id: str, http_client: httpx2.AsyncClient) -> ProbeResult:
        try:
            return await _HTTP_PROBES[probe_id](_HttpTarget(http_client, url))
        except Exception as e:  # noqa: BLE001 — a probe failure is data, never an audit abort
            logger.info("Probe %s failed against %s: %s", probe_id, url, e)
            return ProbeResult(probe_id, ProbeOutcome.ERROR, {"exception": type(e).__name__})

    async def run_with(select: Callable[[str], httpx2.AsyncClient]) -> dict[str, ProbeResult]:
        results = await asyncio.gather(*(run_one(probe_id, select(probe_id)) for probe_id in PROBE_IDS))
        return {result.probe_id: result for result in results}

    if client is not None:
        return await run_with(lambda _probe_id: client)
    async with (
        httpx2.AsyncClient(follow_redirects=True, headers=headers) as own_client,
        httpx2.AsyncClient(follow_redirects=True) as anon_client,
    ):
        return await run_with(lambda probe_id: anon_client if probe_id in _ANONYMOUS_PROBE_IDS else own_client)


async def run_stdio_probes(params: StdioServerParameters) -> dict[str, ProbeResult]:
    """Run the transport-agnostic probes against a local stdio MCP server.

    The modern lifecycle is stateless, so "does this server speak 2026-07-28?"
    is answerable over stdio exactly as over HTTP: send the request, read the
    reply. The suite launches one short-lived sibling process and deliberately
    stays below the SDK session layer, so no ``initialize`` handshake pins that
    connection to the legacy lifecycle. Probes run sequentially on it because
    a stdio stream has one reader; each request remains self-contained.

    Probes in :data:`HTTP_ONLY_PROBE_IDS` are recorded ``NOT_APPLICABLE``:
    their subject does not exist on this transport.

    Args:
        params: Fully-resolved command, arguments and environment of the
            server, as used for the audit's own stdio connection.

    Returns:
        Mapping of probe_id to its ProbeResult, covering all PROBE_IDS

    """

    async def run_one(probe_id: str, target: _StdioTarget) -> ProbeResult:
        try:
            return await _TRANSPORT_AGNOSTIC_PROBES[probe_id](target)
        except Exception as e:  # noqa: BLE001 — a probe failure is data, never an audit abort
            logger.info("Probe %s failed against %s: %s", probe_id, params.command, e)
            return ProbeResult(probe_id, ProbeOutcome.ERROR, {"exception": type(e).__name__})

    results: list[ProbeResult] = []
    try:
        # Use the SDK transport rather than managing asyncio subprocesses
        # directly. This preserves its cross-platform executable resolution,
        # safe environment allowlist, process-tree termination, pipe draining,
        # and cancellation shielding. Diagnostics from the sibling process are
        # suppressed so they cannot interleave with the audit's own output.
        # The SDK annotates errlog as TextIO but forwards it to the subprocess
        # API, where DEVNULL is the native cross-platform sentinel.
        errlog: TextIO = cast("Any", DEVNULL)
        async with stdio_client(params, errlog=errlog) as (read_stream, write_stream):
            target = _StdioTarget(read_stream, write_stream)
            results.extend([await run_one(probe_id, target) for probe_id in STDIO_PROBE_IDS])
    except Exception as e:  # noqa: BLE001 — process startup/teardown failures are probe data
        logger.info("Stdio probe transport failed against %s: %s", params.command, e)
        completed = {result.probe_id for result in results}
        results.extend(
            ProbeResult(probe_id, ProbeOutcome.ERROR, {"exception": type(e).__name__})
            for probe_id in STDIO_PROBE_IDS
            if probe_id not in completed
        )

    return {
        **not_applicable_results("probe subject is HTTP-specific", HTTP_ONLY_PROBE_IDS),
        **{result.probe_id: result for result in results},
    }
