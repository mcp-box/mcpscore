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
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field, replace
from enum import StrEnum
from importlib.metadata import PackageNotFoundError, version as package_version
import ipaddress
import json
import logging
import re
import socket
from subprocess import DEVNULL
import time
from typing import TYPE_CHECKING, Any, Literal, Protocol, TextIO, cast

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable, Iterable

    from mcp import StdioServerParameters
from urllib.parse import urlsplit
from uuid import uuid4

import httpx2
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import MCPError
from mcp.shared.message import SessionMessage
from mcp_types import JSONRPCRequest
from pydantic import TypeAdapter

from mcpscore.redirects import REDIRECT_STATUSES, send_within_origin
from mcpscore.report_evidence import report_evidence
from mcpscore.spec import DRAFT, LATEST, SPEC_VERSIONS, Era, Lifecycle
from mcpscore.tls import async_client
from mcpscore.url_credentials import credential_query_params, without_credential_params

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

GET_STREAM_TIMEOUT_S = 35.0
"""Timeout for a GET on the endpoint. Servlet-based servers send the headers of
an SSE stream only with its first event, often a keep-alive up to 30 s apart."""

PAGINATION_PROBE_TIMEOUT_S = 30.0
"""Total budget for the cache-scope traversal across all declared surfaces."""

PAGINATION_PROBE_MAX_PAGES = 100
"""Safety bound for one surface in the cache-scope traversal."""

_RAW_BODY_SCAN_LIMIT = 16_384
"""Cap on the malformed-request response body scanned for data leaks. A server
dumping a stack trace can return an unbounded body; 16 KB is far more than any
real leak-bearing error page needs while bounding memory and scan time."""

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

HOST_PROBE_VALUE = "mcpscore.invalid"
"""Foreign ``Host`` sent by the Host-validation probe to a loopback server; a reserved name no server serves."""

LOCAL_BIND_TIMEOUT_S = 5.0
"""Deadline for one TCP connect to a non-loopback interface address of this machine.

Windows reports a refused connection only after retrying the SYN for about two seconds."""

LOCAL_BIND_CONFIRM_TIMEOUT_S = 2 * PROBE_TIMEOUT_S
"""Deadline for confirming one network address serves the audited server: the modern control and its fallback."""

UNKNOWN_VERSION = "2099-01-01"
"""Deliberately unsupported version used by the unknown-version probe."""

MISSING_RESOURCE_URI = "resource://mcpscore/does-not-exist"
"""Deliberately nonexistent resource URI used by the missing-resource probe."""

INVALID_TOKEN_PREFIX = "mcpscore-invalid-token-"  # noqa: S105 — a deliberately invalid token, not a secret
"""Prefix of the fabricated bearer token; a random suffix makes each one impossible to have been issued."""

INVALID_CURSOR_PREFIX = "mcpscore-invalid-cursor-"
"""Prefix for fabricated opaque cursors that cannot plausibly have been issued."""

PROBE_DISCOVER = "probe_discover"
PROBE_STATELESS_LIST = "probe_stateless_list"
PROBE_MALFORMED_META = "probe_malformed_meta"
PROBE_HEADER_MISMATCH = "probe_header_mismatch"
PROBE_MISSING_PROTOCOL_VERSION = "probe_missing_protocol_version"
PROBE_MISSING_METHOD_HEADER = "probe_missing_method_header"
PROBE_RESOURCE_NAME_HEADER_MISMATCH = "probe_resource_name_header_mismatch"
PROBE_PROMPT_NAME_HEADER_MISMATCH = "probe_prompt_name_header_mismatch"
PROBE_GET_STREAM_REMOVED = "probe_get_stream_removed"
PROBE_UNKNOWN_VERSION = "probe_unknown_version"
PROBE_MISSING_RESOURCE = "probe_missing_resource"
PROBE_UNAUTHENTICATED = "probe_unauthenticated"
PROBE_INVALID_TOKEN = "probe_invalid_token"  # noqa: S105 — a probe ID
PROBE_SESSION_ID_ECHO = "probe_session_id_echo"
PROBE_REMOVED_METHOD = "probe_removed_method"
PROBE_AUTH_METADATA = "probe_auth_metadata"
PROBE_ORIGIN_VALIDATION = "probe_origin_validation"
PROBE_UNKNOWN_METHOD = "probe_unknown_method"
PROBE_MALFORMED_JSON = "probe_malformed_json"
PROBE_TOOLS_INVALID_CURSOR = "probe_tools_invalid_cursor"
PROBE_RESOURCES_INVALID_CURSOR = "probe_resources_invalid_cursor"
PROBE_RESOURCE_TEMPLATES_INVALID_CURSOR = "probe_resource_templates_invalid_cursor"
PROBE_PROMPTS_INVALID_CURSOR = "probe_prompts_invalid_cursor"
PROBE_PAGINATION_CACHE_SCOPE = "probe_pagination_cache_scope"
PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT = "probe_tools_catalog_connection_independent"
PROBE_RESOURCES_CATALOG_CONNECTION_INDEPENDENT = "probe_resources_catalog_connection_independent"
PROBE_PROMPTS_CATALOG_CONNECTION_INDEPENDENT = "probe_prompts_catalog_connection_independent"
PROBE_NOTIFICATION_ACCEPTED = "probe_notification_accepted"
PROBE_INVALID_REQUEST = "probe_invalid_request"
PROBE_GET_STREAM = "probe_get_stream"
PROBE_SESSION_DELETE = "probe_session_delete"
PROBE_QUERY_CREDENTIAL = "probe_query_credential"
PROBE_HOST_VALIDATION = "probe_host_validation"
PROBE_LOCAL_BIND = "probe_local_bind"

_SINGLE_TARGET_PROBE_IDS: tuple[str, ...] = (
    PROBE_DISCOVER,
    PROBE_STATELESS_LIST,
    PROBE_MALFORMED_META,
    PROBE_HEADER_MISMATCH,
    PROBE_MISSING_PROTOCOL_VERSION,
    PROBE_MISSING_METHOD_HEADER,
    PROBE_RESOURCE_NAME_HEADER_MISMATCH,
    PROBE_PROMPT_NAME_HEADER_MISMATCH,
    PROBE_GET_STREAM_REMOVED,
    PROBE_UNKNOWN_VERSION,
    PROBE_MISSING_RESOURCE,
    PROBE_UNAUTHENTICATED,
    PROBE_SESSION_ID_ECHO,
    PROBE_REMOVED_METHOD,
    PROBE_AUTH_METADATA,
    PROBE_INVALID_TOKEN,
    PROBE_ORIGIN_VALIDATION,
    PROBE_UNKNOWN_METHOD,
    PROBE_MALFORMED_JSON,
    PROBE_TOOLS_INVALID_CURSOR,
    PROBE_RESOURCES_INVALID_CURSOR,
    PROBE_RESOURCE_TEMPLATES_INVALID_CURSOR,
    PROBE_PROMPTS_INVALID_CURSOR,
    PROBE_PAGINATION_CACHE_SCOPE,
    PROBE_NOTIFICATION_ACCEPTED,
    PROBE_INVALID_REQUEST,
    PROBE_GET_STREAM,
    PROBE_SESSION_DELETE,
    PROBE_QUERY_CREDENTIAL,
    PROBE_HOST_VALIDATION,
    PROBE_LOCAL_BIND,
)
CATALOG_CONNECTION_PROBE_IDS: tuple[str, ...] = (
    PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT,
    PROBE_RESOURCES_CATALOG_CONNECTION_INDEPENDENT,
    PROBE_PROMPTS_CATALOG_CONNECTION_INDEPENDENT,
)
PROBE_IDS: tuple[str, ...] = (*_SINGLE_TARGET_PROBE_IDS, *CATALOG_CONNECTION_PROBE_IDS)
"""Stable identifiers of all probes."""

HTTP_ONLY_PROBE_IDS: frozenset[str] = frozenset(
    {
        PROBE_HEADER_MISMATCH,
        PROBE_MISSING_PROTOCOL_VERSION,
        PROBE_MISSING_METHOD_HEADER,
        PROBE_RESOURCE_NAME_HEADER_MISMATCH,
        PROBE_PROMPT_NAME_HEADER_MISMATCH,
        PROBE_GET_STREAM_REMOVED,
        PROBE_UNAUTHENTICATED,
        PROBE_SESSION_ID_ECHO,
        PROBE_AUTH_METADATA,
        PROBE_INVALID_TOKEN,
        PROBE_ORIGIN_VALIDATION,
        PROBE_MALFORMED_JSON,
        PROBE_NOTIFICATION_ACCEPTED,
        PROBE_INVALID_REQUEST,
        PROBE_GET_STREAM,
        PROBE_SESSION_DELETE,
        PROBE_QUERY_CREDENTIAL,
        PROBE_HOST_VALIDATION,
        PROBE_LOCAL_BIND,
    }
)
"""Probes whose *subject* is an HTTP construct, so they cannot run over stdio.

Not "probes that happen to use HTTP" — every probe does that over an HTTP
target. These ask questions that only exist in HTTP: required/mirrored request
headers, the removed GET stream and ``Mcp-Session-Id``, the unauthenticated
status and ``WWW-Authenticate`` challenge, RFC 9728/8414 well-known documents,
``Origin`` and ``Host`` validation against DNS rebinding, the interfaces a
local server listens on, raw malformed HTTP request bodies, and the
Streamable HTTP envelope (notification ``202``, the GET stream, session
``DELETE``, invalid JSON-RPC bodies). Over stdio they record
``NOT_APPLICABLE``, which is the honest answer: this probe path cannot send
malformed wire input through the SDK transport.
"""

STDIO_PROBE_IDS: tuple[str, ...] = tuple(p for p in _SINGLE_TARGET_PROBE_IDS if p not in HTTP_ONLY_PROBE_IDS)
"""Probes that run over stdio — the ones judging JSON-RPC, not HTTP."""

_AUTH_DISCOVERY_PROBE_IDS = (PROBE_UNAUTHENTICATED, PROBE_AUTH_METADATA, PROBE_INVALID_TOKEN)
"""Probes that run after the unauthenticated request, because they depend on what it observed."""

_ANONYMOUS_PROBE_IDS = frozenset((*_AUTH_DISCOVERY_PROBE_IDS, PROBE_QUERY_CREDENTIAL))
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
        return {"probe_id": self.probe_id, "outcome": self.outcome.value, "details": report_evidence(self.details)}


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
    final_url: str | None = None
    """URL that answered, after any same-origin redirect the request followed."""

    unobservable: str | None = None
    """Why the body could not be read (``"encoded"``, ``"capped"``, ``"unfinished"``); None when it was.

    The payload is then None.
    """


CLIENT_NAME = "mcpscore"
"""How mcpscore identifies itself to servers, in every lifecycle.

The single source for the legacy handshake's ``clientInfo``, the modern
probes' ``_meta`` clientInfo, and the status-recovery handshake — three
consumers, one constant, so they cannot drift apart. Etiquette: server
operators and gateways segment traffic by client identity, and an auditor
should be as recognizable as a well-behaved User-Agent.
"""


def client_version() -> str:
    """Installed mcpscore version, for clientInfo in every handshake."""
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
        f"{META_PREFIX}clientInfo": {"name": CLIENT_NAME, "version": client_version()},
        f"{META_PREFIX}clientCapabilities": {},
    }


SKILLS_EXTENSION_ID = "io.modelcontextprotocol/skills"


def _skills_meta(protocol_version: str) -> dict[str, Any]:
    """Build the modern ``_meta`` envelope declaring the Skills extension.

    A server may expose skills only to clients that declare it.
    """
    meta = _modern_meta(protocol_version)
    meta[f"{META_PREFIX}clientCapabilities"] = {"extensions": {SKILLS_EXTENSION_ID: {}}}
    return meta


def _request_body(method: str, request_id: int, meta: dict[str, Any], params: dict[str, Any] | None = None) -> dict:
    body_params: dict[str, Any] = dict(params or {})
    body_params["_meta"] = meta
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": body_params}


LEGACY_INITIALIZE_VERSION = next(v for v in reversed(SPEC_VERSIONS) if v.lifecycle is Lifecycle.STATEFUL).version
"""Newest revision with the ``initialize`` handshake; the fallback control speaks it."""


def _legacy_initialize_body(request_id: int) -> dict:
    """Build the ``initialize`` request every stateful-lifecycle client opens with."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": LEGACY_INITIALIZE_VERSION,
            "capabilities": {},
            "clientInfo": {"name": CLIENT_NAME, "version": client_version()},
        },
    }


def _legacy_headers() -> dict[str, str]:
    """Headers of a stateful-lifecycle POST; ``initialize`` needs no version header."""
    return {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


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


def _parse_payload_text(text: str, content_type: str) -> dict[str, Any] | None:
    """Extract the JSON-RPC message from a JSON or SSE response body text."""
    try:
        if "text/event-stream" in content_type:
            for line in text.splitlines():
                if line.startswith("data:"):
                    parsed = json.loads(line[len("data:") :].strip())
                    return parsed if isinstance(parsed, dict) else None
            return None
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


_RPC_READ_LIMIT = 65_536
"""Bytes of a JSON-RPC answer read while waiting for the response before giving up."""


class _StreamDeadline(httpx2.ReadTimeout):
    """No matching JSON-RPC response arrived before the deadline."""

    def __init__(self, request: httpx2.Request) -> None:
        super().__init__("no matching JSON-RPC response before the deadline", request=request)


class _ReadCapReached(Exception):  # noqa: N818 — a signal, not an error condition
    """The answer exceeded ``_RPC_READ_LIMIT`` before the response was found."""


async def _bounded_chunks(response: httpx2.Response, limit: int | None = None) -> AsyncIterator[bytes]:
    """Yield an identity body as received, counting bytes before anything is buffered.

    Callers only use this on a response without content-encoding, so
    ``aiter_bytes`` decodes nothing and yields the chunks as they arrive.
    Raises ``_ReadCapReached`` past ``limit`` (default ``_RPC_READ_LIMIT``).
    """
    cap = _RPC_READ_LIMIT if limit is None else limit
    read = 0
    async for chunk in response.aiter_bytes():
        space = cap - read
        read += len(chunk)
        if read > cap:
            # The allowed prefix may already hold the answer; how the bytes were chunked must not matter.
            if space > 0:
                yield chunk[:space]
            raise _ReadCapReached
        yield chunk


_UTF8_BOM = b"\xef\xbb\xbf"


def _take_lines(buffer: bytearray, skip_lf: bool) -> tuple[list[str], bool]:
    """Remove and decode complete lines; CR, LF and CRLF all end one (WHATWG SSE line rules).

    A CR ends its line at once, so a stream left open after a CR-terminated
    event is never held back. ``skip_lf`` carries a CR at the end of one chunk
    into the next, whose leading LF is then the CRLF's second half. Returns
    the lines and the new ``skip_lf``.
    """
    lines: list[str] = []
    while buffer:
        if skip_lf:
            skip_lf = False
            if buffer[0] == 0x0A:
                del buffer[:1]
                continue
        ends = [i for i in (buffer.find(b"\r"), buffer.find(b"\n")) if i >= 0]
        if not ends:
            break
        end = min(ends)
        lines.append(bytes(buffer[:end]).decode("utf-8", errors="replace"))
        is_cr = buffer[end] == 0x0D
        del buffer[: end + 1]
        skip_lf = is_cr
    return lines, skip_lf


async def _bounded_lines(response: httpx2.Response, limit: int | None = None) -> AsyncIterator[str]:
    """Yield an SSE body's lines, decoded only once complete, without a leading UTF-8 BOM."""
    buffer = bytearray()
    bom_checked = False
    skip_lf = False
    async for chunk in _bounded_chunks(response, limit):
        buffer.extend(chunk)
        if not bom_checked:
            if len(buffer) < len(_UTF8_BOM) and _UTF8_BOM.startswith(bytes(buffer)):
                continue
            if buffer.startswith(_UTF8_BOM):
                del buffer[: len(_UTF8_BOM)]
            bom_checked = True
        lines, skip_lf = _take_lines(buffer, skip_lf)
        for line in lines:
            yield line
    if buffer:
        yield bytes(buffer).decode("utf-8", errors="replace")


async def _read_sse_response(
    response: httpx2.Response, request_id: object, limit: int | None = None
) -> dict[str, Any] | None:
    """Return the first SSE event that answers ``request_id``; raise ``_ReadCapReached`` past the byte cap."""
    data: list[str] = []
    async for line in _bounded_lines(response, limit):
        if line.startswith("data:"):
            data.append(line[len("data:") :].strip())
            continue
        if line or not data:
            continue
        try:
            message = json.loads("\n".join(data))
        except (json.JSONDecodeError, ValueError):
            message = None
        data = []
        if not isinstance(message, dict) or not ("result" in message or "error" in message):
            continue
        if message.get("id") == request_id or (message.get("id") is None and "error" in message):
            return message
    return None


def _parse_payload(response: httpx2.Response) -> dict[str, Any] | None:
    """Extract the JSON-RPC message from a JSON or SSE response body."""
    return _parse_payload_text(response.text, response.headers.get("content-type", ""))


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


def _no_client_auth(anonymous: bool) -> dict[str, Any]:
    """``send`` arguments that stop the client's ``auth`` flow from re-adding credentials to an anonymous request."""
    return {"auth": None} if anonymous else {}


def _strip_credentials(request: httpx2.Request, keep: dict[str, str] | None = None) -> None:
    """Remove the client's ``Authorization`` and cookie-jar credentials from one built request.

    An ``Authorization`` in ``keep`` (one the probe passed for this request) is put back.
    """
    request.headers.pop("Authorization", None)
    request.headers.pop("Cookie", None)
    if keep and "Authorization" in keep:
        request.headers["Authorization"] = keep["Authorization"]


@dataclass(frozen=True)
class _HttpTarget:
    """A probe target reached over HTTP(S)."""

    client: httpx2.AsyncClient
    url: str
    auth_challenge: str | None = None
    """``WWW-Authenticate`` observed by the unauthenticated probe, for discovery that follows it."""

    async def post(
        self,
        body: dict,
        headers: dict[str, str],
        *,
        anonymous: bool = False,
        follow_redirects: bool = True,
        omit_headers: tuple[str, ...] = (),
    ) -> _HttpProbeResponse:
        """POST a probe request, optionally stripping headers from the final request.

        When ``anonymous``, remove any caller-supplied ``Authorization`` header
        and cookies so the probe observes the server's unauthenticated behavior even when a
        token was provided via --token/--header. When ``run_all_probes`` created
        the clients itself, anonymous probes additionally run on a client that
        carries no caller headers at all (see ``_ANONYMOUS_PROBE_IDS``); the pop
        here also covers caller-injected clients whose defaults it cannot
        control. ``follow_redirects`` follows only a redirect that stays on the
        endpoint's origin, the session's own policy (:mod:`mcpscore.redirects`),
        and may be disabled for security checks that must judge the target
        endpoint itself without forwarding caller context even one hop.
        ``omit_headers`` is applied after ``build_request`` merges
        client defaults, so a caller-supplied default cannot accidentally
        restore a header that a negative probe intends to omit. The shared
        client's defaults are never mutated because probes run concurrently.
        """
        request = self.client.build_request("POST", self.url, json=body, headers=headers, timeout=PROBE_TIMEOUT_S)
        if anonymous:
            _strip_credentials(request)
        for header in omit_headers:
            request.headers.pop(header, None)
        response = (
            await send_within_origin(self.client, request, **_no_client_auth(anonymous))
            if follow_redirects
            else await self.client.send(request, follow_redirects=False, **_no_client_auth(anonymous))
        )
        return _HttpProbeResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            payload=_parse_payload(response),
            final_url=str(response.url),
        )

    async def post_rpc(
        self,
        body: dict,
        headers: dict[str, str],
        *,
        follow_redirects: bool = True,
        close_session_on_failure: bool = False,
        cleanup_headers: dict[str, str] | None = None,
        anonymous: bool = False,
        read_limit: int | None = None,
        omit_headers: tuple[str, ...] = (),
    ) -> _HttpProbeResponse:
        """POST one JSON-RPC request and read only until its response arrives.

        The request asks for an identity body; a content-encoded answer is not
        decoded and has no payload. A JSON answer is read whole. An SSE answer
        is read event by event, skipping priming events and notifications,
        until a message carrying the request's ``id`` (or an error with a null
        ``id``), and then closed, so a stream kept open with heartbeats cannot
        stall the probe. Bytes are counted before they are buffered, and the
        exchange shares one deadline. Past the deadline ``_StreamDeadline`` is
        raised, unless an error status already arrived: that answer, like one
        whose body read times out, is returned with ``unobservable="unfinished"``. An answer that is
        content-encoded or exceeds the byte cap is returned with no payload and
        ``unobservable`` set, never as a timeout.
        With ``close_session_on_failure``, a session ID the answer issued is
        closed at the URL that answered before any failure propagates;
        ``cleanup_headers`` are added to that DELETE. With ``anonymous``, the
        client's ``Authorization`` and cookies are removed from the request and its
        cleanup; an ``Authorization`` passed in ``headers`` is kept. ``read_limit`` replaces the default byte cap.
        ``omit_headers`` are removed after the client's defaults are merged, as in :meth:`post`.
        """
        request = self.client.build_request(
            "POST",
            self.url,
            json=body,
            headers={**headers, "Accept-Encoding": "identity"},
            timeout=PROBE_TIMEOUT_S,
        )
        if anonymous:
            _strip_credentials(request, headers)
        for header in omit_headers:
            request.headers.pop(header, None)
        response: httpx2.Response | None = None
        try:
            async with asyncio.timeout(PROBE_TIMEOUT_S):
                response = (
                    await send_within_origin(self.client, request, stream=True, **_no_client_auth(anonymous))
                    if follow_redirects
                    else await self.client.send(
                        request, follow_redirects=False, stream=True, **_no_client_auth(anonymous)
                    )
                )
                content_type = response.headers.get("content-type", "")
                encoding = response.headers.get("content-encoding", "").strip().lower()
                payload: dict[str, Any] | None = None
                unobservable: str | None = None
                try:
                    if encoding not in ("", "identity"):
                        unobservable = "encoded"
                    elif "text/event-stream" in content_type.lower():
                        payload = await _read_sse_response(response, body.get("id"), read_limit)
                    else:
                        raw = b"".join([chunk async for chunk in _bounded_chunks(response, read_limit)])
                        payload = _parse_payload_text(raw.decode("utf-8", errors="replace"), content_type)
                except _ReadCapReached:
                    unobservable = "capped"
                return _HttpProbeResponse(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    payload=payload,
                    final_url=str(response.url),
                    unobservable=unobservable,
                )
        except Exception as exc:
            if response is not None:
                await response.aclose()
                if close_session_on_failure:
                    answered = replace(self, url=str(response.url))
                    issued = _HttpProbeResponse(
                        status_code=response.status_code, headers=dict(response.headers), payload=None
                    )
                    await answered.end_session(issued, cleanup_headers, anonymous=anonymous)
            timed_out = isinstance(exc, (TimeoutError, httpx2.ReadTimeout))
            if timed_out and response is not None and response.status_code >= 400:
                # The status already arrived and says the request was refused; only the body is missing.
                return _HttpProbeResponse(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    payload=None,
                    final_url=str(response.url),
                    unobservable="unfinished",
                )
            if isinstance(exc, TimeoutError):
                raise _StreamDeadline(request) from exc
            raise
        finally:
            if response is not None:
                await response.aclose()

    async def post_raw(
        self, content: bytes, headers: dict[str, str], *, body_limit: Callable[[int], int] | None = None
    ) -> tuple[_HttpProbeResponse, str | None, str | None]:
        """POST an intentionally invalid raw body without following redirects.

        Only HTTP-specific negative probes use this path. Redirects stay off so
        caller-supplied credentials cannot leave the audited endpoint while
        mcpscore is sending malformed input.

        Memory is bounded against a hostile server, including a compression
        bomb. The request asks for ``Accept-Encoding: identity`` and the body
        is read **only when the response carries no content-encoding** — so
        ``aiter_bytes`` has nothing to decode and cannot inflate a chunk. Each
        chunk is appended only up to the remaining ``_RAW_BODY_SCAN_LIMIT``
        capacity, so a single large chunk cannot overshoot the cap. If the
        server compresses anyway (ignoring the identity request), the body is
        never fed to the decoder — that is where the bomb would inflate — and
        is reported unobservable.

        ``body_limit`` maps the status to the bytes worth reading, for a caller
        whose verdict needs less than the full body: 0 skips the body (an open
        SSE stream is never drained), 1 tells empty from non-empty.

        Returns ``(response, body_text, unobservable_reason)``. ``body_text``
        is the bounded leak surface for ``security_error_data_leak`` (a
        mishandled parse dumps a stack trace or path into a non-JSON body);
        it is ``None`` when the reason is ``"encoded"``. ``unobservable_reason``
        is ``None`` (fully read), ``"truncated"`` (body exceeded the cap — an
        unparsable prefix is not a protocol verdict), or ``"encoded"`` (server
        content-encoded despite the identity request; not decoded).
        """
        probe_headers = {**headers, "Accept-Encoding": "identity"}
        async with self.client.stream(
            "POST",
            self.url,
            content=content,
            headers=probe_headers,
            timeout=PROBE_TIMEOUT_S,
            follow_redirects=False,
        ) as response:
            status_code = response.status_code
            response_headers = dict(response.headers)
            encoding = response.headers.get("content-encoding", "").strip().lower()
            encoded = encoding not in ("", "identity")
            body = bytearray()
            truncated = False
            limit = _RAW_BODY_SCAN_LIMIT if body_limit is None else body_limit(status_code)
            if limit == 0:
                return (
                    _HttpProbeResponse(status_code=status_code, headers=response_headers, payload=None),
                    None,
                    "unread",
                )
            if not encoded:
                # No content-encoding, so aiter_bytes yields identity bytes and
                # performs no decompression — bounding the chunks bounds peak
                # memory. An encoded body is deliberately never iterated (the
                # `async with` closes it without decoding).
                async for chunk in response.aiter_bytes():
                    space = limit - len(body)
                    if len(chunk) > space:
                        body.extend(chunk[:space])
                        truncated = True
                        break
                    body.extend(chunk)
                    if body_limit is not None and len(body) >= limit:
                        # The caller needs no more; waiting for the next chunk could block on an open stream.
                        truncated = True
                        break
        if encoded:
            return (
                _HttpProbeResponse(status_code=status_code, headers=response_headers, payload=None),
                None,
                "encoded",
            )
        text = bytes(body).decode("utf-8", errors="replace")
        return (
            _HttpProbeResponse(
                status_code=status_code,
                headers=response_headers,
                payload=_parse_payload_text(text, response_headers.get("content-type", "")),
            ),
            text,
            "truncated" if truncated else None,
        )

    async def end_session(
        self, response: _HttpProbeResponse, extra_headers: dict[str, str] | None = None, *, anonymous: bool = False
    ) -> None:
        """Best-effort DELETE of a session a legacy ``initialize`` opened; never raises.

        Carries the negotiated ``MCP-Protocol-Version`` (a MUST on every request
        after ``initialize``) and no ``Origin``, so a conforming server has no
        reason to refuse the cleanup. ``extra_headers`` carry a per-request
        credential the session was opened with; ``anonymous`` drops the client's
        ``Authorization`` and cookies for a session opened without them. The answer is
        closed once its headers arrive, and the whole exchange shares one deadline.
        """
        session_id = next((v for k, v in response.headers.items() if k.lower() == "mcp-session-id"), None)
        if not session_id:
            return
        negotiated = (response.result or {}).get("protocolVersion")
        headers = {
            **(extra_headers or {}),
            "Mcp-Session-Id": session_id,
            "MCP-Protocol-Version": negotiated if isinstance(negotiated, str) else LEGACY_INITIALIZE_VERSION,
        }
        try:
            request = self.client.build_request("DELETE", self.url, headers=headers, timeout=PROBE_TIMEOUT_S)
            request.headers.pop("Origin", None)
            if anonymous:
                _strip_credentials(request, extra_headers)
            async with asyncio.timeout(PROBE_TIMEOUT_S):
                answer = await self.client.send(
                    request, follow_redirects=False, stream=True, **_no_client_auth(anonymous)
                )
                await answer.aclose()
        except Exception:  # noqa: BLE001 — courtesy only; the observation is already made
            return

    async def get_status(self, headers: dict[str, str]) -> _HttpProbeResponse:
        """GET the endpoint and close without consuming a possible legacy SSE stream."""
        return await self.request_status("GET", headers, wait_s=GET_STREAM_TIMEOUT_S)

    async def request_status(
        self, method: str, headers: dict[str, str], *, wait_s: float = PROBE_TIMEOUT_S
    ) -> _HttpProbeResponse:
        """Send a bodiless request and close without consuming the response body."""
        async with self.client.stream(
            method,
            self.url,
            headers=headers,
            timeout=wait_s,
            follow_redirects=False,
        ) as response:
            return _HttpProbeResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                payload=None,
            )


@dataclass(frozen=True)
class _StdioTarget:
    """A probe target reached through the SDK's cross-platform stdio transport.

    Each target owns one sibling process, separate from the audit's SDK session
    that has already sent ``initialize`` and pinned its connection to the legacy
    lifecycle. The probe suite reuses its primary target for all single-target
    probes and starts one additional target for the connection-independence
    comparisons. This avoids starting the audited command once per probe while
    still providing two genuinely independent connections.
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
        _request_body("server/discover", 1, _skills_meta(target_version)),
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
    # Keep malformed result objects for sanitized catalog diagnostics. Payloads
    # are excluded from probe serialization; the observed outcome is unchanged.
    return ProbeResult(PROBE_STATELESS_LIST, ProbeOutcome.UNSUPPORTED, details, payload=result)


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


def _header_validation_result(probe_id: str, response: _HttpProbeResponse) -> ProbeResult:
    """Classify one required-header failure without misreporting an unobservable request."""
    details = _base_details(response)
    if response.status_code in AUTH_GATED_STATUSES:
        details["reason"] = "request is access-controlled; header validation not observable"
        return ProbeResult(probe_id, ProbeOutcome.NOT_APPLICABLE, details)
    correct = response.status_code == 400 and response.error_code == ERROR_HEADER_MISMATCH
    return ProbeResult(probe_id, ProbeOutcome.SUPPORTED if correct else ProbeOutcome.UNSUPPORTED, details)


async def _probe_missing_protocol_version(target: _HttpTarget) -> ProbeResult:
    """Omit the required ``MCP-Protocol-Version`` header from a harmless list request."""
    target_version = _target_version()
    headers = _request_headers(target_version, "server/discover")
    del headers["MCP-Protocol-Version"]
    response = await target.post(
        _request_body("server/discover", 19, _modern_meta(target_version)),
        headers,
        follow_redirects=False,
        omit_headers=("MCP-Protocol-Version",),
    )
    return _header_validation_result(PROBE_MISSING_PROTOCOL_VERSION, response)


async def _probe_missing_method_header(target: _HttpTarget) -> ProbeResult:
    """Omit the required ``Mcp-Method`` header from a harmless list request."""
    target_version = _target_version()
    headers = _request_headers(target_version, "server/discover")
    del headers["Mcp-Method"]
    response = await target.post(
        _request_body("server/discover", 20, _modern_meta(target_version)),
        headers,
        follow_redirects=False,
        omit_headers=("Mcp-Method",),
    )
    return _header_validation_result(PROBE_MISSING_METHOD_HEADER, response)


async def _probe_name_header_mismatch(
    target: _HttpTarget,
    *,
    method: str,
    request_id: int,
    params: dict[str, Any],
    name: str,
    probe_id: str,
) -> ProbeResult:
    """Prove an optional named method exists, then contradict its Mcp-Name header."""
    target_version = _target_version()
    body = _request_body(method, request_id, _modern_meta(target_version), params=params)
    control = await target.post(
        body,
        _request_headers(target_version, method, name=name),
        follow_redirects=False,
    )
    if control.status_code in AUTH_GATED_STATUSES:
        details = _base_details(control)
        details["reason"] = "control request is access-controlled; header validation not observable"
        return ProbeResult(probe_id, ProbeOutcome.NOT_APPLICABLE, details)
    if control.error_code == ERROR_METHOD_NOT_FOUND:
        details = _base_details(control)
        details["reason"] = "optional request method is not implemented"
        return ProbeResult(probe_id, ProbeOutcome.NOT_APPLICABLE, details)

    response = await target.post(
        body,
        _request_headers(target_version, method, name=f"{name}-mismatch"),
        follow_redirects=False,
    )
    result = _header_validation_result(probe_id, response)
    return ProbeResult(
        result.probe_id,
        result.outcome,
        {"control_http_status": control.status_code, "control_error_code": control.error_code, **result.details},
    )


async def _probe_resource_name_header_mismatch(target: _HttpTarget) -> ProbeResult:
    """Contradict ``resources/read``'s body URI in ``Mcp-Name`` without reading a real resource."""
    return await _probe_name_header_mismatch(
        target,
        method="resources/read",
        request_id=21,
        params={"uri": MISSING_RESOURCE_URI},
        name=MISSING_RESOURCE_URI,
        probe_id=PROBE_RESOURCE_NAME_HEADER_MISMATCH,
    )


async def _probe_prompt_name_header_mismatch(target: _HttpTarget) -> ProbeResult:
    """Contradict a fabricated ``prompts/get`` name in ``Mcp-Name`` without resolving a real prompt."""
    prompt_name = "mcpscore-does-not-exist"
    return await _probe_name_header_mismatch(
        target,
        method="prompts/get",
        request_id=22,
        params={"name": prompt_name},
        name=prompt_name,
        probe_id=PROBE_PROMPT_NAME_HEADER_MISMATCH,
    )


async def _probe_get_stream_removed(target: _HttpTarget) -> ProbeResult:
    """Verify that the removed standalone GET stream receives HTTP 405."""
    response = await target.get_status({"Accept": "text/event-stream"})
    details = _base_details(response)
    if response.status_code in AUTH_GATED_STATUSES:
        details["reason"] = "request is access-controlled; GET handling not observable"
        return ProbeResult(PROBE_GET_STREAM_REMOVED, ProbeOutcome.NOT_APPLICABLE, details)
    outcome = ProbeOutcome.SUPPORTED if response.status_code == 405 else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_GET_STREAM_REMOVED, outcome, details)


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


async def _probe_invalid_cursor(
    target: _ProbeTarget,
    *,
    method: str,
    request_id: int,
    probe_id: str,
) -> ProbeResult:
    """Send a fabricated opaque cursor and require Invalid params (-32602)."""
    target_version = _target_version()
    cursor = f"{INVALID_CURSOR_PREFIX}{uuid4().hex}"
    response = await target.post(
        _request_body(method, request_id, _modern_meta(target_version), params={"cursor": cursor}),
        _request_headers(target_version, method),
    )
    details = _base_details(response)
    item_key = {
        "tools/list": "tools",
        "resources/list": "resources",
        "resources/templates/list": "resourceTemplates",
        "prompts/list": "prompts",
    }[method]
    if response.error is not None:
        details["response_kind"] = "error"
    elif response.result is not None and isinstance(response.result.get(item_key), list):
        details["response_kind"] = "page"
    else:
        details["response_kind"] = "unexpected_response"
    if response.status_code in AUTH_GATED_STATUSES:
        details["reason"] = "request is access-controlled; cursor validation not observable"
        return ProbeResult(probe_id, ProbeOutcome.NOT_APPLICABLE, details)
    if method == "resources/templates/list" and response.error_code == ERROR_METHOD_NOT_FOUND:
        details["reason"] = "optional resource-template listing is not implemented"
        return ProbeResult(probe_id, ProbeOutcome.NOT_APPLICABLE, details)
    outcome = ProbeOutcome.SUPPORTED if response.error_code == ERROR_INVALID_PARAMS else ProbeOutcome.UNSUPPORTED
    return ProbeResult(probe_id, outcome, details)


async def _probe_tools_invalid_cursor(target: _ProbeTarget) -> ProbeResult:
    return await _probe_invalid_cursor(
        target,
        method="tools/list",
        request_id=14,
        probe_id=PROBE_TOOLS_INVALID_CURSOR,
    )


async def _probe_resources_invalid_cursor(target: _ProbeTarget) -> ProbeResult:
    return await _probe_invalid_cursor(
        target,
        method="resources/list",
        request_id=15,
        probe_id=PROBE_RESOURCES_INVALID_CURSOR,
    )


async def _probe_resource_templates_invalid_cursor(target: _ProbeTarget) -> ProbeResult:
    return await _probe_invalid_cursor(
        target,
        method="resources/templates/list",
        request_id=16,
        probe_id=PROBE_RESOURCE_TEMPLATES_INVALID_CURSOR,
    )


async def _probe_prompts_invalid_cursor(target: _ProbeTarget) -> ProbeResult:
    return await _probe_invalid_cursor(
        target,
        method="prompts/list",
        request_id=17,
        probe_id=PROBE_PROMPTS_INVALID_CURSOR,
    )


async def _traverse_cache_scope_surface(
    target: _ProbeTarget,
    *,
    target_version: str,
    method: str,
    item_key: str,
    deadline: float,
    request_id_base: int,
) -> tuple[dict[str, Any], bool]:
    """Collect bounded wire-level cache scopes for one modern list surface."""
    cursor: str | None = None
    seen_cursors: set[str] = set()
    cache_scopes: list[Any] = []
    complete = False
    for page_number in range(PAGINATION_PROBE_MAX_PAGES):
        remaining = max(deadline - time.monotonic(), 0)
        if remaining == 0:
            raise TimeoutError
        params = {"cursor": cursor} if cursor is not None else None
        response = await asyncio.wait_for(
            target.post(
                _request_body(
                    method,
                    request_id_base + page_number,
                    _modern_meta(target_version),
                    params=params,
                ),
                _request_headers(target_version, method),
            ),
            timeout=remaining,
        )
        result = response.result
        if result is None or not isinstance(result.get(item_key), list):
            if method == "resources/templates/list" and response.error_code == ERROR_METHOD_NOT_FOUND:
                return {"implemented": False}, False
            return {
                "implemented": True,
                "complete": False,
                "pages": len(cache_scopes),
                "error_code": response.error_code,
            }, True

        cache_scopes.append(result.get("cacheScope"))
        next_cursor = result.get("nextCursor")
        if next_cursor is None:
            complete = True
            break
        if not isinstance(next_cursor, str) or next_cursor in seen_cursors:
            break
        seen_cursors.add(next_cursor)
        cursor = next_cursor

    observation = {
        "implemented": True,
        "complete": complete,
        "pages": len(cache_scopes),
        "cache_scopes": cache_scopes,
    }
    return observation, not complete


async def _probe_pagination_cache_scope(target: _ProbeTarget) -> ProbeResult:
    """Traverse declared modern list surfaces and compare real wire cache scopes.

    The SDK model defaults an absent ``cacheScope`` to ``private``, so this
    requirement must be observed below the SDK layer. A fresh discover request
    identifies declared surfaces; each traversal is read-only and shares one
    total deadline and the normal per-request timeout.
    """
    target_version = _target_version()
    discover = await target.post(
        _request_body("server/discover", 18, _modern_meta(target_version)),
        _request_headers(target_version, "server/discover"),
    )
    capabilities = discover.result.get("capabilities") if discover.result is not None else None
    if not isinstance(capabilities, dict):
        return ProbeResult(
            PROBE_PAGINATION_CACHE_SCOPE,
            ProbeOutcome.NOT_APPLICABLE,
            {"reason": "modern declared list capabilities were not observable"},
        )

    surfaces: list[tuple[str, str, str]] = []
    if capabilities.get("tools") is not None:
        surfaces.append(("tools", "tools/list", "tools"))
    if capabilities.get("resources") is not None:
        surfaces.extend(
            (
                ("resources", "resources/list", "resources"),
                ("resource_templates", "resources/templates/list", "resourceTemplates"),
            )
        )
    if capabilities.get("prompts") is not None:
        surfaces.append(("prompts", "prompts/list", "prompts"))
    if not surfaces:
        return ProbeResult(
            PROBE_PAGINATION_CACHE_SCOPE,
            ProbeOutcome.NOT_APPLICABLE,
            {"reason": "server declares no paginated list capabilities"},
        )

    deadline = time.monotonic() + PAGINATION_PROBE_TIMEOUT_S
    observations: dict[str, dict[str, Any]] = {}
    incomplete = False
    for surface_index, (surface, method, item_key) in enumerate(surfaces):
        observation, surface_incomplete = await _traverse_cache_scope_surface(
            target,
            target_version=target_version,
            method=method,
            item_key=item_key,
            deadline=deadline,
            request_id_base=1900 + surface_index * PAGINATION_PROBE_MAX_PAGES,
        )
        observations[surface] = observation
        incomplete = incomplete or surface_incomplete

    paginated = {
        surface: observation
        for surface, observation in observations.items()
        if observation.get("complete") is True and observation.get("pages", 0) >= 2
    }
    details: dict[str, Any] = {"surfaces": observations}
    inconsistent = [
        surface
        for surface, observation in paginated.items()
        if not observation["cache_scopes"]
        or observation["cache_scopes"][0] not in ("public", "private")
        or any(scope != observation["cache_scopes"][0] for scope in observation["cache_scopes"][1:])
    ]
    details["inconsistent_surfaces"] = inconsistent
    if inconsistent:
        return ProbeResult(PROBE_PAGINATION_CACHE_SCOPE, ProbeOutcome.UNSUPPORTED, details)
    if incomplete:
        details["reason"] = "at least one declared list traversal did not complete"
        return ProbeResult(PROBE_PAGINATION_CACHE_SCOPE, ProbeOutcome.ERROR, details)
    if not paginated:
        details["reason"] = "no declared list surface returned multiple pages"
        return ProbeResult(PROBE_PAGINATION_CACHE_SCOPE, ProbeOutcome.NOT_APPLICABLE, details)
    return ProbeResult(PROBE_PAGINATION_CACHE_SCOPE, ProbeOutcome.SUPPORTED, details)


_CATALOG_CONNECTION_SURFACES: tuple[tuple[str, str, str, str], ...] = (
    ("tools", "tools/list", "tools", PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT),
    ("resources", "resources/list", "resources", PROBE_RESOURCES_CATALOG_CONNECTION_INDEPENDENT),
    ("prompts", "prompts/list", "prompts", PROBE_PROMPTS_CATALOG_CONNECTION_INDEPENDENT),
)
"""Capability, method, result key, and probe ID for connection-stable catalogs."""


async def _collect_catalog_identities(
    target: _ProbeTarget,
    *,
    target_version: str,
    method: str,
    item_key: str,
    request_id_base: int,
    unfinished_pages: list[int] | None = None,
) -> frozenset[str]:
    """Collect one complete catalog as an order-independent identity set.

    Pages without ``resultType: "complete"`` (SEP-2322) are appended to *unfinished_pages* when it is given.
    """
    identities: set[str] = set()
    seen_cursors: set[str] = set()
    cursor: str | None = None
    deadline = time.monotonic() + PAGINATION_PROBE_TIMEOUT_S
    identity_key = "uri" if item_key == "resources" else "name"

    for page_number in range(PAGINATION_PROBE_MAX_PAGES):
        remaining = max(deadline - time.monotonic(), 0)
        if remaining == 0:
            raise TimeoutError
        params = {"cursor": cursor} if cursor is not None else None
        response = await asyncio.wait_for(
            target.post(
                _request_body(
                    method,
                    request_id_base + page_number,
                    _modern_meta(target_version),
                    params=params,
                ),
                _request_headers(target_version, method),
            ),
            timeout=remaining,
        )
        result = response.result
        if result is None:
            msg = f"{method} did not return a result object"
            raise TypeError(msg)
        if unfinished_pages is not None and result.get("resultType") != "complete":
            unfinished_pages.append(page_number)
        items = result.get(item_key)
        if not isinstance(items, list):
            msg = f"{method} did not return a {item_key} list"
            raise TypeError(msg)
        for item in items:
            identity = item.get(identity_key) if isinstance(item, dict) else None
            if not isinstance(identity, str) or not identity:
                msg = f"{method} returned an item without a valid {identity_key}"
                raise ValueError(msg)
            identities.add(identity)

        next_cursor = result.get("nextCursor")
        if next_cursor is None:
            return frozenset(identities)
        if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
            msg = f"{method} returned an invalid or repeated cursor"
            raise ValueError(msg)
        seen_cursors.add(next_cursor)
        cursor = next_cursor

    msg = f"{method} exceeded the {PAGINATION_PROBE_MAX_PAGES}-page safety bound"
    raise ValueError(msg)


async def _probe_catalog_connection_independence(
    first: _ProbeTarget,
    second: _ProbeTarget,
    failures: _ProbeFailureLog | None = None,
) -> dict[str, ProbeResult]:
    """Compare complete modern catalogs over two independent connections.

    Transport errors become ``ERROR`` results and are recorded in ``failures`` when given.
    """
    target_version = _target_version()

    async def gather_pair(first_awaitable: Any, second_awaitable: Any) -> tuple[Any, Any]:
        """Run work on independent targets, always draining a failed sibling."""
        first_task = asyncio.create_task(first_awaitable)
        second_task = asyncio.create_task(second_awaitable)
        try:
            return await asyncio.gather(first_task, second_task)
        except BaseException:
            first_task.cancel()
            second_task.cancel()
            await asyncio.gather(first_task, second_task, return_exceptions=True)
            raise

    try:
        first_discover, second_discover = await gather_pair(
            first.post(
                _request_body("server/discover", 2100, _modern_meta(target_version)),
                _request_headers(target_version, "server/discover"),
            ),
            second.post(
                _request_body("server/discover", 2101, _modern_meta(target_version)),
                _request_headers(target_version, "server/discover"),
            ),
        )
    except Exception as exc:  # noqa: BLE001 — probe transport failures are data
        if failures is not None:
            for probe_id in CATALOG_CONNECTION_PROBE_IDS:
                failures.record(probe_id, exc)
        return {
            probe_id: ProbeResult(
                probe_id,
                ProbeOutcome.ERROR,
                {"exception": type(exc).__name__, "reason": str(exc)},
            )
            for probe_id in CATALOG_CONNECTION_PROBE_IDS
        }
    first_capabilities = first_discover.result.get("capabilities") if first_discover.result is not None else None
    second_capabilities = second_discover.result.get("capabilities") if second_discover.result is not None else None
    if not isinstance(first_capabilities, dict) or not isinstance(second_capabilities, dict):
        return not_applicable_results(
            "modern declared catalog capabilities were not observable on both connections",
            CATALOG_CONNECTION_PROBE_IDS,
        )

    async def compare(
        surface_index: int,
        capability: str,
        method: str,
        item_key: str,
        probe_id: str,
    ) -> ProbeResult:
        first_declares = first_capabilities.get(capability) is not None
        second_declares = second_capabilities.get(capability) is not None
        if not first_declares and not second_declares:
            return ProbeResult(
                probe_id,
                ProbeOutcome.NOT_APPLICABLE,
                {"reason": f"server does not declare the {capability} capability"},
            )
        if first_declares != second_declares:
            return ProbeResult(
                probe_id,
                ProbeOutcome.UNSUPPORTED,
                {
                    "first_declares_capability": first_declares,
                    "second_declares_capability": second_declares,
                    "reason": f"{capability} capability varies across client connections",
                },
            )
        unfinished_pages: list[int] = []
        try:
            first_ids, second_ids = await gather_pair(
                _collect_catalog_identities(
                    first,
                    target_version=target_version,
                    method=method,
                    item_key=item_key,
                    request_id_base=2200 + surface_index * 300,
                    unfinished_pages=unfinished_pages,
                ),
                _collect_catalog_identities(
                    second,
                    target_version=target_version,
                    method=method,
                    item_key=item_key,
                    request_id_base=2300 + surface_index * 300,
                    unfinished_pages=unfinished_pages,
                ),
            )
        except Exception as exc:  # noqa: BLE001 — incomplete evidence must skip, never fail
            if failures is not None:
                failures.record(probe_id, exc)
            return ProbeResult(
                probe_id,
                ProbeOutcome.ERROR,
                {
                    "exception": type(exc).__name__,
                    "reason": str(exc),
                    "first_declares_capability": True,
                    "second_declares_capability": True,
                },
            )

        only_first = sorted(first_ids - second_ids)
        only_second = sorted(second_ids - first_ids)
        outcome = ProbeOutcome.SUPPORTED if not only_first and not only_second else ProbeOutcome.UNSUPPORTED
        return ProbeResult(
            probe_id,
            outcome,
            {
                "first_count": len(first_ids),
                "second_count": len(second_ids),
                "results_complete": not unfinished_pages,
                "only_first": only_first[:10],
                "only_second": only_second[:10],
                "differences_truncated": len(only_first) > 10 or len(only_second) > 10,
            },
        )

    # A stdio target has one response stream. Keep surfaces sequential so two
    # readers never race to consume a response intended for the other request.
    results = [await compare(index, *surface) for index, surface in enumerate(_CATALOG_CONNECTION_SURFACES)]
    return {result.probe_id: result for result in results}


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


def _token_refused(response: _HttpProbeResponse) -> bool:
    """Whether the answer refuses the bearer token: 401/403, or any 4xx with an RFC 6750 ``invalid_token`` challenge."""
    if response.status_code in AUTH_GATED_STATUSES:
        return True
    challenge = response.headers.get("www-authenticate") or ""
    return 400 <= response.status_code < 500 and www_authenticate_param(challenge, "error") == "invalid_token"


async def _probe_invalid_token(target: _HttpTarget) -> ProbeResult:
    """Send the unauthenticated request again with a fabricated bearer token, then a legacy ``initialize``.

    SUPPORTED: the token is refused (:func:`_token_refused`). UNSUPPORTED: a 2xx
    answer, so the token got past the auth check. Any other 4xx says nothing,
    because a legacy server past the check refuses the sessionless request too;
    the ``initialize`` then decides, but only when the same ``initialize`` without a
    token is refused: a server may leave the handshake public and guard the reads.
    Redirects, timeouts, rate limits and 5xx are NOT_APPLICABLE. Redirects are not
    followed, so the answer is the endpoint's own. Every request is a read, read only
    up to its response; a session opened for one is closed with the token it carried.
    """
    target_version = _target_version()
    token = {"Authorization": f"Bearer {INVALID_TOKEN_PREFIX}{uuid4().hex}"}
    attempts = (
        (
            "tools/list",
            _request_body("tools/list", 7, _modern_meta(target_version)),
            _request_headers(target_version, "tools/list"),
        ),
        ("initialize", _legacy_initialize_body(8), _legacy_headers()),
    )
    details: dict[str, Any] = {}
    for method, body, headers in attempts:
        response = await target.post_rpc(
            body,
            {**headers, **token},
            follow_redirects=False,
            close_session_on_failure=True,
            cleanup_headers=token,
            anonymous=True,
        )
        await target.end_session(response, token, anonymous=True)
        details = {**_base_details(response), "method": method}
        status = response.status_code
        if _token_refused(response):
            details["www_authenticate"] = response.headers.get("www-authenticate")
            return ProbeResult(PROBE_INVALID_TOKEN, ProbeOutcome.SUPPORTED, details)
        if 200 <= status < 300:
            if method == "initialize":
                return await _judge_served_initialize(target, details)
            return ProbeResult(PROBE_INVALID_TOKEN, ProbeOutcome.UNSUPPORTED, details)
        redirected = _redirected(PROBE_INVALID_TOKEN, status, details)
        if redirected is not None:
            return redirected
        if not 400 <= status < 500 or status in (408, 429):
            break
    details["reason"] = f"HTTP {details.get('http_status')} does not show whether the token was accepted"
    return ProbeResult(PROBE_INVALID_TOKEN, ProbeOutcome.NOT_APPLICABLE, details)


async def _judge_served_initialize(target: _HttpTarget, details: dict[str, Any]) -> ProbeResult:
    """Judge an ``initialize`` served with the fabricated token against the same request without one."""
    control = await target.post_rpc(
        _legacy_initialize_body(9),
        _legacy_headers(),
        follow_redirects=False,
        close_session_on_failure=True,
        anonymous=True,
    )
    await target.end_session(control, anonymous=True)
    details["anonymous_http_status"] = control.status_code
    if _token_refused(control):
        return ProbeResult(PROBE_INVALID_TOKEN, ProbeOutcome.UNSUPPORTED, details)
    details["reason"] = f"initialize without a token gets HTTP {control.status_code}, so serving it proves nothing"
    return ProbeResult(PROBE_INVALID_TOKEN, ProbeOutcome.NOT_APPLICABLE, details)


async def _probe_query_credential(target: _HttpTarget) -> ProbeResult:
    """Ask whether the server takes its credential from the URL's query string.

    Runs only when the audited URL carries a credential parameter
    (:func:`mcpscore.url_credentials.credential_query_params`); otherwise NOT_APPLICABLE
    with no request sent. The same anonymous ``tools/list`` goes to the URL as given and
    to the URL without its credential parameters, then a legacy ``initialize`` when the
    request with the credential got a plain 4xx (a missing session). Served means a 2xx
    carrying a JSON-RPC result. UNSUPPORTED: the first is served and the second refused
    (:func:`_token_refused`), so the server authenticates from the query. SUPPORTED: both
    ``tools/list`` requests are served, so the credential is not needed; two served
    handshakes prove nothing, since a server may keep ``initialize`` public. Anything
    else is NOT_APPLICABLE. Each request reads only up to its response; a session opened
    is closed. Details name the parameters, never their values.
    """
    names = credential_query_params(urlsplit(target.url).query)
    if not names:
        return ProbeResult(
            PROBE_QUERY_CREDENTIAL,
            ProbeOutcome.NOT_APPLICABLE,
            {"reason": "the URL carries no credential in its query"},
        )
    stripped_target = replace(target, url=without_credential_params(target.url))
    target_version = _target_version()
    attempts = (
        (
            "tools/list",
            _request_body("tools/list", 7, _modern_meta(target_version)),
            _request_headers(target_version, "tools/list"),
        ),
        ("initialize", _legacy_initialize_body(8), _legacy_headers()),
    )
    details: dict[str, Any] = {"credential_params": [name[:40] for name in names[:5]]}
    for method, body, headers in attempts:
        responses: list[_HttpProbeResponse] = []
        for each in (target, stripped_target):
            response = await each.post_rpc(
                body, headers, follow_redirects=False, close_session_on_failure=True, anonymous=True
            )
            await each.end_session(response, anonymous=True)
            responses.append(response)
        statuses = [response.status_code for response in responses]
        given, stripped = statuses
        details |= {"method": method, "http_status": given, "without_credential_http_status": stripped}
        served = [200 <= response.status_code < 300 and response.result is not None for response in responses]
        if served[0] and _token_refused(responses[1]):
            return ProbeResult(PROBE_QUERY_CREDENTIAL, ProbeOutcome.UNSUPPORTED, details)
        # A served initialize proves only the handshake, which a server may leave public while it guards reads.
        if method == "tools/list" and all(served):
            return ProbeResult(PROBE_QUERY_CREDENTIAL, ProbeOutcome.SUPPORTED, details)
        # A legacy server refuses the sessionless request with a plain 4xx; its initialize may still decide.
        plain_4xx = 400 <= given < 500 and given not in (408, 429) and not _token_refused(responses[0])
        if not (plain_4xx and 400 <= stripped < 500 and stripped not in (408, 429)):
            break
    details["reason"] = (
        f"HTTP {details['http_status']} with the credential and {details['without_credential_http_status']} "
        "without it do not show whether the server reads it"
    )
    return ProbeResult(PROBE_QUERY_CREDENTIAL, ProbeOutcome.NOT_APPLICABLE, details)


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
    """GET a public well-known JSON document, stripping any caller Authorization and cookies.

    Returns (http_status, parsed_dict_or_None). Auth-discovery documents (RFC
    9728, RFC 8414) are public — and RFC 8414 discovery can leave the server's
    origin for the authorization server's — so no caller credential may be
    sent. When ``run_all_probes`` created the clients, these fetches already
    run on a header-free client (``_ANONYMOUS_PROBE_IDS``); the pop here also
    covers caller-injected clients.
    """
    request = client.build_request("GET", url, headers={"Accept": "application/json"}, timeout=PROBE_TIMEOUT_S)
    _strip_credentials(request)
    response = await send_within_origin(client, request, auth=None)
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
    """Whether a value is an http(s) URL string; the scheme is case-insensitive."""
    return isinstance(value, str) and value.lower().startswith(("https://", "http://"))


_LOCAL_HOSTNAMES = ("localhost",)
_LOCAL_HOSTNAME_SUFFIXES = (".localhost", ".local", ".internal")


def _is_local_host(host: str | None) -> bool:
    """Whether a host is a loopback/private literal IP or an internal-only name (no DNS lookup)."""
    if not host:
        return False
    lowered = host.lower().rstrip(".")
    if lowered in _LOCAL_HOSTNAMES or lowered.endswith(_LOCAL_HOSTNAME_SUFFIXES):
        return True
    try:
        return not _is_global_ip(ipaddress.ip_address(lowered.strip("[]")))
    except ValueError:
        return False


def _is_global_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Whether an address is globally routable, judging an IPv4-mapped IPv6 address by its IPv4 form."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global


_DNS_TIMEOUT_SECONDS = 5.0


async def _resolve_host(host: str) -> list[str] | None:
    """Return the addresses a host name resolves to: empty when it does not resolve, None when the lookup times out."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=_DNS_TIMEOUT_SECONDS
        )
    except TimeoutError:
        return None
    except (OSError, UnicodeError):
        return []
    return [str(info[4][0]) for info in infos]


_HostClass = Literal["public", "private", "mixed", "unresolved", "timeout"]
_DNS_TIMEOUT_ERROR = "DNSTimeout"


async def _classify_host(host: str | None) -> _HostClass:
    """Classify a host: literals and internal names without DNS, other names by every resolved address.

    A name is public when every address it resolves to is globally routable,
    private when none is, and mixed otherwise.
    """
    if not host:
        return "unresolved"
    if _is_local_host(host):
        return "private"
    try:
        return "public" if _is_global_ip(ipaddress.ip_address(host.strip("[]"))) else "private"
    except ValueError:
        pass
    resolved = await _resolve_host(host)
    if resolved is None:
        return "timeout"
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for address in resolved:
        try:
            addresses.append(ipaddress.ip_address(address.split("%", 1)[0]))
        except ValueError:
            continue
    if not addresses:
        return "unresolved"
    public = sum(_is_global_ip(ip) for ip in addresses)
    if public == len(addresses):
        return "public"
    return "private" if public == 0 else "mixed"


def _origin(url: str) -> tuple[str, str, int | None] | None:
    """Return a URL's scheme, host and effective port, or None when it has no host."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    if not parts.hostname:
        return None
    scheme = parts.scheme.lower()
    return scheme, parts.hostname, port if port is not None else {"https": 443, "http": 80}.get(scheme)


def _is_fetchable_url(value: object) -> bool:
    """Whether a value is an http(s) URL with a host."""
    return _is_http_url(value) and _origin(cast("str", value)) is not None


async def _discovery_url_refusal(url: str, target_url: str) -> Literal["private", "timeout"] | None:
    """Why a server-supplied discovery URL must not be fetched, or None when it may be.

    The challenge's ``resource_metadata`` and the listed issuers are chosen by
    the audited server, so following them must not turn an audit of a public
    server into a request to loopback, link-local or private addresses. A
    URL on the target's own origin is never refused: the audit connects there
    anyway. Any other discovery host with a non-public address is refused as ``"private"``,
    and one whose lookup times out as ``"timeout"``, unless every address of
    the target is non-public. A discovery name that does not resolve is left
    to the fetch. The check resolves before the fetch connects, so it does not
    stop DNS rebinding.
    """
    try:
        host = urlsplit(url).hostname
        target_host = urlsplit(target_url).hostname
    except ValueError:
        return None
    if _origin(url) == _origin(target_url):
        return None
    discovery = await _classify_host(host)
    if discovery not in ("private", "mixed", "timeout"):
        return None
    if await _classify_host(target_host) == "private":
        return None
    return "timeout" if discovery == "timeout" else "private"


# A name starts only at the header start or after whitespace or a comma, and every
# quantifier is possessive, so a long server-supplied header parses in linear time.
_AUTH_PARAM = re.compile(
    r"(?:^|(?<=[\s,]))([!#$%&'*+.^_`|~0-9A-Za-z-]++)\s*+=\s*+(?:\"((?:[^\"\\]|\\.)*+)\"|([^\s,\"]++))"
)
_QUOTED_PAIR = re.compile(r"\\(.)")


def www_authenticate_param(header: str, param: str) -> str | None:
    """Extract an auth-param from a challenge, accepting the quoted and bare forms.

    RFC 7235 §2.1 defines an auth-param value as ``token / quoted-string``, and
    a URL contains ``:`` and ``/`` — delimiters that are not valid ``token``
    characters — so strictly it must be quoted. Deployed servers send it bare
    anyway and clients read it fine, so the bare form is accepted too.

    The bare value ends at the next comma or whitespace, the auth-param
    separators. Parameters are read as whole name/value pairs, so text inside
    another quoted value is never taken for a parameter, and
    ``xresource_metadata=`` is not mistaken for ``resource_metadata=``. Param
    names are matched case-insensitively (RFC 7235 §2.1).
    """
    wanted = param.lower()
    for match in _AUTH_PARAM.finditer(header):
        name, quoted, bare = match.groups()
        if name.lower() == wanted:
            return _QUOTED_PAIR.sub(r"\1", quoted) if quoted is not None else bare
    return None


def _is_https_url(value: object) -> bool:
    """Whether ``value`` is an absolute HTTPS URL with a host, as authorization server endpoints must be."""
    if not isinstance(value, str):
        return False
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return False
    return parts.scheme.lower() == "https" and bool(parts.hostname)


def _auth_server_metadata_urls(issuer: str) -> list[str]:
    """Return an issuer's authorization server metadata locations, in the MCP discovery order.

    An issuer with a path component gets RFC 8414 path insertion, OpenID
    Connect path insertion, then OpenID Connect path appending; an issuer
    without one gets the RFC 8414 and OpenID Connect root locations (MCP
    Authorization, Authorization Server Metadata Discovery, 2025-11-25+).
    """
    try:
        parts = urlsplit(issuer)
    except ValueError:
        # Unparsable: keep plain candidates so the fetch records InvalidURL as a finding.
        parts = None
    origin = f"{parts.scheme}://{parts.netloc}" if parts else issuer.rstrip("/")
    path = parts.path.rstrip("/") if parts else ""
    if not path:
        return [
            f"{origin}/.well-known/oauth-authorization-server",
            f"{origin}/.well-known/openid-configuration",
        ]
    return [
        f"{origin}/.well-known/oauth-authorization-server{path}",
        f"{origin}/.well-known/openid-configuration{path}",
        f"{origin}{path}/.well-known/openid-configuration",
    ]


def _differs_only_by_trailing_slash(declared: object, issuer: str) -> bool:
    """Return whether ``declared`` equals ``issuer`` apart from one trailing slash."""
    return isinstance(declared, str) and (declared == f"{issuer}/" or f"{declared}/" == issuer)


async def _fetch_auth_server_metadata(
    client: httpx2.AsyncClient, issuer: str, target_url: str, details: dict[str, Any]
) -> None:
    """Fetch the authorization server's metadata; record posture in details.

    Records whether a usable metadata document was found, whether it
    advertises the required authorization/token endpoints, and whether it
    advertises PKCE with S256 (`code_challenge_methods_supported`) — the OAuth
    security BCP (RFC 9700) / MCP-auth requirement.

    A document counts only when its ``issuer`` is identical to the issuer the
    location was built from (RFC 8414 §3.3, OpenID Connect Discovery §4.3);
    clients must not use any other, so a mismatch is recorded in
    ``auth_server_issuer_mismatch`` and the next location is tried. A
    difference in the trailing slash alone is tolerated and recorded in
    ``auth_server_issuer_declared``.

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
    refusal = await _discovery_url_refusal(issuer, target_url)
    if refusal == "timeout":
        details["auth_server_metadata_error"] = _DNS_TIMEOUT_ERROR
        return
    if refusal is not None:
        details["auth_server_metadata_blocked"] = True
        return
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
        declared = metadata.get("issuer")
        if declared != issuer and not _differs_only_by_trailing_slash(declared, issuer):
            details.setdefault("auth_server_issuer_mismatch", {"metadata_url": candidate, "issuer": declared})
            continue
        if declared != issuer:
            details["auth_server_issuer_declared"] = declared
        methods = metadata.get("code_challenge_methods_supported")
        details["auth_server_metadata_url"] = candidate
        details["auth_server_metadata_present"] = True
        details["auth_server_has_endpoints"] = isinstance(metadata.get("authorization_endpoint"), str) and isinstance(
            metadata.get("token_endpoint"), str
        )
        details["auth_server_pkce_s256"] = isinstance(methods, list) and "S256" in methods
        details["auth_server_cimd_supported"] = metadata.get("client_id_metadata_document_supported") is True
        details["auth_server_registration_endpoint"] = _is_https_url(metadata.get("registration_endpoint"))
        return
    if not reached:
        details["auth_server_metadata_error"] = last_error


async def _metadata_candidates(target: _HttpTarget, details: dict[str, Any]) -> tuple[list[str], str | None]:
    """Protected-resource metadata locations in the order an MCP client tries them.

    A ``resource_metadata`` URL in the observed challenge comes first, then the
    RFC 9728 well-known locations (MCP Authorization, Protected Resource
    Metadata Discovery Requirements). The challenge URL is recorded in
    ``challenge_metadata_url`` whether or not it is fetched: an unusable or
    blocked one is that rule's finding. Returns the candidates and the
    challenge URL when it is among them.
    """
    candidates: list[str] = []
    challenge_url: str | None = None
    referenced = www_authenticate_param(target.auth_challenge, "resource_metadata") if target.auth_challenge else None
    if referenced is not None:
        details["challenge_metadata_url"] = referenced
        fetchable = _is_fetchable_url(referenced)
        refusal = await _discovery_url_refusal(referenced, target.url) if fetchable else None
        if not fetchable:
            details["challenge_metadata_invalid"] = True
        elif refusal == "timeout":
            details["challenge_metadata_error"] = _DNS_TIMEOUT_ERROR
        elif refusal is not None:
            details["challenge_metadata_blocked"] = True
        else:
            challenge_url = referenced
            candidates.append(referenced)
    for candidate in _well_known_urls(target.url):
        if candidate not in candidates:
            candidates.append(candidate)
    return candidates, challenge_url


async def _probe_auth_metadata(target: _HttpTarget) -> ProbeResult:
    """Fetch the auth-discovery chain (RFC 9728 PRM → RFC 8414 AS metadata).

    Observation probe feeding the auth-posture rules: SUPPORTED when a
    location returns HTTP 200 with a JSON object carrying the REQUIRED
    ``resource`` field (RFC 9728 §2); details record what was found where, how
    it was discovered (``discovery``: challenge or well-known), plus the
    authorization server's endpoint/PKCE posture. When the challenge names a
    metadata URL, what that URL served is recorded under ``challenge_metadata_*``
    even if discovery falls through to a well-known location. Servers without
    authentication commonly 404 here — the dependent rules skip unless the
    endpoint demanded auth in the first place.

    A transport error on one location does not abort discovery of the next,
    but "every location failed to connect" stays ERROR rather than
    UNSUPPORTED: an unreachable host is *unverified*, not proof that the
    server publishes no metadata, and the dependent rules must skip rather
    than fail it. Locations that could not be contacted are listed in
    ``unreachable_locations`` whatever the outcome, so a firewalled location is
    distinguishable from one that simply answered 404.
    """
    details: dict[str, Any] = {"urls_tried": []}
    candidates, challenge_url = await _metadata_candidates(target, details)
    reached = False
    last_error: str | None = None
    for candidate in candidates:
        details["urls_tried"].append(candidate)
        status, metadata, error = await _try_get_json_anonymous(target.client, candidate)
        is_challenge = candidate == challenge_url
        if error is not None:
            last_error = error
            details.setdefault("unreachable_locations", []).append(candidate)
            if is_challenge and error == "InvalidURL":
                details["challenge_metadata_invalid"] = True
            elif is_challenge:
                details["challenge_metadata_error"] = error
            continue
        reached = True
        details["http_status"] = status
        resource = metadata.get("resource") if metadata is not None else None
        if is_challenge:
            details["challenge_metadata_http_status"] = status
            details["challenge_metadata_resource"] = resource if isinstance(resource, str) else None
        if not isinstance(resource, str):
            continue
        assert metadata is not None  # noqa: S101 — a string resource implies a parsed document
        servers = metadata.get("authorization_servers")
        servers = servers if isinstance(servers, list) else None
        details["metadata_url"] = candidate
        details["discovery"] = "challenge" if is_challenge else "well-known"
        details["resource"] = resource
        details["authorization_servers"] = servers
        details["scopes_supported"] = metadata.get("scopes_supported")
        # Walk to the first authorization server's metadata. The document is
        # public and fetched anonymously; whether the AS URL is HTTPS is scored
        # separately by auth_authorization_servers_https, so observe http too.
        first = next((s for s in (servers or []) if _is_http_url(s)), None)
        if first is not None:
            await _fetch_auth_server_metadata(target.client, first, target.url, details)
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


@dataclass(frozen=True)
class _AcceptedControl:
    """A harmless request the server accepted, to be repeated with one header spoofed."""

    body: dict[str, Any]
    headers: dict[str, str]
    shape: str
    """``modern`` (``server/discover``) or ``legacy-initialize``."""
    details: dict[str, Any]
    """Control status and shape, plus the rejected modern control when it fell back."""


async def _accepted_control(
    target: _HttpTarget, probe_id: str, subject: str, *, host: str | None = None
) -> _AcceptedControl | ProbeResult:
    """Send the control request a spoofed-header probe is judged against.

    The control is ``server/discover`` (mandatory in 2026-07-28), falling back
    to the ``initialize`` every 2025-11-25 client opens with when a legacy-only
    server rejects the modern request. Sessions that handshake opens are closed
    with DELETE. The control drops any ``Origin`` a caller configured as a
    client default, so it is the headerless twin of the spoofed request.
    ``host`` replaces the ``Host`` header, for a control sent to another
    address of the same server. Returns a NOT_APPLICABLE result when the control is access-controlled or
    not accepted in either shape: a refusal of the spoofed twin would then say
    nothing about *subject* handling.
    """
    target_version = _target_version()
    body = _request_body("server/discover", 10, _modern_meta(target_version))
    host_header = {"Host": host} if host is not None else {}
    headers = {**_request_headers(target_version, "server/discover"), **host_header}
    control = await target.post_rpc(
        body,
        headers,
        follow_redirects=False,
        omit_headers=("Origin",),
        close_session_on_failure=True,
        cleanup_headers=host_header,
    )
    shape = "modern"
    details: dict[str, Any] = {}

    # "Accepted" means the server answered the method, not merely 2xx: a legacy
    # server may return HTTP 200 carrying a JSON-RPC method-not-found error,
    # and judging that server on a request it cannot serve would fail it for
    # the wrong reason.
    def served(response: _HttpProbeResponse, field: str) -> bool:
        return 200 <= response.status_code < 300 and (response.result or {}).get(field) is not None

    if control.status_code not in AUTH_GATED_STATUSES and not served(control, "supportedVersions"):
        details["modern_control_http_status"] = control.status_code
        if control.unobservable is not None:
            details["modern_control_unobservable"] = control.unobservable
        body = _legacy_initialize_body(10)
        headers = {**_legacy_headers(), **host_header}
        control = await target.post_rpc(
            body,
            headers,
            follow_redirects=False,
            omit_headers=("Origin",),
            close_session_on_failure=True,
            cleanup_headers=host_header,
        )
        await target.end_session(control, host_header)
        shape = "legacy-initialize"
        accepted = served(control, "protocolVersion")
    else:
        accepted = served(control, "supportedVersions")

    # Decide on the control before sending anything spoofed. When the answer is
    # already unknowable, the second request would add security-relevant traffic
    # (and another timeout) to a server we cannot judge anyway.
    details["control_http_status"] = control.status_code
    details["control_shape"] = shape
    if control.unobservable is not None:
        details["control_unobservable"] = control.unobservable
    if control.status_code in AUTH_GATED_STATUSES:
        # The endpoint refuses the control too, so a refusal of the spoofed twin
        # would say nothing. Not a failure — an unanswerable question.
        details["reason"] = f"control request is access-controlled; {subject} handling not observable"
        return ProbeResult(probe_id, ProbeOutcome.NOT_APPLICABLE, details)
    if not accepted:
        details["reason"] = f"control request was not accepted (HTTP {control.status_code}" + (
            f", JSON-RPC error {control.error_code})" if control.error_code is not None else ")"
        )
        return ProbeResult(probe_id, ProbeOutcome.NOT_APPLICABLE, details)
    return _AcceptedControl(body=body, headers=headers, shape=shape, details=details)


async def _probe_origin_validation(target: _HttpTarget) -> ProbeResult:
    """Send a harmless request with an invalid foreign ``Origin``.

    Streamable HTTP servers MUST validate every supplied Origin to prevent DNS
    rebinding and MUST reject an invalid one with HTTP 403 — a requirement of
    every Streamable HTTP revision, not only 2026-07-28. The request is a
    ``server/discover`` (modern) or ``initialize`` (legacy) and cannot invoke
    server-side tool behavior.

    **A single 403 proves nothing**, because 403 is also how an access-controlled
    server refuses everyone. Judged on its own, every server that rejects
    unauthenticated callers would pass a CRITICAL security check it has not
    earned — measured against the registry, 54 servers answer 403 to any
    unauthenticated request. So the probe first sends a control request without
    the foreign Origin (:func:`_accepted_control`), and only judges the server
    when that control shows the same request would otherwise be accepted.
    ``details["control_shape"]`` records which request judged the server.
    """
    control = await _accepted_control(target, PROBE_ORIGIN_VALIDATION, "Origin")
    if isinstance(control, ProbeResult):
        return control

    spoofed = dict(control.headers)
    spoofed["Origin"] = ORIGIN_PROBE_VALUE
    response = await target.post_rpc(control.body, spoofed, follow_redirects=False, close_session_on_failure=True)
    if control.shape == "legacy-initialize":
        await target.end_session(response)

    details = _base_details(response)
    details.update(control.details)
    outcome = ProbeOutcome.SUPPORTED if response.status_code == 403 else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_ORIGIN_VALIDATION, outcome, details)


async def _probe_host_validation(target: _HttpTarget) -> ProbeResult:
    """Send a harmless request to a loopback server with a foreign ``Host``.

    DNS rebinding points a hostname the attacker controls at 127.0.0.1, so the
    browser's request reaches a local server carrying that hostname as ``Host``.
    A local server that checks ``Host`` against the names it is served under
    refuses it, as both official SDKs do by default for loopback binds (Python
    421, TypeScript 403); any 4xx counts as a refusal. Public hosts are not
    judged: behind virtual hosting a foreign ``Host`` is routed elsewhere, not
    validated. The control request (:func:`_accepted_control`) must be accepted
    first, so an access-controlled server is not credited with a refusal it
    gives everyone. The spoofed twin carries no ``Origin``, so only ``Host``
    can explain a refusal.
    """
    if not _is_loopback_host(urlsplit(target.url).hostname):
        return ProbeResult(
            PROBE_HOST_VALIDATION,
            ProbeOutcome.NOT_APPLICABLE,
            {"reason": "target is not a loopback address; a public host's Host routing is not validation"},
        )
    control = await _accepted_control(target, PROBE_HOST_VALIDATION, "Host")
    if isinstance(control, ProbeResult):
        return control

    # A rebound request keeps the port, so only the hostname is foreign: the port comes from the Host the
    # control actually sent (a caller-configured one, or the URL's with an explicit default port dropped).
    effective_host = target.client.build_request("POST", target.url).headers["Host"]
    foreign_host = f"{HOST_PROBE_VALUE}{_port_suffix(effective_host)}"
    spoofed = {**control.headers, "Host": foreign_host}
    response = await target.post_rpc(
        control.body,
        spoofed,
        follow_redirects=False,
        omit_headers=("Origin",),
        close_session_on_failure=True,
        cleanup_headers={"Host": foreign_host},
    )
    if control.shape == "legacy-initialize":
        await target.end_session(response, {"Host": foreign_host})

    details = _base_details(response)
    details.update(control.details)
    if response.status_code in (408, 429):
        # A timeout or rate limit refuses any Host alike, so it says nothing about Host validation.
        details["reason"] = f"HTTP {response.status_code} is not a Host decision"
        return ProbeResult(PROBE_HOST_VALIDATION, ProbeOutcome.ERROR, details)
    refused = 400 <= response.status_code < 500
    return ProbeResult(PROBE_HOST_VALIDATION, ProbeOutcome.SUPPORTED if refused else ProbeOutcome.UNSUPPORTED, details)


def _port_suffix(host: str) -> str:
    """Return the ``:port`` a ``Host`` value ends with, or an empty string; an IPv6 literal's colons are bracketed."""
    head, separator, port = host.rpartition(":")
    if separator and port.isdigit() and (not head.startswith("[") or head.endswith("]")):
        return f":{port}"
    return ""


def _is_loopback_host(host: str | None) -> bool:
    """Whether a URL host is ``localhost`` (or a ``*.localhost`` name) or a loopback literal IP; no DNS lookup."""
    if not host:
        return False
    lowered = host.lower().rstrip(".")
    if lowered == "localhost" or lowered.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(lowered.strip("[]"))
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped.is_loopback
    return ip.is_loopback


def _non_loopback_addresses() -> list[str]:
    """Return this machine's default-route addresses (IPv4, IPv6), minus loopback, link-local and unspecified ones.

    A UDP ``connect`` to a documentation address sends no packet but makes the
    OS pick the source address it would route from. A server bound to every
    interface answers there; host-name lookups are skipped, as they can stall
    for seconds on machines without a resolvable host name.
    """
    found: set[str] = set()
    for family, documentation_address in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.connect((documentation_address, 9))
                found.add(sock.getsockname()[0])
        except OSError:
            continue
    addresses = []
    for address in found:
        ip = ipaddress.ip_address(address.split("%", 1)[0])  # getsockname() returns a numeric address
        if not (ip.is_loopback or ip.is_link_local or ip.is_unspecified):
            addresses.append(str(ip))
    return sorted(addresses)


async def _tcp_listening(host: str, port: int) -> bool | None:
    """Connect to *host*:*port*: True when it accepts, False when it refuses, None when the answer is unknown.

    Only a refusal proves the port closed. A timeout (a firewall that drops
    the packet) or any other socket error leaves it unknown. Never raises.
    """
    try:
        async with asyncio.timeout(LOCAL_BIND_TIMEOUT_S):
            _, writer = await asyncio.open_connection(host, port)
    except ConnectionRefusedError:
        return False
    except (OSError, TimeoutError):
        return None
    writer.close()
    with suppress(OSError):
        await writer.wait_closed()
    return True


def _inconclusive_status(status: object) -> bool:
    """Whether an HTTP status refuses any request alike: a timeout (408), a rate limit (429) or a server error."""
    return isinstance(status, int) and (status in (408, 429) or status >= 500)


def _direct_client() -> httpx2.AsyncClient:
    """Return a client for requests to this machine's own addresses: no caller headers, cookies or proxies."""
    return async_client(trust_env=False)


def _address_family(host: str) -> int | None:
    """Return the address family a URL host pins, or None for a name such as ``localhost``."""
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is None:
        return socket.AF_INET6
    return socket.AF_INET


def _url_at(url: str, address: str) -> str:
    """*url* with its host replaced by *address*, keeping scheme, port, path and query."""
    parts = urlsplit(url)
    netloc = f"[{address}]" if ":" in address else address
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"
    return parts._replace(netloc=netloc).geturl()


async def _probe_local_bind(target: _HttpTarget) -> ProbeResult:
    """Check whether a loopback server also serves MCP on this machine's network addresses.

    Every Streamable HTTP revision says a server running locally SHOULD bind
    only to localhost rather than all network interfaces. For a loopback http
    target the probe first sends the control request (:func:`_accepted_control`)
    to the audited URL, then TCP-connects to the same port on each
    default-route address of this machine. Where a
    connection opens, the same control goes to that address with the audited
    URL's ``Host``: served there, the audited server listens on
    ``0.0.0.0``/``::`` and the network can reach it. A listener that does not
    serve it is another program and does not count. Only a refused connection
    proves a port closed, so a timeout, or a connection whose request gets no
    HTTP answer, with no address serving, makes the probe an ERROR. Details
    record counts, never addresses. Not applicable to non-loopback or https
    targets (a certificate for ``localhost`` does not cover an address), when
    no address of the target's family can be tried, or when the control
    request is not accepted on loopback. Every request goes out on
    :func:`_direct_client` to the URL without credential query parameters,
    and both controls carry the URL's own ``Host``: a server that needs
    credentials or another ``Host`` refuses the loopback control, and stays
    unjudged.
    """
    parts = urlsplit(target.url)
    if not _is_loopback_host(parts.hostname):
        return ProbeResult(
            PROBE_LOCAL_BIND, ProbeOutcome.NOT_APPLICABLE, {"reason": "target is not a loopback address"}
        )
    if parts.scheme != "http":
        return ProbeResult(
            PROBE_LOCAL_BIND,
            ProbeOutcome.NOT_APPLICABLE,
            {"reason": "an https target's certificate does not cover this machine's network addresses"},
        )
    family = _address_family(parts.hostname or "")
    addresses = [
        address
        for address in await asyncio.to_thread(_non_loopback_addresses)
        if family is None or _address_family(address) == family
    ]
    if not addresses:
        return ProbeResult(
            PROBE_LOCAL_BIND,
            ProbeOutcome.NOT_APPLICABLE,
            {"reason": "this machine has no routable address of the target's family to try"},
        )
    # A listener on another address is unverified until it serves the control, so no request carries
    # the caller's credentials, and none goes through a proxy that could answer in the server's place.
    # Rebuilt from host and port, so no userinfo reaches either the URL or the Host header.
    url = _url_at(without_credential_params(target.url), parts.hostname or "")
    authority = urlsplit(url).netloc
    async with _direct_client() as client:
        loopback_control = await _accepted_control(
            _HttpTarget(client, url), PROBE_LOCAL_BIND, "network exposure", host=authority
        )
        if isinstance(loopback_control, ProbeResult):
            return loopback_control

        port = parts.port or 80
        states = await asyncio.gather(*(_tcp_listening(address, port) for address in addresses))
        listening = [address for address, state in zip(addresses, states, strict=True) if state]
        serving = 0
        unknown = sum(state is None for state in states)
        for address in listening:
            lan_target = _HttpTarget(client, _url_at(url, address))
            try:
                # One deadline for the whole confirmation: a stream kept open with heartbeats never times out a read.
                async with asyncio.timeout(LOCAL_BIND_CONFIRM_TIMEOUT_S):
                    control = await _accepted_control(lan_target, PROBE_LOCAL_BIND, "network exposure", host=authority)
            except (httpx2.HTTPError, TimeoutError):
                # Connected, no complete HTTP answer: a host firewall can accept a connection and drop the request.
                unknown += 1
                continue
            if isinstance(control, _AcceptedControl):
                serving += 1
            elif any(
                _inconclusive_status(control.details.get(key))
                for key in ("control_http_status", "modern_control_http_status")
            ) or any(key in control.details for key in ("control_unobservable", "modern_control_unobservable")):
                # A timeout, rate limit, server error or unreadable body, to either control shape, says nothing
                # about which program answered.
                unknown += 1
    details: dict[str, Any] = {
        "port": port,
        "interfaces_checked": len(addresses),
        "interfaces_listening": len(listening),
        "interfaces_serving": serving,
        "interfaces_unknown": unknown,
    }
    if serving:
        return ProbeResult(PROBE_LOCAL_BIND, ProbeOutcome.UNSUPPORTED, details)
    if unknown:
        details["reason"] = "an address neither refused the connection nor answered the request"
        return ProbeResult(PROBE_LOCAL_BIND, ProbeOutcome.ERROR, details)
    return ProbeResult(PROBE_LOCAL_BIND, ProbeOutcome.SUPPORTED, details)


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


def _malformed_json_result(
    response: _HttpProbeResponse,
    control: _HttpProbeResponse,
    raw_body: str | None,
    unobservable_reason: str | None,
) -> ProbeResult:
    """Judge JSON-RPC's normative malformed-JSON response, status-agnostically.

    The raw response body is carried on the ProbeResult ``payload`` (excluded
    from ``to_dict``, so it never reaches a report) for
    ``security_error_data_leak`` to scan — the malformed request is the probe
    most likely to make a server dump a stack trace or a file path.

    ``unobservable_reason`` (from ``post_raw``) means the parse verdict cannot
    be trusted: ``"truncated"`` (payload came from a bounded prefix — a valid
    oversized ``-32700`` would parse to ``None`` only because it was cut) or
    ``"encoded"`` (the body was content-encoded and not decoded, to bound
    memory against a compression bomb). Either way an unparsable/absent
    payload is unobservable, not UNSUPPORTED.
    """
    details = _base_details(response)
    details["control_http_status"] = control.status_code
    leak_payload = {"error_body": raw_body}

    # The control proves that this endpoint parses valid JSON-RPC rather than
    # returning one canned parse-error response for every POST. Modern servers
    # return a result; legacy stateful servers may return an ordinary correlated
    # error (for example -32600 because there is no session). A parse error or
    # null/missing ID cannot prove the valid body was parsed.
    control_payload = control.payload
    control_is_correlated = (
        isinstance(control_payload, dict)
        and control_payload.get("jsonrpc") == "2.0"
        and control_payload.get("id") == 13
        and ("result" in control_payload or control.error is not None)
        and control.error_code != -32700
    )
    if not control_is_correlated:
        details["reason"] = (
            "control request is access-controlled; payload parsing not observable"
            if control.status_code in AUTH_GATED_STATUSES
            else "control did not return a correlated JSON-RPC response; payload parsing not observable"
        )
        # Still carry the body: a server can leak data in an error response
        # whether or not its parse-error verdict is judgeable.
        return ProbeResult(PROBE_MALFORMED_JSON, ProbeOutcome.NOT_APPLICABLE, details, payload=leak_payload)

    payload = response.payload
    error = response.error
    # A missing `id` counts the same as an explicit `null`: on a parse error the id
    # is unknowable and no client correlates a parse error by id. A real value
    # (e.g. 0) is still excluded.
    id_absent_or_null = isinstance(payload, dict) and payload.get("id") is None
    correct = (
        isinstance(payload, dict)
        and payload.get("jsonrpc") == "2.0"
        and id_absent_or_null
        and response.error_code == -32700
        and error is not None
        and isinstance(error.get("message"), str)
        and "result" not in payload
    )
    details["response_id_absent_or_null"] = id_absent_or_null
    if not correct and unobservable_reason is not None and not isinstance(payload, dict):
        # Absent or unparsable payload after a bounded read (a truncated prefix or an
        # undecoded content-encoded body): a verdict we could not observe cannot fail
        # the server. The leak scan still sees the bounded prefix.
        details["reason"] = (
            "response was content-encoded; not decoded to bound memory, parse verdict not observable"
            if unobservable_reason == "encoded"
            else "response body exceeded scan cap; parse verdict not observable"
        )
        return ProbeResult(PROBE_MALFORMED_JSON, ProbeOutcome.NOT_APPLICABLE, details, payload=leak_payload)
    outcome = ProbeOutcome.SUPPORTED if correct else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_MALFORMED_JSON, outcome, details, payload=leak_payload)


async def _probe_malformed_json(target: _HttpTarget) -> ProbeResult:
    """Send truncated JSON and require JSON-RPC Parse error with a null or absent ID."""
    target_version = _target_version()
    headers = _request_headers(target_version, "server/discover")
    control = await target.post(
        _request_body("server/discover", 13, _modern_meta(target_version)),
        headers,
        follow_redirects=False,
    )
    response, raw_body, unobservable_reason = await target.post_raw(
        b'{"jsonrpc":"2.0","id":13,"method":"server/discover",',
        headers,
    )
    return _malformed_json_result(response, control, raw_body, unobservable_reason)


@dataclass(frozen=True)
class _LegacySession:
    """A stateful-lifecycle session a probe opened with ``initialize`` and ``notifications/initialized``."""

    initialize: _HttpProbeResponse
    headers: dict[str, str]
    """POST headers for requests inside the session: negotiated version and any session ID."""

    session_id: str | None
    initialized: _HttpProbeResponse
    initialized_body: str | None
    initialized_unobservable: str | None
    """Why the ``notifications/initialized`` body could not be read (``post_raw``), or None."""


async def _open_legacy_session(
    target: _HttpTarget, request_id: int
) -> tuple[_LegacySession | None, _HttpProbeResponse, _HttpTarget]:
    """Open a legacy session the way every 2025 client does; None when ``initialize`` is not served.

    ``initialize`` follows a same-origin redirect, as the audit's own session
    does, and every later request goes to the URL that answered. The
    ``notifications/initialized`` that completes the handshake is sent as a
    raw POST so its status and body can be judged. Returns the session, the
    ``initialize`` response, and the target to use from here on.
    """
    response = await target.post_rpc(
        _legacy_initialize_body(request_id), _legacy_headers(), close_session_on_failure=True
    )
    if response.final_url and response.final_url != target.url:
        target = replace(target, url=response.final_url)
    negotiated = (response.result or {}).get("protocolVersion")
    if not 200 <= response.status_code < 300 or not isinstance(negotiated, str):
        # A session ID may have been issued with an answer the probe cannot use; close it.
        await target.end_session(response)
        return None, response, target
    headers = {**_legacy_headers(), "MCP-Protocol-Version": negotiated}
    session_id = next((v for k, v in response.headers.items() if k.lower() == "mcp-session-id"), None)
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    notification = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
    try:
        initialized, body, unobservable = await target.post_raw(
            notification, headers, body_limit=_notification_body_limit
        )
    except Exception:
        await target.end_session(response)
        raise
    return _LegacySession(response, headers, session_id, initialized, body, unobservable), response, target


def _notification_body_limit(status: int) -> int:
    """Only a 202 needs its body, and one byte decides whether it has one."""
    return 1 if status == 202 else 0


async def _incomplete_handshake(probe_id: str, session: _LegacySession, target: _HttpTarget) -> ProbeResult | None:
    """Close the session and return NOT_APPLICABLE when ``notifications/initialized`` was not accepted.

    A server may refuse requests in a session whose handshake never completed,
    so nothing later in it says anything about the transport contract.
    """
    status = session.initialized.status_code
    if 200 <= status < 300:
        return None
    await target.end_session(session.initialize)
    details = {"initialized_http_status": status, "reason": "handshake notification was not accepted"}
    return ProbeResult(probe_id, ProbeOutcome.NOT_APPLICABLE, details)


def _legacy_unavailable(probe_id: str, response: _HttpProbeResponse) -> ProbeResult:
    """NOT_APPLICABLE for a session probe whose ``initialize`` was refused."""
    if response.status_code in AUTH_GATED_STATUSES:
        reason = "initialize is access-controlled"
    elif response.unobservable:
        reason = f"initialize answer not observable ({response.unobservable})"
    else:
        reason = f"initialize was not served (HTTP {response.status_code}); no legacy session to probe"
    details = {"initialize_http_status": response.status_code, "reason": reason}
    return ProbeResult(probe_id, ProbeOutcome.NOT_APPLICABLE, details)


def _redirected(probe_id: str, status: int, details: dict[str, Any]) -> ProbeResult | None:
    """NOT_APPLICABLE when the answer is a redirect the probe did not follow: it never reached the endpoint."""
    if status in REDIRECT_STATUSES:
        return ProbeResult(probe_id, ProbeOutcome.NOT_APPLICABLE, {**details, "reason": "endpoint redirects"})
    return None


def _notification_outcome(status: int, body: str | None) -> ProbeOutcome:
    """Judge a notification POST: ``202`` with a zero-length body, or an HTTP error status, both conform."""
    if status == 202:
        return ProbeOutcome.SUPPORTED if body == "" else ProbeOutcome.UNSUPPORTED
    return ProbeOutcome.SUPPORTED if status >= 400 else ProbeOutcome.UNSUPPORTED


async def _probe_notification_accepted(target: _HttpTarget) -> ProbeResult:
    """POST a JSON-RPC notification and check the transport's answer.

    Every Streamable HTTP revision says a notification the server accepts MUST
    get ``202 Accepted`` with no body, and one it cannot accept an HTTP error
    status. A 202 passes only with a zero-length body; one whose body could
    not be read (content-encoded) is not judged. The notification is the ``notifications/initialized`` that
    completes a legacy handshake; a server without the legacy lifecycle gets a
    stateless 2026-07-28 ``notifications/cancelled`` instead.
    """
    session, response, target = await _open_legacy_session(target, 23)
    if session is not None:
        await target.end_session(session.initialize)
        status, body, shape = session.initialized.status_code, session.initialized_body, "legacy-initialized"
        unobservable = session.initialized_unobservable
    elif response.status_code in AUTH_GATED_STATUSES or response.unobservable:
        return _legacy_unavailable(PROBE_NOTIFICATION_ACCEPTED, response)
    else:
        version = _target_version()
        method = "notifications/cancelled"
        notification = {"jsonrpc": "2.0", "method": method, "params": {"requestId": "mcpscore-probe"}}
        sent, body, unobservable = await target.post_raw(
            json.dumps(notification).encode(), _request_headers(version, method), body_limit=_notification_body_limit
        )
        status, shape = sent.status_code, "modern-cancelled"
        if status in AUTH_GATED_STATUSES:
            return ProbeResult(
                PROBE_NOTIFICATION_ACCEPTED,
                ProbeOutcome.NOT_APPLICABLE,
                {"http_status": status, "reason": "notification POST is access-controlled"},
            )
    details: dict[str, Any] = {
        "http_status": status,
        "body_present": None if body is None else body != "",
        "shape": shape,
    }
    redirected = _redirected(PROBE_NOTIFICATION_ACCEPTED, status, details)
    if redirected is not None:
        return redirected
    if status == 202 and body is None:
        # A compressed body was not decoded, so "no body" cannot be verified either way.
        details["reason"] = f"202 body not observable ({unobservable or 'unread'})"
        return ProbeResult(PROBE_NOTIFICATION_ACCEPTED, ProbeOutcome.NOT_APPLICABLE, details)
    return ProbeResult(PROBE_NOTIFICATION_ACCEPTED, _notification_outcome(status, body), details)


INVALID_REQUEST_METHOD = 24
"""The ``method`` of the invalid-request probe; JSON-RPC 2.0 requires a string."""


def _judge_invalid_answer(rejected: _HttpProbeResponse, details: dict[str, Any]) -> ProbeResult:
    """Judge the answer to the invalid request; ``details`` already holds the control's observations."""
    details.update(_base_details(rejected))
    if rejected.status_code in AUTH_GATED_STATUSES:
        details["reason"] = "invalid request was refused by access control; validation not observable"
        return ProbeResult(PROBE_INVALID_REQUEST, ProbeOutcome.NOT_APPLICABLE, details)
    redirected = _redirected(PROBE_INVALID_REQUEST, rejected.status_code, details)
    if redirected is not None:
        return redirected
    if rejected.unobservable:
        # The status still decides a crash or a refusal; the body, and so the error code, is unknown.
        details["body_unobservable"] = rejected.unobservable
        if rejected.status_code >= 500:
            return ProbeResult(PROBE_INVALID_REQUEST, ProbeOutcome.UNSUPPORTED, details)
        if rejected.status_code >= 400:
            return ProbeResult(PROBE_INVALID_REQUEST, ProbeOutcome.SUPPORTED, details)
        details["reason"] = f"answer to the invalid request not observable ({rejected.unobservable})"
        return ProbeResult(PROBE_INVALID_REQUEST, ProbeOutcome.NOT_APPLICABLE, details)
    served = rejected.result is not None
    details["served"] = served
    if rejected.error is not None:
        response_id = rejected.payload.get("id") if isinstance(rejected.payload, dict) else None
        details["id_echoed_or_null"] = response_id in (None, 24)
    if served or rejected.status_code >= 500:
        outcome = ProbeOutcome.UNSUPPORTED
    elif rejected.error is not None or rejected.status_code >= 400:
        outcome = ProbeOutcome.SUPPORTED
    else:
        outcome = ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_INVALID_REQUEST, outcome, details)


async def _probe_invalid_request(target: _HttpTarget) -> ProbeResult:
    """Send a well-formed JSON body that is not a valid JSON-RPC 2.0 request.

    The body is a correct request except that ``method`` is a number;
    JSON-RPC 2.0 calls that an Invalid Request (-32600), and no handler can
    serve it. The same request with a valid method must be served first, so
    a server that refuses everything is not credited with a refusal. In a
    legacy session the request is ``ping``; without the legacy lifecycle it
    is a stateless ``server/discover``. A timeout counts as no answer
    (``timed_out``) only when a second control, sent afterwards, is served;
    otherwise it is an error. An answer that cannot be read (compressed, or
    over the byte cap) is judged by its status alone, and its code is left
    unknown (``body_unobservable``). A 404 in a legacy session is not judged
    when a ``ping`` in it also gets 404: the session expired. Details also
    record whether the invalid request was served, the error code, and
    whether the response id is the request's or null.
    """
    session, response, target = await _open_legacy_session(target, 29)
    if session is not None and (incomplete := await _incomplete_handshake(PROBE_INVALID_REQUEST, session, target)):
        return incomplete
    if session is not None:
        headers, body = session.headers, {"jsonrpc": "2.0", "id": 25, "method": "ping"}
        shape = "legacy-ping"
    elif response.status_code in AUTH_GATED_STATUSES or response.unobservable:
        return _legacy_unavailable(PROBE_INVALID_REQUEST, response)
    else:
        version = _target_version()
        headers = _request_headers(version, "server/discover")
        body, shape = _request_body("server/discover", 25, _modern_meta(version)), "modern-discover"
    try:
        control = await target.post_rpc(body, headers, follow_redirects=False)
        details: dict[str, Any] = {"control_http_status": control.status_code, "shape": shape}
        if control.status_code in AUTH_GATED_STATUSES or control.result is None:
            details["reason"] = (
                f"control answer not observable ({control.unobservable})"
                if control.unobservable
                else "control request was not served; invalid-request handling not observable"
            )
            return ProbeResult(PROBE_INVALID_REQUEST, ProbeOutcome.NOT_APPLICABLE, details)
        invalid = {**body, "method": INVALID_REQUEST_METHOD, "id": 24}
        try:
            rejected = await target.post_rpc(invalid, headers, follow_redirects=False)
        except httpx2.ReadTimeout:
            # Silence is the server's only if the session still answers a control afterwards;
            # otherwise the timeout propagates and the runner records ERROR.
            again = await target.post_rpc({**body, "id": 30}, headers, follow_redirects=False)
            if again.result is None:
                raise
            details["timed_out"] = True
            return ProbeResult(PROBE_INVALID_REQUEST, ProbeOutcome.UNSUPPORTED, details)
        if session is not None and rejected.status_code == 404 and await _session_gone(target, session, 31):
            details["reason"] = "session no longer exists; a ping in it was answered 404"
            return ProbeResult(PROBE_INVALID_REQUEST, ProbeOutcome.NOT_APPLICABLE, details)
    finally:
        if session is not None:
            await target.end_session(session.initialize)
    return _judge_invalid_answer(rejected, details)


async def _probe_get_stream(target: _HttpTarget) -> ProbeResult:
    """GET the endpoint inside a legacy session: an SSE stream or ``405``.

    From 2025-03-26 through 2025-11-25 the server MUST answer a GET either with
    ``Content-Type: text/event-stream`` or ``405 Method Not Allowed``. The
    stream is closed as soon as the headers arrive. A 404 is not judged when
    a ``ping`` in the session also gets 404: the session expired, not the GET.
    """
    session, response, target = await _open_legacy_session(target, 26)
    if session is None:
        return _legacy_unavailable(PROBE_GET_STREAM, response)
    if incomplete := await _incomplete_handshake(PROBE_GET_STREAM, session, target):
        return incomplete
    headers = {"Accept": "text/event-stream", "MCP-Protocol-Version": session.headers["MCP-Protocol-Version"]}
    if session.session_id:
        headers["Mcp-Session-Id"] = session.session_id
    try:
        got = await target.get_status(headers)
        gone = got.status_code == 404 and await _session_gone(target, session, 29)
    finally:
        await target.end_session(session.initialize)
    content_type = next((v for k, v in got.headers.items() if k.lower() == "content-type"), "")
    details: dict[str, Any] = {"http_status": got.status_code, "content_type": content_type or None}
    if gone:
        details["reason"] = "session no longer exists; a ping in it was answered 404"
        return ProbeResult(PROBE_GET_STREAM, ProbeOutcome.NOT_APPLICABLE, details)
    if got.status_code in AUTH_GATED_STATUSES:
        details["reason"] = "GET is access-controlled"
        return ProbeResult(PROBE_GET_STREAM, ProbeOutcome.NOT_APPLICABLE, details)
    redirected = _redirected(PROBE_GET_STREAM, got.status_code, details)
    if redirected is not None:
        return redirected
    media_type = content_type.split(";", 1)[0].strip().lower()
    is_stream = 200 <= got.status_code < 300 and media_type == "text/event-stream"
    outcome = ProbeOutcome.SUPPORTED if got.status_code == 405 or is_stream else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_GET_STREAM, outcome, details)


async def _probe_session_delete(target: _HttpTarget) -> ProbeResult:
    """DELETE a session the probe opened, then check the session is gone.

    A client SHOULD end a session with DELETE, and the server MAY refuse with
    ``405``. A server that accepts it has terminated the session, after which
    it MUST answer requests carrying that session ID with ``404``; a ``ping``
    in the deleted session checks that. Applies only when ``initialize``
    issued a session ID, and only when the session is gone afterwards: a
    server that accepts the DELETE and keeps serving the session has not
    terminated it. A 404 to the DELETE is judged only while the session is
    still served; a session the server already dropped says nothing. Unless
    the session is known to be closed, cleanup sends one more DELETE.
    """
    session, response, target = await _open_legacy_session(target, 27)
    if session is None:
        return _legacy_unavailable(PROBE_SESSION_DELETE, response)
    if incomplete := await _incomplete_handshake(PROBE_SESSION_DELETE, session, target):
        return incomplete
    if not session.session_id:
        return ProbeResult(
            PROBE_SESSION_DELETE, ProbeOutcome.NOT_APPLICABLE, {"reason": "initialize issued no session ID"}
        )
    closed = False
    try:
        result, closed = await _observe_session_delete(target, session)
    finally:
        if not closed:
            await target.end_session(session.initialize)
    return result


async def _session_gone(target: _HttpTarget, session: _LegacySession, request_id: int) -> bool:
    """Ping the session and report whether the server answers 404 because it no longer has it."""
    if not session.session_id:
        return False
    answer = await target.post_rpc(
        {"jsonrpc": "2.0", "id": request_id, "method": "ping"}, session.headers, follow_redirects=False
    )
    return answer.status_code == 404


async def _observe_session_delete(target: _HttpTarget, session: _LegacySession) -> tuple[ProbeResult, bool]:
    """Send the DELETE and judge it; also say whether the session is known to be closed (or cannot be)."""
    deleted = await target.request_status(
        "DELETE",
        {
            "Mcp-Session-Id": cast("str", session.session_id),
            "MCP-Protocol-Version": session.headers["MCP-Protocol-Version"],
        },
    )
    details: dict[str, Any] = {"http_status": deleted.status_code}
    if deleted.status_code in AUTH_GATED_STATUSES:
        details["reason"] = "DELETE is access-controlled"
        return ProbeResult(PROBE_SESSION_DELETE, ProbeOutcome.NOT_APPLICABLE, details), False
    redirected = _redirected(PROBE_SESSION_DELETE, deleted.status_code, details)
    if redirected is not None:
        return redirected, False
    if deleted.status_code == 405:
        return ProbeResult(PROBE_SESSION_DELETE, ProbeOutcome.SUPPORTED, details), True
    if deleted.status_code == 404 and await _session_gone(target, session, 28):
        details["reason"] = "session no longer exists; a ping in it was answered 404"
        return ProbeResult(PROBE_SESSION_DELETE, ProbeOutcome.NOT_APPLICABLE, details), True
    if not 200 <= deleted.status_code < 300:
        return ProbeResult(PROBE_SESSION_DELETE, ProbeOutcome.UNSUPPORTED, details), False
    after = await target.post_rpc(
        {"jsonrpc": "2.0", "id": 28, "method": "ping"}, session.headers, follow_redirects=False
    )
    details["after_delete_http_status"] = after.status_code
    return _judge_after_delete(after, details), after.status_code == 404


def _judge_after_delete(after: _HttpProbeResponse, details: dict[str, Any]) -> ProbeResult:
    """Judge the answer to a ``ping`` in a session the server accepted to DELETE."""
    if after.status_code in AUTH_GATED_STATUSES:
        details["reason"] = "request after DELETE is access-controlled"
        return ProbeResult(PROBE_SESSION_DELETE, ProbeOutcome.NOT_APPLICABLE, details)
    redirected = _redirected(PROBE_SESSION_DELETE, after.status_code, details)
    if redirected is not None:
        return redirected
    if after.unobservable and 200 <= after.status_code < 300:
        # Only a success needs its body: it decides whether the session is still served.
        details["reason"] = f"answer after DELETE not observable ({after.unobservable})"
        return ProbeResult(PROBE_SESSION_DELETE, ProbeOutcome.NOT_APPLICABLE, details)
    if after.result is not None:
        # The 404 requirement binds a terminated session, and this one was kept.
        details["reason"] = "session is still served after DELETE; no terminated session to observe"
        return ProbeResult(PROBE_SESSION_DELETE, ProbeOutcome.NOT_APPLICABLE, details)
    outcome = ProbeOutcome.SUPPORTED if after.status_code == 404 else ProbeOutcome.UNSUPPORTED
    return ProbeResult(PROBE_SESSION_DELETE, outcome, details)


_TRANSPORT_AGNOSTIC_PROBES: dict[str, Callable[[_ProbeTarget], Awaitable[ProbeResult]]] = {
    PROBE_DISCOVER: _probe_discover,
    PROBE_STATELESS_LIST: _probe_stateless_list,
    PROBE_MALFORMED_META: _probe_malformed_meta,
    PROBE_UNKNOWN_VERSION: _probe_unknown_version,
    PROBE_MISSING_RESOURCE: _probe_missing_resource,
    PROBE_REMOVED_METHOD: _probe_removed_method,
    PROBE_UNKNOWN_METHOD: _probe_unknown_method,
    PROBE_TOOLS_INVALID_CURSOR: _probe_tools_invalid_cursor,
    PROBE_RESOURCES_INVALID_CURSOR: _probe_resources_invalid_cursor,
    PROBE_RESOURCE_TEMPLATES_INVALID_CURSOR: _probe_resource_templates_invalid_cursor,
    PROBE_PROMPTS_INVALID_CURSOR: _probe_prompts_invalid_cursor,
    PROBE_PAGINATION_CACHE_SCOPE: _probe_pagination_cache_scope,
}
"""Probes that judge JSON-RPC behavior, and so run over any transport."""

_HTTP_ONLY_PROBES: dict[str, Callable[[_HttpTarget], Awaitable[ProbeResult]]] = {
    PROBE_HEADER_MISMATCH: _probe_header_mismatch,
    PROBE_MISSING_PROTOCOL_VERSION: _probe_missing_protocol_version,
    PROBE_MISSING_METHOD_HEADER: _probe_missing_method_header,
    PROBE_RESOURCE_NAME_HEADER_MISMATCH: _probe_resource_name_header_mismatch,
    PROBE_PROMPT_NAME_HEADER_MISMATCH: _probe_prompt_name_header_mismatch,
    PROBE_GET_STREAM_REMOVED: _probe_get_stream_removed,
    PROBE_UNAUTHENTICATED: _probe_unauthenticated,
    PROBE_SESSION_ID_ECHO: _probe_session_id_echo,
    PROBE_AUTH_METADATA: _probe_auth_metadata,
    PROBE_INVALID_TOKEN: _probe_invalid_token,
    PROBE_ORIGIN_VALIDATION: _probe_origin_validation,
    PROBE_MALFORMED_JSON: _probe_malformed_json,
    PROBE_NOTIFICATION_ACCEPTED: _probe_notification_accepted,
    PROBE_INVALID_REQUEST: _probe_invalid_request,
    PROBE_GET_STREAM: _probe_get_stream,
    PROBE_SESSION_DELETE: _probe_session_delete,
    PROBE_QUERY_CREDENTIAL: _probe_query_credential,
    PROBE_HOST_VALIDATION: _probe_host_validation,
    PROBE_LOCAL_BIND: _probe_local_bind,
}
"""Probes whose subject is an HTTP construct (see HTTP_ONLY_PROBE_IDS)."""

# A probe accepting any target also accepts an HTTP one, so the merged map is
# keyed on the narrower parameter type.
_HTTP_PROBES: dict[str, Callable[[_HttpTarget], Awaitable[ProbeResult]]] = {
    **_TRANSPORT_AGNOSTIC_PROBES,
    **_HTTP_ONLY_PROBES,
}


async def _not_gated(probe_id: str) -> ProbeResult:
    """NOT_APPLICABLE for a probe that needs an unauthenticated request to have been refused."""
    return ProbeResult(probe_id, ProbeOutcome.NOT_APPLICABLE, {"reason": "the unauthenticated request was not refused"})


def not_applicable_results(reason: str, probe_ids: Iterable[str] = PROBE_IDS) -> dict[str, ProbeResult]:
    """NOT_APPLICABLE results for the given probes (all of them by default)."""
    return {probe_id: ProbeResult(probe_id, ProbeOutcome.NOT_APPLICABLE, {"reason": reason}) for probe_id in probe_ids}


GATEWAY_PROBE_IDS: tuple[str, ...] = (PROBE_DISCOVER, PROBE_STATELESS_LIST)
"""Probes whose support indicates the server speaks the modern lifecycle at all."""


MODERN_RESULT_FIELDS: tuple[str, ...] = ("result_type", "ttl_ms", "cache_scope")
"""Stateless-list details that only a modern result carries (``resultType``, ``ttlMs``, ``cacheScope``)."""


def has_modern_support(probes: dict[str, ProbeResult] | None) -> bool:
    """Whether the probes observed any modern-lifecycle support.

    True when the server answered ``server/discover``, or answered a stateless
    request with a modern result — the gateway condition for the detail
    readiness rules. A plain tools result is not enough: a legacy server that
    answers without checking for ``initialize`` returns one too.
    """
    if not probes:
        return False
    discover = probes.get(PROBE_DISCOVER)
    if discover is not None and discover.outcome is ProbeOutcome.SUPPORTED:
        return True
    stateless = probes.get(PROBE_STATELESS_LIST)
    return (
        stateless is not None
        and stateless.outcome is ProbeOutcome.SUPPORTED
        and any(stateless.details.get(field) is not None for field in MODERN_RESULT_FIELDS)
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


def _exception_message(exc: BaseException) -> str:
    message = exc.args[0] if len(exc.args) == 1 and isinstance(exc.args[0], str) else str(exc)
    return " ".join(message.split())


def failure_cause(exc: BaseException) -> str:
    """Return the innermost cause's message, looking through single-exception groups, wrapped errors and ``from``.

    A ``from`` cause without a message of its own does not replace an outer message.
    """
    while True:
        if isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) == 1:
            exc = exc.exceptions[0]
        elif len(exc.args) == 1 and isinstance(exc.args[0], BaseException):
            exc = exc.args[0]
        elif exc.__cause__ is not None and (_exception_message(exc.__cause__) or not _exception_message(exc)):
            exc = exc.__cause__
        else:
            break
    return _exception_message(exc) or type(exc).__name__


class _ProbeFailureLog:
    """Log probe exceptions once per distinct cause, not once per probe."""

    def __init__(self, target: str) -> None:
        super().__init__()
        self._target = target
        self._probes_by_cause: dict[str, list[str]] = {}

    def record(self, probe_id: str, exc: Exception) -> None:
        self._add(probe_id, failure_cause(exc))

    def record_result(self, result: ProbeResult) -> None:
        """Count a probe that handled its own exception and returned ``ERROR``."""
        if result.outcome is ProbeOutcome.ERROR:
            self._add(result.probe_id, str(result.details.get("reason") or result.details.get("exception") or "error"))

    def _add(self, probe_id: str, cause: str) -> None:
        logger.debug("Probe %s failed against %s: %s", probe_id, self._target, cause)
        self._probes_by_cause.setdefault(cause, []).append(probe_id)

    def flush(self) -> None:
        for cause, probe_ids in self._probes_by_cause.items():
            if len(probe_ids) == 1:
                logger.info("Probe %s failed against %s: %s", probe_ids[0], self._target, cause)
            else:
                logger.info("%d probes failed against %s: %s", len(probe_ids), self._target, cause)
        self._probes_by_cause.clear()


async def run_all_probes(
    url: str,
    client: httpx2.AsyncClient | None = None,
    headers: dict[str, str] | None = None,
    *,
    fresh_client: httpx2.AsyncClient | None = None,
) -> dict[str, ProbeResult]:
    """Run every probe against an HTTP(S) MCP endpoint.

    Probes run concurrently; a probe that fails at the network level yields
    ``ProbeOutcome.ERROR`` with the exception name in its details — probes
    never raise.

    Args:
        url: The MCP endpoint URL (http:// or https://)
        client: Optional preconfigured httpx client (tests inject a
            MockTransport-backed one); short-lived clients are created
            otherwise. An injected client is used for every single-target
            probe, including the anonymous ones — the caller configures its
            headers.
        headers: Extra HTTP headers (e.g. an ``Authorization`` bearer) merged
            into the short-lived authenticated client's defaults; probes in
            ``_ANONYMOUS_PROBE_IDS`` run on a separate client that carries
            none of them. Ignored when ``client`` is supplied. Sensitive —
            never logged.
        fresh_client: A second independently configured client used only for
            catalog connection-independence comparisons when ``client`` is
            injected. Without it those comparisons are not observable and
            skip; one client must never manufacture two-connection evidence.

    Returns:
        Mapping of probe_id to its ProbeResult, covering all PROBE_IDS

    """
    failures = _ProbeFailureLog(url)

    async def run_one(probe_id: str, http_client: httpx2.AsyncClient, auth_challenge: str | None = None) -> ProbeResult:
        try:
            result = await _HTTP_PROBES[probe_id](_HttpTarget(http_client, url, auth_challenge))
        except Exception as e:  # noqa: BLE001 — a probe failure is data, never an audit abort
            failures.record(probe_id, e)
            return ProbeResult(probe_id, ProbeOutcome.ERROR, {"exception": type(e).__name__})
        failures.record_result(result)
        return result

    async def run_with(
        select: Callable[[str], httpx2.AsyncClient],
        comparison_client: httpx2.AsyncClient | None,
    ) -> dict[str, ProbeResult]:
        primary_client = select(PROBE_DISCOVER)
        # Compare pristine clients before any single-target response can mutate
        # the primary client's cookie jar and create a different auth context.
        connection_results = (
            await _probe_catalog_connection_independence(
                _HttpTarget(primary_client, url),
                _HttpTarget(comparison_client, url),
                failures,
            )
            if comparison_client is not None and comparison_client is not primary_client
            else not_applicable_results(
                "a second independent probe client was not supplied",
                CATALOG_CONNECTION_PROBE_IDS,
            )
        )

        async def run_auth_discovery() -> list[ProbeResult]:
            # Metadata discovery follows the challenge the unauthenticated request received.
            unauthenticated = await run_one(PROBE_UNAUTHENTICATED, select(PROBE_UNAUTHENTICATED))
            challenge = unauthenticated.details.get("www_authenticate")
            # Without an observed answer the token probe still runs, so a network failure stays ERROR data.
            gated = (
                unauthenticated.outcome is not ProbeOutcome.SUPPORTED
                or unauthenticated.details.get("http_status") in AUTH_GATED_STATUSES
            )
            metadata = await run_one(
                PROBE_AUTH_METADATA,
                select(PROBE_AUTH_METADATA),
                challenge if isinstance(challenge, str) else None,
            )
            # After discovery: a cookie set in reply to the fabricated token must not reach the metadata fetches.
            invalid_token = (
                await run_one(PROBE_INVALID_TOKEN, select(PROBE_INVALID_TOKEN))
                if gated
                else await _not_gated(PROBE_INVALID_TOKEN)
            )
            return [unauthenticated, metadata, invalid_token]

        independent = [probe_id for probe_id in _SINGLE_TARGET_PROBE_IDS if probe_id not in _AUTH_DISCOVERY_PROBE_IDS]
        auth_results, results = await asyncio.gather(
            run_auth_discovery(), asyncio.gather(*(run_one(probe_id, select(probe_id)) for probe_id in independent))
        )
        by_id = {result.probe_id: result for result in [*auth_results, *results]}
        return {
            **{probe_id: by_id[probe_id] for probe_id in _SINGLE_TARGET_PROBE_IDS},
            **connection_results,
        }

    try:
        if client is not None:
            return await run_with(lambda _probe_id: client, fresh_client)
        # No follow_redirects on the clients: every probe request goes through
        # the same-origin policy in ``mcpscore.redirects``, which does not consult
        # the client's setting, exactly as the SDK transports do not.
        async with (
            async_client(headers=headers) as own_client,
            async_client(headers=headers) as fresh_client,
            async_client() as anon_client,
        ):
            return await run_with(
                lambda probe_id: anon_client if probe_id in _ANONYMOUS_PROBE_IDS else own_client,
                fresh_client,
            )
    finally:
        failures.flush()


async def run_stdio_probes(
    params: StdioServerParameters,
    *,
    require_modern_support: bool = False,
) -> dict[str, ProbeResult]:
    """Run the transport-agnostic probes against a local stdio MCP server.

    The modern lifecycle is stateless, so "does this server speak 2026-07-28?"
    is answerable over stdio exactly as over HTTP: send the request, read the
    reply. The suite launches two short-lived sibling processes and deliberately
    stays below the SDK session layer, so no ``initialize`` handshake pins those
    connections to the legacy lifecycle. Single-target probes run sequentially
    on the first process because a stdio stream has one reader; the second exists
    only to compare catalogs across independent connections.

    Probes in :data:`HTTP_ONLY_PROBE_IDS` are recorded ``NOT_APPLICABLE``:
    their subject does not exist on this transport.

    Args:
        params: Fully-resolved command, arguments and environment of the
            server, as used for the audit's own stdio connection.
        require_modern_support: Run the two gateway probes first and stop when
            neither establishes modern-lifecycle support. This bounds the
            fallback cost after a failed legacy initialize; regular audits
            still run the complete suite for legacy and dual-era servers.

    Returns:
        Mapping of probe_id to its ProbeResult, covering all PROBE_IDS

    """
    failures = _ProbeFailureLog(params.command)

    async def run_one(probe_id: str, target: _StdioTarget) -> ProbeResult:
        try:
            result = await _TRANSPORT_AGNOSTIC_PROBES[probe_id](target)
        except Exception as e:  # noqa: BLE001 — a probe failure is data, never an audit abort
            failures.record(probe_id, e)
            return ProbeResult(probe_id, ProbeOutcome.ERROR, {"exception": type(e).__name__})
        failures.record_result(result)
        return result

    results: list[ProbeResult] = []
    try:
        # Use the SDK transport, not raw asyncio subprocesses: it owns executable
        # resolution, the environment allowlist, process-tree termination and pipe
        # draining. errlog is annotated TextIO but reaches the subprocess API, where
        # DEVNULL is the portable sentinel.
        errlog: TextIO = cast("Any", DEVNULL)
        async with stdio_client(params, errlog=errlog) as (read_stream, write_stream):
            target = _StdioTarget(read_stream, write_stream)
            results.extend([await run_one(probe_id, target) for probe_id in GATEWAY_PROBE_IDS])
            completed = {result.probe_id: result for result in results}
            if require_modern_support and not has_modern_support(completed):
                return {
                    **not_applicable_results("modern support was not established by gateway probes"),
                    **not_applicable_results("probe subject is HTTP-specific", HTTP_ONLY_PROBE_IDS),
                    **completed,
                }
            results.extend(
                [await run_one(probe_id, target) for probe_id in STDIO_PROBE_IDS if probe_id not in GATEWAY_PROBE_IDS]
            )
            async with stdio_client(params, errlog=errlog) as (fresh_read_stream, fresh_write_stream):
                connection_results = await _probe_catalog_connection_independence(
                    target,
                    _StdioTarget(fresh_read_stream, fresh_write_stream),
                    failures,
                )
                results.extend(connection_results.values())
    except Exception as e:  # process startup/teardown failures are probe data
        logger.debug("Stdio probe transport failed against %s", params.command, exc_info=e)
        completed = {result.probe_id for result in results}
        not_run = [
            probe_id for probe_id in (*STDIO_PROBE_IDS, *CATALOG_CONNECTION_PROBE_IDS) if probe_id not in completed
        ]
        for probe_id in not_run:
            failures.record(probe_id, e)
            results.append(ProbeResult(probe_id, ProbeOutcome.ERROR, {"exception": type(e).__name__}))
    finally:
        failures.flush()

    return {
        **not_applicable_results("probe subject is HTTP-specific", HTTP_ONLY_PROBE_IDS),
        **{result.probe_id: result for result in results},
    }


STATELESS_READ_LIMIT = 6 * 1024 * 1024 + 64 * 1024
"""Bytes of one stateless skills answer read before giving up.

A 1 MiB file fits even when it is all control characters, each JSON-escaped in six bytes, plus the envelope.
"""


class StatelessSession:
    """Answer the skills collector's calls with one stateless request each (SEP-2575).

    Every request carries the modern ``_meta`` and declares the Skills extension in its client capabilities,
    since a server may expose skills only to clients that declare it. A JSON-RPC error raises ``MCPError``; a
    reply that is neither a result nor an error raises ``ConnectionError``, which the collector treats as no
    answer.
    """

    def __init__(self, target: _HttpTarget | _StdioTarget) -> None:
        super().__init__()
        self._target = target
        self._next_id = 0
        # One stdio stream carries every reply and an exchange drops replies to other IDs, so exchanges take turns.
        self._stdio_turn = asyncio.Lock()

    async def _post(self, body: dict, headers: dict[str, str]) -> _ProbeResponse:
        if isinstance(self._target, _StdioTarget):
            async with self._stdio_turn:
                return await self._target.post(body, headers)
        try:
            return await self._target.post_rpc(body, headers, read_limit=STATELESS_READ_LIMIT)
        except httpx2.TimeoutException as exc:
            raise TimeoutError(str(exc)) from exc

    async def request_raw(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Send one stateless request and return its result object."""
        self._next_id += 1
        version = _target_version()
        meta = _skills_meta(version)
        name = params.get("uri") if method == "resources/read" and isinstance(params.get("uri"), str) else None
        request_id = 1000 + self._next_id
        response = await self._post(
            _request_body(method, request_id, meta, params), _request_headers(version, method, name)
        )
        payload = response.payload if isinstance(response.payload, dict) else {}
        if payload.get("id") != request_id and not (payload.get("id") is None and "error" in payload):
            msg = f"{method} got no reply carrying its request ID"
            raise ConnectionError(msg)
        error = response.error
        if error is not None:
            code = response.error_code
            message = error.get("message")
            raise MCPError(code if code is not None else 0, message if isinstance(message, str) else "")
        if "result" in payload and not isinstance(payload["result"], dict):
            # An answer whose result is not an object is malformed, not missing: raise pydantic's ValidationError.
            TypeAdapter(dict[str, Any]).validate_python(payload["result"])
        result = response.result
        if result is None:
            msg = f"{method} returned neither a result nor an error"
            raise ConnectionError(msg)
        return result

    async def read_resource_contents(self, uri: str) -> list[dict[str, Any]]:
        """Read one resource and return its ``contents`` entries."""
        contents = (await self.request_raw("resources/read", {"uri": uri})).get("contents")
        return [item for item in contents if isinstance(item, dict)] if isinstance(contents, list) else []


@asynccontextmanager
async def stateless_session(
    target: str | StdioServerParameters, headers: dict[str, str] | None = None
) -> AsyncGenerator[StatelessSession]:
    """Open a stateless session on an HTTP endpoint or a fresh stdio process of the audited command."""
    if isinstance(target, str):
        async with async_client(headers=headers) as client:
            yield StatelessSession(_HttpTarget(client, target))
        return
    errlog: TextIO = cast("Any", DEVNULL)
    async with stdio_client(target, errlog=errlog) as (read_stream, write_stream):
        yield StatelessSession(_StdioTarget(read_stream, write_stream))
