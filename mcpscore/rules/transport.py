from typing import Any, ClassVar

from ..enums import MCPTransportType
from ..probes import (
    PROBE_GET_STREAM,
    PROBE_INVALID_REQUEST,
    PROBE_NOTIFICATION_ACCEPTED,
    PROBE_SESSION_DELETE,
    ProbeOutcome,
    ProbeResult,
)
from ..spec import compare
from .base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_NOT_APPLICABLE,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
    requires_fields,
)
from .probe_diagnostics import diagnostic_result
from .registry import register_rule


@register_rule
class StreamableHTTPTransportRule(BaseRule):
    """Check that a remote server uses the Streamable HTTP transport.

    Streamable HTTP is the current MCP standard for remote servers; the
    standalone SSE transport is deprecated by the specification. Servers
    still exposing only SSE should migrate.

    Scoring: 1 point (LOW - migration recommendation)
    """

    rule_id = "transport_streamable_http"
    basis = "MCP 2025-11-25 Transports §Streamable HTTP (replaces the deprecated HTTP+SSE transport from 2024-11-05)"
    group_name = "transport"
    group_order = 5
    rule_order = 1

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when a remote transport cannot be judged.

        Remote transport quality does not apply to stdio. A missing transport
        or URL leaves insufficient evidence, including in partial audits that
        reach a server only through raw probe requests.
        """
        if audit_data.transport_type == MCPTransportType.STDIO:
            return SKIP_REASON_NOT_APPLICABLE
        if audit_data.transport_type is None or audit_data.url is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    @property
    def rule_name(self) -> str:
        return "Streamable HTTP Transport"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    @requires_fields("transport_type", "url")
    def check(self, transport_type: MCPTransportType | None, url: str | None) -> RuleResult:  # type: ignore[override]
        """Check which remote transport the server was reached over.

        Args:
            transport_type: The transport type used for connection
            url: The server URL (if applicable)

        Returns:
            RuleResult indicating pass/fail

        """
        assert transport_type is not None  # noqa: S101 — skip_reason guarantees transport data
        assert url is not None  # noqa: S101 — skip_reason guarantees a remote URL

        if transport_type == MCPTransportType.STREAMABLE_HTTP:
            return diagnostic_result(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=True,
                message="✅ Server uses the Streamable HTTP transport (current MCP standard)",
                details={"transport_type": transport_type, "url": url},
                suggested_fix=None,
            )

        if transport_type == MCPTransportType.SSE:
            return diagnostic_result(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message=("❌ The audited endpoint was reached over deprecated HTTP+SSE transport"),
                details={"transport_type": transport_type, "url": url},
                suggested_fix=(
                    "Expose a Streamable HTTP MCP endpoint and audit its URL. Keep a separate legacy "
                    "HTTP+SSE endpoint if older clients still require it."
                ),
            )

        # Unknown transport type
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=False,
            message=f"[INFO] Unknown transport type: {transport_type}",
            details={"transport_type": transport_type, "url": url},
            suggested_fix="Verify the URL and selected transport, then re-audit the Streamable HTTP MCP endpoint.",
        )


_LEGACY_TRANSPORTS_SPEC = "https://modelcontextprotocol.io/specification/{version}/basic/transports"
_MODERN_STREAMABLE_HTTP_SPEC = (
    "https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http"
)
_JSONRPC_ERROR_OBJECT = "https://www.jsonrpc.org/specification#error_object"
_JSONRPC_INVALID_REQUEST = -32600
_HEADER_MISMATCH = -32020


def _legacy_transport_spec(negotiated_version: str | None, anchor: str) -> str:
    """Dated Transports section for a rule that ends at 2025-11-25; an unknown or later revision cites 2025-11-25."""
    if negotiated_version is None or compare(negotiated_version, "2025-11-25") > 0:
        negotiated_version = "2025-11-25"
    return f"{_LEGACY_TRANSPORTS_SPEC.format(version=negotiated_version)}#{anchor}"


def _transport_spec(negotiated_version: str | None, legacy_anchor: str, modern_anchor: str) -> str:
    """Dated Streamable HTTP section for the negotiated revision; an unknown one cites the current text."""
    if negotiated_version is None or compare(negotiated_version, "2026-07-28") >= 0:
        return f"{_MODERN_STREAMABLE_HTTP_SPEC}#{modern_anchor}"
    return f"{_LEGACY_TRANSPORTS_SPEC.format(version=negotiated_version)}#{legacy_anchor}"


class _TransportProbeRule(BaseRule):
    """A Streamable HTTP envelope rule judged from one probe."""

    group_name = "transport"
    group_order = 5
    min_spec_version = "2025-03-26"  # Streamable HTTP begins here
    probe_id: ClassVar[str]

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip on stdio and HTTP+SSE, and when the probe could not observe the behaviour."""
        if audit_data.transport_type in (MCPTransportType.STDIO, MCPTransportType.SSE):
            return SKIP_REASON_NOT_APPLICABLE
        probe = (audit_data.probes or {}).get(self.probe_id)
        if probe is not None and probe.outcome is ProbeOutcome.NOT_APPLICABLE:
            return SKIP_REASON_NOT_APPLICABLE
        if probe is None or probe.outcome is ProbeOutcome.ERROR:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def _probe(self, audit_data: AuditData) -> ProbeResult:
        return (audit_data.probes or {})[self.probe_id]


@register_rule
class NotificationAcceptedRule(_TransportProbeRule):
    """A JSON-RPC notification POST gets ``202 Accepted`` with no body, or an HTTP error status.

    Every Streamable HTTP revision: a notification the server accepts MUST be
    answered with 202 and no body; one it cannot accept with an HTTP error
    status. A 200 carrying a body, or another 2xx, is a client-visible
    contract break: clients wait for or misparse a response that should not
    exist. The probe sends the ``notifications/initialized`` that completes a
    legacy handshake, or a stateless notification on 2026-07-28.

    Scoring: 1 point (LOW)
    """

    rule_id = "transport_notification_accepted"
    basis = (
        "Transports §Sending Messages to the Server (2025-03-26 to 2025-11-25) and Streamable HTTP §Sending "
        "Messages (2026-07-28): an accepted notification MUST get HTTP 202 with no body, a refused one an HTTP "
        "error status"
    )
    rule_order = 2
    probe_id: ClassVar[str] = PROBE_NOTIFICATION_ACCEPTED

    @property
    def rule_name(self) -> str:
        return "Notification Answered With 202"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def check(self, audit_data: AuditData) -> RuleResult:
        """Pass when the notification got 202 with no body, or an HTTP error status."""
        probe = self._probe(audit_data)
        status = probe.details.get("http_status")
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        details: dict[str, Any] = {
            "spec": _transport_spec(audit_data.protocol_version, "sending-messages-to-the-server", "sending-messages"),
            "http_status": status,
            "body_present": probe.details.get("body_present"),
            "shape": probe.details.get("shape"),
        }
        if passed:
            message = (
                "✅ A notification POST is answered with HTTP 202 and no body"
                if status == 202
                else "✅ A notification POST the server does not accept is refused with an HTTP error status"
            )
        elif status == 202:
            message = "❌ A notification POST is answered with HTTP 202 but carries a body"
        else:
            message = "❌ A notification POST is not answered with HTTP 202 and no body"
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details=details,
            suggested_fix=None
            if passed
            else (
                "Answer every accepted JSON-RPC notification with HTTP 202 Accepted and an empty body. "
                "Do not send a JSON-RPC response for a notification; refuse one you cannot accept with a 4xx status."
            ),
            audit_data=audit_data,
            expected={"http_status": 202, "body": "empty"},
        )


@register_rule
class InvalidRequestRejectedRule(_TransportProbeRule):
    """A JSON body that is not a valid JSON-RPC 2.0 request is rejected, not served.

    MCP messages MUST follow JSON-RPC 2.0, which answers an invalid Request
    object with an error. The probe sends a request that differs from a served
    control only in a numeric ``method``. Serving it, failing with a 5xx, or
    never answering it fails. The JSON-RPC code is not judged here:
    ``transport_invalid_request_error_code`` requires -32600 separately, so a
    wrong code costs that LOW rule, not this one.

    Scoring: 2 points (MEDIUM)
    """

    rule_id = "transport_invalid_request_rejected"
    basis = (
        "Base Protocol §Messages: all messages MUST follow JSON-RPC 2.0; JSON-RPC 2.0 §5.1: a request that is "
        "not a valid Request object is answered with error -32600 (Invalid Request)"
    )
    rule_order = 3
    probe_id: ClassVar[str] = PROBE_INVALID_REQUEST

    @property
    def rule_name(self) -> str:
        return "Invalid JSON-RPC Request Rejected"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        """Pass when the invalid request was refused with a JSON-RPC error or an HTTP 4xx."""
        probe = self._probe(audit_data)
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        code = probe.details.get("error_code")
        status = probe.details.get("http_status")
        details: dict[str, Any] = {
            "spec": _JSONRPC_ERROR_OBJECT,
            "http_status": status,
            "error_code": code,
            "invalid_request_code": code == _JSONRPC_INVALID_REQUEST,
            "id_echoed_or_null": probe.details.get("id_echoed_or_null"),
            "timed_out": probe.details.get("timed_out", False),
            "shape": probe.details.get("shape"),
        }
        if passed and code == _JSONRPC_INVALID_REQUEST:
            message = "✅ A request whose method is a number is rejected with -32600 (Invalid Request)"
        elif passed:
            message = (
                "✅ A request whose method is a number is rejected "
                f"({code if code is not None else 'no JSON-RPC error'}; transport_invalid_request_error_code judges "
                "the code)"
            )
        elif probe.details.get("timed_out"):
            message = "❌ A request whose method is a number gets no answer before the probe times out"
        elif probe.details.get("served"):
            message = "❌ A request whose method is a number is served as if it were valid JSON-RPC 2.0"
        elif isinstance(status, int) and status >= 500:
            message = "❌ A request whose method is a number makes the server fail with an HTTP 5xx error"
        else:
            message = "❌ A request whose method is a number is neither rejected with an error nor served"
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details=details,
            suggested_fix=None
            if passed
            else (
                "Validate every message against JSON-RPC 2.0 before dispatching it: answer an invalid Request "
                "object with error -32600 and HTTP 400, and never let malformed input reach a handler or crash it."
            ),
            audit_data=audit_data,
            expected={"error_code": _JSONRPC_INVALID_REQUEST, "http_status": "4xx"},
        )


@register_rule
class InvalidRequestErrorCodeRule(_TransportProbeRule):
    """A rejected invalid request carries JSON-RPC error -32600 (Invalid Request).

    JSON-RPC 2.0 assigns -32600 to JSON that is not a valid Request object.
    ``transport_invalid_request_rejected`` judges whether the server refuses
    the request at all; this rule judges the code, and skips when the request
    was not refused. Several MCP SDKs send -32700 or -32602 here, so servers
    built on them fail until the SDK is fixed. On the stateless 2026-07-28
    path the ``Mcp-Method`` header cannot match a numeric method, and
    Streamable HTTP §Server Validation then requires -32020 first, which
    passes.

    Scoring: 1 point (LOW)
    """

    rule_id = "transport_invalid_request_error_code"
    basis = (
        "JSON-RPC 2.0 §5.1: -32600 Invalid Request, the JSON sent is not a valid Request object; Base Protocol "
        "§Messages: all messages MUST follow JSON-RPC 2.0"
    )
    rule_order = 4
    probe_id: ClassVar[str] = PROBE_INVALID_REQUEST

    @property
    def rule_name(self) -> str:
        return "Invalid Request Answered With -32600"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Also skip when the request was not refused: ``transport_invalid_request_rejected`` fails that."""
        reason = super().skip_reason(audit_data)
        if reason is not None:
            return reason
        if self._probe(audit_data).outcome is not ProbeOutcome.SUPPORTED:
            return SKIP_REASON_NOT_APPLICABLE
        return None

    def check(self, audit_data: AuditData) -> RuleResult:
        """Pass when the refusal carries -32600, or -32020 for a header-validated stateless request."""
        probe = self._probe(audit_data)
        code = probe.details.get("error_code")
        shape = probe.details.get("shape") or ""
        header_validated = shape.startswith("modern") and code == _HEADER_MISMATCH
        passed = code == _JSONRPC_INVALID_REQUEST or header_validated
        details: dict[str, Any] = {
            "spec": _JSONRPC_ERROR_OBJECT,
            "http_status": probe.details.get("http_status"),
            "error_code": code,
            "shape": shape or None,
        }
        if header_validated:
            message = "✅ The invalid request is refused by header validation with -32020, as 2026-07-28 requires"
        elif passed:
            message = "✅ The invalid request is refused with -32600 (Invalid Request)"
        elif code is None:
            message = "❌ The invalid request is refused without a JSON-RPC error; JSON-RPC 2.0 requires -32600"
        else:
            message = f"❌ The invalid request is refused with {code}; JSON-RPC 2.0 assigns -32600 (Invalid Request)"
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details=details,
            suggested_fix=None
            if passed
            else (
                "Answer JSON that is not a valid JSON-RPC request with error -32600 (Invalid Request). Some MCP SDKs "
                "send -32700 or -32602 here; if yours does, upgrade once it is fixed or validate before dispatch."
            ),
            audit_data=audit_data,
            expected={"error_code": _JSONRPC_INVALID_REQUEST},
        )


@register_rule
class GetStreamContractRule(_TransportProbeRule):
    """A GET on the endpoint opens an SSE stream or is refused with ``405``.

    2025-03-26 through 2025-11-25: the server MUST answer a GET with
    ``Content-Type: text/event-stream`` or ``405 Method Not Allowed``.
    2026-07-28 removed the GET stream; ``readiness_2026_no_get_stream`` judges
    that revision.

    Scoring: 1 point (LOW)
    """

    rule_id = "transport_get_stream_contract"
    basis = (
        "Transports §Listening for Messages from the Server (2025-03-26 to 2025-11-25): the server MUST return "
        "Content-Type text/event-stream to a GET, or HTTP 405 Method Not Allowed"
    )
    rule_order = 5
    max_spec_version = "2025-11-25"  # 2026-07-28 removed the GET stream
    probe_id: ClassVar[str] = PROBE_GET_STREAM

    @property
    def rule_name(self) -> str:
        return "GET Stream Or 405"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def check(self, audit_data: AuditData) -> RuleResult:
        """Pass when GET opened an event stream or got 405."""
        probe = self._probe(audit_data)
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        status = probe.details.get("http_status")
        content_type = probe.details.get("content_type")
        details: dict[str, Any] = {
            "spec": _legacy_transport_spec(audit_data.protocol_version, "listening-for-messages-from-the-server"),
            "http_status": status,
            "content_type": content_type,
        }
        if passed:
            message = (
                "✅ GET on the endpoint is refused with HTTP 405"
                if status == 405
                else "✅ GET on the endpoint opens a text/event-stream"
            )
        else:
            message = "❌ GET on the endpoint neither opens a text/event-stream nor returns HTTP 405"
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details=details,
            suggested_fix=None
            if passed
            else (
                "Answer GET on the MCP endpoint with an SSE stream (Content-Type: text/event-stream) if the server "
                "sends server-initiated messages, otherwise with HTTP 405 Method Not Allowed."
            ),
            audit_data=audit_data,
            expected={"http_status": "405 or 2xx text/event-stream"},
        )


@register_rule
class SessionDeleteRule(_TransportProbeRule):
    """DELETE with ``Mcp-Session-Id`` ends the session or is refused with ``405``.

    2025-03-26 through 2025-11-25: clients SHOULD end a session with DELETE and
    the server MAY answer 405. A server that terminates the session MUST then
    answer requests carrying its ID with 404; anything else (a 400 is common)
    stops clients from opening a new session. Only servers that issue a
    session ID are judged, and a server that accepts the DELETE but keeps
    serving the session is not applicable: nothing was terminated.

    Scoring: 1 point (LOW)
    """

    rule_id = "transport_session_delete"
    basis = (
        "Transports §Session Management (2025-03-26 to 2025-11-25): the server MAY answer DELETE with HTTP 405; "
        "after terminating a session it MUST answer requests with that session ID with HTTP 404"
    )
    rule_order = 6
    max_spec_version = "2025-11-25"  # 2026-07-28 removed sessions
    probe_id: ClassVar[str] = PROBE_SESSION_DELETE

    @property
    def rule_name(self) -> str:
        return "Session DELETE Honoured"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def check(self, audit_data: AuditData) -> RuleResult:
        """Pass when DELETE got 405, or 2xx followed by 404 for the deleted session."""
        probe = self._probe(audit_data)
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        status = probe.details.get("http_status")
        after = probe.details.get("after_delete_http_status")
        details: dict[str, Any] = {
            "spec": _legacy_transport_spec(audit_data.protocol_version, "session-management"),
            "http_status": status,
            "after_delete_http_status": after,
        }
        if passed:
            message = (
                "✅ DELETE of a session is refused with HTTP 405"
                if status == 405
                else "✅ DELETE ends the session; a later request with its ID gets HTTP 404"
            )
        elif after is not None:
            message = (
                f"❌ DELETE of a session returns HTTP {status}, but a later request with its ID gets HTTP {after}, "
                "not 404"
            )
        else:
            message = "❌ DELETE of a session is neither accepted nor refused with HTTP 405"
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details=details,
            suggested_fix=None
            if passed
            else (
                "On DELETE with Mcp-Session-Id, terminate the session and answer 2xx, then return HTTP 404 for any "
                "request carrying that ID. If sessions cannot be ended by clients, answer HTTP 405."
            ),
            audit_data=audit_data,
            expected={"http_status": "2xx then 404, or 405"},
        )
