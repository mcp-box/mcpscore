"""Assess readiness for MCP 2026-07-28.

Legacy clients establish context with initialize and a negotiated session version.
Modern requests carry context in _meta without an initialization handshake. A
dual-era server may support both paths; a legacy handshake alone does not tell us
whether it also supports the modern lifecycle. Gateway probes provide that evidence.

The auditor scores readiness on its own axis. In full audits of modern or
dual-era servers it also contributes to the main score. For legacy servers
and partial audits it remains informative; guidance does not change promotion.

Most rules here consume probe observations (see ``mcpscore.probes``): the two
CRITICAL gateway rules check modern-lifecycle support itself, and the detail
rules skip with ``requires-modern-support`` when both gateways failed — the
verdict "not ready" is already carried by the gateways; repeating it per
detail adds noise, not information. The two session-based rules (deprecated
features, tool schema dialect) run regardless: a legacy server can fix those
today.

Each rule cites the SEP / spec section it enforces in its result details.
The readiness group remains a distinct report axis even when promoted into
main scoring; rule IDs and applicability are stable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from jsonschema.exceptions import SchemaError
from jsonschema.validators import Draft202012Validator

from mcpscore.enums import MCPTransportType
from mcpscore.probes import (
    GATEWAY_PROBE_IDS,
    PROBE_DISCOVER,
    PROBE_GET_STREAM_REMOVED,
    PROBE_HEADER_MISMATCH,
    PROBE_MALFORMED_META,
    PROBE_MISSING_METHOD_HEADER,
    PROBE_MISSING_PROTOCOL_VERSION,
    PROBE_MISSING_RESOURCE,
    PROBE_ORIGIN_VALIDATION,
    PROBE_PROMPT_NAME_HEADER_MISMATCH,
    PROBE_REMOVED_METHOD,
    PROBE_RESOURCE_NAME_HEADER_MISMATCH,
    PROBE_SESSION_ID_ECHO,
    PROBE_STATELESS_LIST,
    PROBE_UNKNOWN_METHOD,
    PROBE_UNKNOWN_VERSION,
    REMOVED_METHOD,
    ProbeOutcome,
    has_modern_support,
)
from mcpscore.report_evidence import evidence_preview
from mcpscore.spec import DRAFT, LATEST

from .base import (
    READINESS_GROUP,
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_NOT_APPLICABLE,
    SKIP_REASON_REQUIRES_MODERN_SUPPORT,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
)
from .catalog_diagnostics import field_issue, pointer_token
from .probe_diagnostics import diagnostic_result
from .registry import register_rule

if TYPE_CHECKING:
    from mcpscore.probes import ProbeResult

READINESS_TARGET = (DRAFT or LATEST).version
"""Spec version the readiness rules assess against."""

_JSON_SCHEMA_2020_12 = "https://json-schema.org/draft/2020-12/schema"

_VALID_CACHE_SCOPES = frozenset({"public", "private"})


def _http_clause(audit_data: AuditData, text: str) -> str:
    """Return an HTTP-status clause, or nothing when there is no HTTP layer.

    Several 2026-07-28 requirements pair a JSON-RPC error code with an HTTP
    status. Over stdio only the JSON-RPC half exists and only it was checked
    (see ``_http_status_is`` in mcpscore.probes), so naming a status in the
    message would claim an observation that was never made.
    """
    return "" if audit_data.transport_type is MCPTransportType.STDIO else text


def _response_issue(probe_id: str, path: str, value: Any, expected: str) -> dict[str, Any]:
    """Locate an invalid result field without copying its publisher-controlled value."""
    return {
        **field_issue("response", None, path, "missing_or_null" if value is None else "invalid_value", expected),
        "probe_id": probe_id,
    }


class ReadinessBaseRule(BaseRule):
    """Base class for all readiness rules (separate scoring axis)."""

    group_name = READINESS_GROUP
    group_order = 99  # after every main group in execution/report order


class ProbeBackedReadinessRule(ReadinessBaseRule):
    """Base class for readiness rules that judge a single probe observation."""

    probe_id: ClassVar[str] = ""
    """The probe whose observation this rule judges. Set by subclasses."""

    requires_modern_support: ClassVar[bool] = True
    """Detail rules skip when both gateway probes failed; the gateway rules
    themselves (server/discover, stateless request) set this to False."""

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when this rule cannot judge anything meaningful.

        That is when the probe could not observe anything, or when a detail
        rule would just repeat the gateways' "no modern support" verdict.
        """
        probes = audit_data.probes or {}
        result = probes.get(self.probe_id)
        if result is not None and result.outcome is ProbeOutcome.NOT_APPLICABLE:
            return SKIP_REASON_NOT_APPLICABLE
        if result is None or result.outcome is ProbeOutcome.ERROR:
            return SKIP_REASON_INSUFFICIENT_DATA
        if self.requires_modern_support and not has_modern_support(probes):
            return SKIP_REASON_REQUIRES_MODERN_SUPPORT
        return None

    def _probe(self, audit_data: AuditData) -> ProbeResult:
        """Return this rule's probe result (skip_reason guarantees presence)."""
        assert audit_data.probes is not None  # noqa: S101 — guaranteed by skip_reason
        return audit_data.probes[self.probe_id]


class ModernOnlyHttpProbeBackedReadinessRule(ProbeBackedReadinessRule):
    """Probe-backed rule whose requirement excludes dual-era compatibility behavior."""

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when a completed legacy handshake proves that the endpoint is dual-era.

        ``protocol_version`` is intentionally not sufficient evidence: modern-
        only audits populate it from ``server/discover`` too. The separate
        ``session_protocol_version`` field is set only after a successful
        ``initialize`` handshake and therefore records the provenance this
        applicability decision needs.
        """
        reason = super().skip_reason(audit_data)
        if reason is not None:
            return reason
        if audit_data.session_protocol_version is not None:
            return SKIP_REASON_NOT_APPLICABLE
        return None


@register_rule
class ServerDiscoverReadinessRule(ProbeBackedReadinessRule):
    """Gateway check: the server implements the mandatory ``server/discover`` (SEP-2575)."""

    rule_id = "readiness_2026_server_discover"
    rule_order = 1
    probe_id = PROBE_DISCOVER
    requires_modern_support = False

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - server/discover"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    def check(self, audit_data: AuditData) -> RuleResult:
        probe = self._probe(audit_data)
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        if passed:
            message = (
                f"✅ server/discover supported versions: {evidence_preview(probe.details.get('supported_versions'))}"
            )
        else:
            message = f"❌ The server/discover probe did not produce a usable DiscoverResult for {READINESS_TARGET}"
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2575", "target_version": READINESS_TARGET, **probe.details},
            suggested_fix=(
                "Implement server/discover for the target revision and return a valid DiscoverResult "
                "with capabilities and supportedVersions; include server identity in _meta. Keep "
                "legacy initialize support if older clients need it."
            )
            if not passed
            else None,
            audit_data=audit_data,
        )


@register_rule
class SupportedVersionsReadinessRule(ProbeBackedReadinessRule):
    """The DiscoverResult names at least one supported protocol version.

    The schema requires ``supportedVersions: string[]`` on every DiscoverResult
    and the client "should choose a version from this list for use in
    subsequent requests" — an empty list satisfies the type but makes version
    selection impossible, so it is judged a defect here (the schema has no
    minItems constraint yet). Skips when there is no DiscoverResult to
    inspect: the CRITICAL gateway rule already carries that verdict.
    """

    rule_id = "readiness_2026_supported_versions"
    rule_order = 13
    probe_id = PROBE_DISCOVER

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - supported versions listed"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip (beyond the base gating) when the discover probe found no DiscoverResult."""
        if reason := super().skip_reason(audit_data):
            return reason
        if self._probe(audit_data).outcome is not ProbeOutcome.SUPPORTED:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def check(self, audit_data: AuditData) -> RuleResult:
        probe = self._probe(audit_data)
        raw_versions = probe.details.get("supported_versions")
        versions = raw_versions if isinstance(raw_versions, list) else []
        non_strings = [v for v in versions if not isinstance(v, str)]
        passed = bool(versions) and not non_strings
        if passed:
            message = f"✅ server/discover names {len(versions)} supported version(s): {evidence_preview(versions)}"
        elif raw_versions is None:
            message = "❌ supportedVersions is absent; expected a non-empty array of version strings"
        elif not isinstance(raw_versions, list):
            message = "❌ supportedVersions is not an array"
        elif not versions:
            message = (
                "❌ server/discover returns an empty supportedVersions list — clients choose their "
                "protocol version from this list, so an empty one makes version selection impossible"
            )
        else:
            message = (
                f"❌ supportedVersions contains {len(non_strings)} non-string entries — the schema "
                "requires a list of protocol version strings"
            )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "sep": "SEP-2575",
                "schema_field": "DiscoverResult.supportedVersions",
                "target_version": READINESS_TARGET,
                **probe.details,
                "supported_versions": versions,
            },
            suggested_fix=(
                "Return supportedVersions as a non-empty array of protocol-version strings that the "
                "server actually supports. Do not advertise revisions without implementing their "
                "behavior."
            )
            if not passed
            else None,
            audit_data=audit_data,
            expected={"supportedVersions": "non-empty array of protocol-version strings"},
        )


@register_rule
class StatelessRequestReadinessRule(ProbeBackedReadinessRule):
    """Gateway check: the server accepts a stateless request with per-request ``_meta`` (SEP-2575)."""

    rule_id = "readiness_2026_stateless_request"
    rule_order = 2
    probe_id = PROBE_STATELESS_LIST
    requires_modern_support = False

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - stateless requests"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    def check(self, audit_data: AuditData) -> RuleResult:
        probe = self._probe(audit_data)
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        if passed:
            message = "✅ Server accepts stateless requests (per-request _meta, no initialize handshake)"
        else:
            message = f"❌ The stateless list probe did not produce a usable modern result for {READINESS_TARGET}"
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2575", "target_version": READINESS_TARGET, **probe.details},
            suggested_fix=(
                "Handle the probed list request using its per-request _meta context without requiring "
                "initialize. Return a valid list result; retain the separate legacy handshake path for"
                " older clients."
            )
            if not passed
            else None,
            audit_data=audit_data,
        )


@register_rule
class MetaValidationReadinessRule(ProbeBackedReadinessRule):
    """The server rejects requests missing required ``_meta`` fields with -32602 + HTTP 400."""

    rule_id = "readiness_2026_meta_validation"
    rule_order = 3
    probe_id = PROBE_MALFORMED_META

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - _meta validation"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def check(self, audit_data: AuditData) -> RuleResult:
        probe = self._probe(audit_data)
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        if passed:
            message = (
                "✅ Server rejects requests missing required _meta fields with -32602"
                f"{_http_clause(audit_data, ' and HTTP 400')}"
            )
        else:
            message = (
                "❌ Server does not reject a request missing required _meta fields with "
                f"-32602 (Invalid params){_http_clause(audit_data, ' and HTTP 400')}, as the spec requires"
            )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2575", "target_version": READINESS_TARGET, **probe.details},
            suggested_fix=(
                (
                    "Validate required per-request _meta fields before dispatch; return JSON-RPC -32602 "
                    "for missing fields."
                )
                + _http_clause(audit_data, " On HTTP, use status 400.")
            )
            if not passed
            else None,
            audit_data=audit_data,
            expected={
                "error_code": -32602,
                **({} if audit_data.transport_type is MCPTransportType.STDIO else {"http_status": 400}),
            },
        )


@register_rule
class HeaderValidationReadinessRule(ProbeBackedReadinessRule):
    """The server rejects header/body mismatches with -32020 (HeaderMismatch) + HTTP 400 (SEP-2243)."""

    rule_id = "readiness_2026_header_validation"
    rule_order = 4
    probe_id = PROBE_HEADER_MISMATCH

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - HTTP header validation"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def check(self, audit_data: AuditData) -> RuleResult:
        probe = self._probe(audit_data)
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        if passed:
            message = "✅ Server rejects Mcp-Method header/body mismatches with -32020 and HTTP 400"
        else:
            message = (
                "❌ Server does not reject an Mcp-Method header contradicting the request body "
                "with -32020 (HeaderMismatch) and HTTP 400 (SEP-2243)"
            )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2243", "target_version": READINESS_TARGET, **probe.details},
            suggested_fix=(
                "Compare Mcp-Method with the JSON-RPC method before dispatch. Reject a mismatch with "
                "JSON-RPC -32020 (HeaderMismatch) and HTTP 400."
            )
            if not passed
            else None,
            audit_data=audit_data,
            expected={"error_code": -32020, "http_status": 400},
        )


@register_rule
class CacheMetadataReadinessRule(ReadinessBaseRule):
    """List/discover results carry the mandatory caching hints ``ttlMs`` and ``cacheScope`` (SEP-2549)."""

    rule_id = "readiness_2026_cache_metadata"
    rule_order = 5

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - caching hints"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip unless at least one gateway probe produced a modern result to inspect."""
        probes = audit_data.probes or {}
        observed = [probes[pid] for pid in GATEWAY_PROBE_IDS if pid in probes]
        if not observed or all(p.outcome in (ProbeOutcome.ERROR, ProbeOutcome.NOT_APPLICABLE) for p in observed):
            return SKIP_REASON_INSUFFICIENT_DATA
        if not has_modern_support(audit_data.probes):
            return SKIP_REASON_REQUIRES_MODERN_SUPPORT
        return None

    @staticmethod
    def _valid_hints(details: dict[str, Any]) -> bool:
        ttl_ms = details.get("ttl_ms")
        return isinstance(ttl_ms, int) and ttl_ms >= 0 and details.get("cache_scope") in _VALID_CACHE_SCOPES

    def check(self, audit_data: AuditData) -> RuleResult:
        probes = audit_data.probes or {}
        supported = {
            pid: probes[pid]
            for pid in GATEWAY_PROBE_IDS
            if pid in probes and probes[pid].outcome is ProbeOutcome.SUPPORTED
        }
        missing = [pid for pid, probe in supported.items() if not self._valid_hints(probe.details)]
        issues = []
        for pid in missing:
            observed = supported[pid].details
            ttl = observed.get("ttl_ms")
            if not (isinstance(ttl, int) and ttl >= 0):
                issues.append(_response_issue(pid, "/ttlMs", ttl, "non-negative integer"))
            scope = observed.get("cache_scope")
            if scope not in _VALID_CACHE_SCOPES:
                issues.append(_response_issue(pid, "/cacheScope", scope, "public or private"))
        passed = not missing
        if passed:
            message = "✅ Modern results carry valid caching hints (ttlMs >= 0, cacheScope public/private)"
        else:
            message = f"❌ Results have absent or invalid ttlMs/cacheScope (SEP-2549): {', '.join(sorted(missing))}"
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "sep": "SEP-2549",
                "target_version": READINESS_TARGET,
                "observed": {pid: probe.details for pid, probe in supported.items()},
            },
            suggested_fix=(
                "Set ttlMs to a non-negative integer and cacheScope to public or private on each "
                "observed list/discover result. Use private for authorization-dependent data; "
                "ttlMs: 0 marks a response immediately stale."
            )
            if not passed
            else None,
            audit_data=audit_data,
            expected={"ttlMs": "non-negative integer", "cacheScope": ["public", "private"]},
            issues=issues,
        )


@register_rule
class OriginValidationRule(ProbeBackedReadinessRule):
    """The HTTP endpoint rejects an invalid foreign Origin with HTTP 403."""

    rule_id = "readiness_2026_origin_validation"
    rule_order = 14
    probe_id = PROBE_ORIGIN_VALIDATION

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - invalid Origin rejected"

    @property
    def severity(self) -> RuleSeverity:
        # HIGH, not CRITICAL: for local or plain-http targets this is the direct
        # DNS-rebinding mitigation, for the remote HTTPS majority it is defence in depth.
        # The measured population behind the trade-off is in AGENTS.md.
        return RuleSeverity.HIGH

    def check(self, audit_data: AuditData) -> RuleResult:
        probe = self._probe(audit_data)
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        message = (
            "✅ Streamable HTTP rejects an invalid foreign Origin with HTTP 403"
            if passed
            else "❌ Streamable HTTP does not reject an invalid foreign Origin with HTTP 403, risking DNS rebinding"
        )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "spec": "https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#security-&-endpoint",
                "target_version": READINESS_TARGET,
                **probe.details,
            },
            suggested_fix=(
                "Validate supplied Origin headers against the origins allowed for this endpoint. "
                "Return HTTP 403 for invalid origins; do not allow every origin to satisfy browser "
                "requests."
            )
            if not passed
            else None,
            audit_data=audit_data,
            expected={"http_status": 403},
        )


@register_rule
class UnknownMethodErrorRule(ProbeBackedReadinessRule):
    """Unknown RPC methods return HTTP 404 and JSON-RPC -32601."""

    rule_id = "readiness_2026_unknown_method_error"
    rule_order = 15
    probe_id = PROBE_UNKNOWN_METHOD

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - unknown method error"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def check(self, audit_data: AuditData) -> RuleResult:
        probe = self._probe(audit_data)
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        message = (
            f"✅ Unknown RPC methods return JSON-RPC -32601{_http_clause(audit_data, ' with HTTP 404')}"
            if passed
            else (
                "❌ Unknown RPC methods do not return JSON-RPC -32601 (Method not found)"
                f"{_http_clause(audit_data, ' with HTTP 404')}"
            )
        )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "spec": "https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#protocol-version-header",
                "target_version": READINESS_TARGET,
                **probe.details,
            },
            suggested_fix=(
                "Return JSON-RPC -32601 (Method not found) for the unknown method."
                + _http_clause(audit_data, " On HTTP, use status 404.")
            )
            if not passed
            else None,
            audit_data=audit_data,
            expected={
                "error_code": -32601,
                **({} if audit_data.transport_type is MCPTransportType.STDIO else {"http_status": 404}),
            },
        )


@register_rule
class ResponseContentTypeRule(ReadinessBaseRule):
    """Successful modern requests use JSON or SSE response content types."""

    rule_id = "readiness_2026_response_content_type"
    rule_order = 16

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - response content type"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip unless a successful modern gateway response can be inspected.

        The gateway probes run over stdio too, but this rule judges a
        *Streamable HTTP* response header. A stdio server sends no headers at
        all, so an absent Content-Type there is not a finding — it is the
        question not applying. Judging it anyway would fail every stdio server
        for a header the transport has no way to send.
        """
        if audit_data.transport_type is MCPTransportType.STDIO:
            return SKIP_REASON_NOT_APPLICABLE
        probes = audit_data.probes or {}
        if not has_modern_support(probes):
            observed = [probes[pid] for pid in GATEWAY_PROBE_IDS if pid in probes]
            if not observed or all(p.outcome in (ProbeOutcome.ERROR, ProbeOutcome.NOT_APPLICABLE) for p in observed):
                return SKIP_REASON_INSUFFICIENT_DATA
            return SKIP_REASON_REQUIRES_MODERN_SUPPORT
        return None

    @staticmethod
    def _media_type(value: object) -> str | None:
        if not isinstance(value, str):
            return None
        return value.partition(";")[0].strip().lower()

    def check(self, audit_data: AuditData) -> RuleResult:
        probes = audit_data.probes or {}
        successful = {
            pid: probes[pid]
            for pid in GATEWAY_PROBE_IDS
            if pid in probes and probes[pid].outcome is ProbeOutcome.SUPPORTED
        }
        invalid = {
            pid: probe.details.get("content_type")
            for pid, probe in successful.items()
            if self._media_type(probe.details.get("content_type")) not in {"application/json", "text/event-stream"}
        }
        passed = not invalid
        # A missing header renders as `None`, which reads as a bug in the report
        # rather than a finding about the server. Name the absence instead.
        observed = ", ".join(
            f"{pid}: {evidence_preview(value) if value is not None else 'no Content-Type header'}"
            for pid, value in sorted(invalid.items())
        )
        message = (
            "✅ Successful Streamable HTTP requests return application/json or text/event-stream"
            if passed
            else f"❌ Successful Streamable HTTP responses use invalid content types — {observed}"
        )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "spec": "https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#sending-messages",
                "target_version": READINESS_TARGET,
                "observed": {pid: probe.details.get("content_type") for pid, probe in successful.items()},
            },
            suggested_fix=(
                "Set Content-Type to application/json for a JSON response or text/event-stream for "
                "SSE. Check reverse-proxy header rewriting as well as the MCP handler."
            )
            if not passed
            else None,
            audit_data=audit_data,
            expected={"Content-Type": ["application/json", "text/event-stream"]},
        )


@register_rule
class UnsupportedVersionErrorReadinessRule(ProbeBackedReadinessRule):
    """Unknown protocol versions are rejected with -32022 naming the supported versions.

    The error code alone is not enough: the schema requires the error's
    ``data`` to carry ``supported`` (the versions to retry with) and
    ``requested``, so a bare -32022 fails with its own message.
    """

    rule_id = "readiness_2026_unsupported_version_error"
    rule_order = 6
    probe_id = PROBE_UNKNOWN_VERSION

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - unsupported-version errors"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        probe = self._probe(audit_data)
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        if passed:
            message = f"✅ Unknown version: -32022; supported: {evidence_preview(probe.details.get('supported'))}"
        elif probe.details.get("data_well_formed") is False:
            message = (
                "❌ -32022 is emitted but its data block is missing or malformed — the error must "
                "carry data.supported (a non-empty list of versions to retry with) and data.requested"
            )
        else:
            message = (
                "❌ An unknown protocol version is not rejected with -32022 "
                "(UnsupportedProtocolVersion) listing the supported versions"
            )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2575", "target_version": READINESS_TARGET, **probe.details},
            suggested_fix=(
                (
                    "Add a well-formed data object to -32022: supported must list supported version "
                    "strings and requested must identify the requested revision."
                )
                if probe.details.get("data_well_formed") is False
                else (
                    "Reject an unsupported protocol revision with -32022 (UnsupportedProtocolVersion), "
                    "including data.supported and data.requested."
                )
            )
            if not passed
            else None,
            audit_data=audit_data,
            expected={
                "error_code": -32022,
                "data.supported": "non-empty array of version strings",
                "data.requested": "requested version string",
            },
        )


@register_rule
class ErrorCodeMigrationReadinessRule(ProbeBackedReadinessRule):
    """Missing resources yield -32602, not the legacy -32002 (SEP-2164).

    Applies only to servers that declare the ``resources`` capability: the
    -32602 requirement sits under "servers that support resources", and a
    server without the capability correctly answers ``resources/read`` with
    -32601 (Method not found).
    """

    rule_id = "readiness_2026_error_code_migration"
    rule_order = 7
    probe_id = PROBE_MISSING_RESOURCE

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when the server declares no resources capability."""
        if reason := super().skip_reason(audit_data):
            return reason
        capabilities = audit_data.capabilities
        if capabilities is not None and getattr(capabilities, "resources", None) is None:
            return SKIP_REASON_NOT_APPLICABLE
        return None

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - error-code migration"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        probe = self._probe(audit_data)
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        if passed:
            message = "✅ Missing resources are rejected with the standard -32602 (Invalid params)"
        elif probe.details.get("legacy_code_emitted"):
            message = (
                f"❌ Missing resources still yield the legacy -32002 — from {READINESS_TARGET} "
                "this code MUST NOT be emitted; use -32602 (SEP-2164)"
            )
        else:
            message = "❌ The missing-resource probe did not return JSON-RPC -32602"
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2164", "target_version": READINESS_TARGET, **probe.details},
            suggested_fix=(
                "Return JSON-RPC -32602 (Invalid params) when resources/read cannot find the requested"
                " URI on the modern protocol path. Preserve version-appropriate errors for supported "
                "legacy clients."
            )
            if not passed
            else None,
            audit_data=audit_data,
            expected={"error_code": -32602},
        )


@register_rule
class ResultTypeReadinessRule(ReadinessBaseRule):
    """Results carry the mandatory ``resultType`` discriminator (SEP-2322)."""

    rule_id = "readiness_2026_result_type"
    rule_order = 8

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - resultType on results"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Apply the same gating as the cache-metadata rule (needs a modern result)."""
        return CacheMetadataReadinessRule.skip_reason(self, audit_data)

    def check(self, audit_data: AuditData) -> RuleResult:
        probes = audit_data.probes or {}
        supported = {
            pid: probes[pid]
            for pid in GATEWAY_PROBE_IDS
            if pid in probes and probes[pid].outcome is ProbeOutcome.SUPPORTED
        }
        missing = [pid for pid, probe in supported.items() if probe.details.get("result_type") != "complete"]
        passed = not missing
        if passed:
            message = '✅ Modern results carry resultType: "complete"'
        else:
            message = (
                f"❌ Results have absent or invalid resultType (expected complete) (SEP-2322): "
                f"{', '.join(sorted(missing))}"
            )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "sep": "SEP-2322",
                "target_version": READINESS_TARGET,
                "observed": {pid: probe.details.get("result_type") for pid, probe in supported.items()},
            },
            suggested_fix=(
                'Include resultType: "complete" on each completed list/discover result. Check response'
                " serialization so the discriminator is not dropped."
            )
            if not passed
            else None,
            audit_data=audit_data,
            expected={"resultType": "complete"},
            issues=(
                _response_issue(pid, "/resultType", supported[pid].details.get("result_type"), "complete")
                for pid in missing
            ),
        )


@register_rule
class DeprecatedFeaturesReadinessRule(ReadinessBaseRule):
    """The server does not rely on features the target revision deprecates (SEP-2577).

    Server capabilities only declare server-side features, so this checks the
    ``logging`` capability (deprecated in 2026-07-28 in favor of stderr/
    OpenTelemetry). Roots and sampling are client features and not observable
    in a server audit.
    """

    rule_id = "readiness_2026_deprecated_features"
    rule_order = 9

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - deprecated features"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when no capabilities were collected (nothing to assess)."""
        return SKIP_REASON_INSUFFICIENT_DATA if audit_data.capabilities is None else None

    def check(self, audit_data: AuditData) -> RuleResult:
        target = DRAFT or LATEST
        flagged: list[str] = []
        capabilities = audit_data.capabilities
        if "logging" in target.deprecated_features and getattr(capabilities, "logging", None) is not None:
            flagged.append("logging")

        passed = not flagged
        if passed:
            message = f"✅ The deprecated logging capability is not declared for {READINESS_TARGET}"
        else:
            message = (
                f"❌ Server declares features deprecated in {READINESS_TARGET}: {', '.join(flagged)} "
                "(logging; SEP-2577)"
            )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "sep": "SEP-2577",
                "target_version": READINESS_TARGET,
                "deprecated_features_declared": flagged,
                "earliest_removal": "2027-07-28",
            },
            suggested_fix=(
                "Migrate logging to stderr for stdio or OpenTelemetry. Review the deprecated logging "
                "capability for the target revision; deprecation does not require immediate removal "
                "from supported legacy clients."
            )
            if not passed
            else None,
            audit_data=audit_data,
        )


def _find_network_refs(schema: Any, found: list[str]) -> None:
    """Collect ``$ref`` values resolving to network URIs (forbidden to auto-fetch)."""
    if isinstance(schema, dict):
        ref = schema.get("$ref")
        if isinstance(ref, str) and ref.startswith(("http://", "https://")):
            found.append(ref)
        for value in schema.values():
            _find_network_refs(value, found)
    elif isinstance(schema, list):
        for item in schema:
            _find_network_refs(item, found)


@register_rule
class ToolSchemaDialectReadinessRule(ReadinessBaseRule):
    """Tool schemas are valid under the default JSON Schema 2020-12 dialect (SEP-2106).

    From 2026-07-28 a schema without ``$schema`` defaults to JSON Schema
    2020-12 and MUST be valid under its declared-or-default dialect; ``$ref``
    values resolving to network URIs must not be auto-dereferenced, so they
    are flagged too. Schemas declaring a different dialect via ``$schema``
    are left alone — only the default is enforced here.
    """

    rule_id = "readiness_2026_tool_schema_dialect"
    rule_order = 10

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - tool schema dialect"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when no tools were collected (nothing to assess)."""
        return SKIP_REASON_INSUFFICIENT_DATA if audit_data.tools is None else None

    @staticmethod
    def _schema_problems(
        schema: dict[str, Any], index: int, path: str
    ) -> tuple[list[str], list[dict[str, Any]], str | None]:
        """Separate value-free labels and locations from the human-only preview."""
        declared = schema.get("$schema")
        problems: list[str] = []
        issues: list[dict[str, Any]] = []
        preview: str | None = None
        network_refs: list[str] = []
        _find_network_refs(schema, network_refs)
        problems.extend("network $ref requires resolution review" for _ in network_refs)
        if network_refs:
            preview = problems[0]
            issues.append(field_issue("tool", index, path, "network_reference", "no automatic network dereferencing"))
        if declared is None or declared == _JSON_SCHEMA_2020_12:
            try:
                Draft202012Validator.check_schema(schema)
            except SchemaError as error:
                problems.append("invalid under JSON Schema 2020-12")
                if preview is None:
                    preview = f"invalid under JSON Schema 2020-12: {evidence_preview(error.message)}"
                location = path + "".join("/" + pointer_token(str(part)) for part in error.absolute_path)
                issues.append(field_issue("tool", index, location, "invalid_schema", "valid JSON Schema 2020-12"))
        return problems, issues, preview

    def check(self, audit_data: AuditData) -> RuleResult:
        offending: dict[str, list[str]] = {}
        offending_indexes: dict[str, list[int]] = {}
        first_problem = ""
        issues: list[dict[str, Any]] = []
        for index, tool in enumerate(audit_data.tools or []):
            problems: list[str] = []
            for attribute, path in (("input_schema", "/inputSchema"), ("output_schema", "/outputSchema")):
                schema = getattr(tool, attribute, None)
                if isinstance(schema, dict):
                    schema_problems, schema_issues, preview = self._schema_problems(schema, index, path)
                    if not first_problem and preview is not None:
                        first_problem = preview
                    problems.extend(schema_problems)
                    issues.extend(schema_issues)
            if problems:
                name = getattr(tool, "name", "<unnamed>")
                # Keep the legacy name-keyed shape, unioning labels rather than
                # overwriting collisions. Indexes preserve every affected owner.
                labels = offending.setdefault(name, [])
                labels.extend(problem for problem in dict.fromkeys(problems) if problem not in labels)
                offending_indexes.setdefault(name, []).append(index)

        passed = not offending
        if passed:
            message = (
                "✅ Checked default-dialect schemas passed validation; no network references were found"
                " (other declared dialects not validated)"
            )
        else:
            affected_count = len({issue["entity_index"] for issue in issues})
            message = (
                f"❌ Schema validation or network-reference findings affect {affected_count} tool(s). "
                f"First finding: {first_problem}"
            )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "sep": "SEP-2106",
                "target_version": READINESS_TARGET,
                "offending_tools": offending,
                "offending_tool_indexes": offending_indexes,
            },
            suggested_fix=(
                "Fix schemas under their declared or default dialect. For network $ref findings, "
                "bundle local definitions or verify preloaded resolution; clients must not "
                "automatically fetch network references."
            )
            if not passed
            else None,
            audit_data=audit_data,
            issues=issues,
        )


@register_rule
class NoSessionIdReadinessRule(ProbeBackedReadinessRule):
    """Legacy-leakage check: no ``Mcp-Session-Id`` minted or echoed on modern requests.

    Protocol-level sessions are removed in the target revision (SEP-2567). A
    server that serves modern requests SHOULD ignore an incoming
    ``Mcp-Session-Id`` and not mint or echo one — the strength the spec's
    backward-compatibility section uses. Runs only when modern support was
    detected (inverse gating): a legacy-only server keeping sessions is correct
    behavior, not leakage.
    """

    rule_id = "readiness_2026_no_session_id"
    rule_order = 11
    probe_id = PROBE_SESSION_ID_ECHO

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - no session IDs"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def check(self, audit_data: AuditData) -> RuleResult:
        probe = self._probe(audit_data)
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        echoed = probe.details.get("response_session_id")
        if passed:
            message = "✅ Server ignores a spurious Mcp-Session-Id and mints none of its own"
        elif echoed is not None:
            message = (
                f"❌ Server echoes/mints an Mcp-Session-Id on a modern request — "
                f"protocol-level sessions are removed in {READINESS_TARGET}; servers should not "
                "mint or echo session IDs (SEP-2567)"
            )
        else:
            message = (
                "❌ Server does not serve a modern request carrying a spurious Mcp-Session-Id — "
                "the header should be ignored, not treated as an error (SEP-2567)"
            )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2567", "target_version": READINESS_TARGET, **probe.details},
            suggested_fix=(
                (
                    "Stop adding Mcp-Session-Id to modern responses, including in shared proxy/session "
                    "middleware. Retain required session handling only for supported legacy revisions."
                )
                if echoed is not None
                else (
                    "Ignore a spurious Mcp-Session-Id on modern requests and serve them from per-request "
                    "context. Keep legacy session validation on the legacy lifecycle."
                )
            )
            if not passed
            else None,
            audit_data=audit_data,
        )


@register_rule
class RemovedMethodsReadinessRule(ProbeBackedReadinessRule):
    """Legacy-leakage check: removed methods are rejected, not served.

    ``ping`` (representative of the methods removed in the target revision:
    ``ping``, ``logging/setLevel``, ``resources/subscribe``) is an unknown
    method there — the server MUST reject it with HTTP 404 and JSON-RPC
    ``-32601``. Runs only when modern support was detected.
    """

    rule_id = "readiness_2026_removed_methods"
    rule_order = 12
    probe_id = PROBE_REMOVED_METHOD

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - removed methods"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        probe = self._probe(audit_data)
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        if passed:
            message = (
                f"✅ Removed method '{REMOVED_METHOD}' is rejected with "
                f"-32601{_http_clause(audit_data, ' and HTTP 404')}"
            )
        elif probe.details.get("method_served"):
            message = (
                f"❌ Server still serves '{REMOVED_METHOD}', which is removed in {READINESS_TARGET} — "
                "leaked legacy surface (SEP-2575)"
            )
        else:
            message = (
                f"❌ Removed method '{REMOVED_METHOD}' is not rejected with "
                f"-32601{_http_clause(audit_data, ' and HTTP 404')} "
                "(Method not found) as the spec requires"
            )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2575", "target_version": READINESS_TARGET, **probe.details},
            suggested_fix=(
                (
                    "Stop dispatching ping on the modern protocol path; return JSON-RPC -32601."
                    if probe.details.get("method_served")
                    else "Correct the modern ping rejection to JSON-RPC -32601 (Method not found)."
                )
                + _http_clause(audit_data, " On HTTP, use status 404.")
                + " Retain ping for supported legacy revisions."
            )
            if not passed
            else None,
            audit_data=audit_data,
            expected={
                "error_code": -32601,
                **({} if audit_data.transport_type is MCPTransportType.STDIO else {"http_status": 404}),
            },
        )


_STREAMABLE_HTTP_SPEC = "https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http"


class HeaderRequirementReadinessRule(ProbeBackedReadinessRule):
    """Base for HTTP request-header rules requiring HeaderMismatch plus HTTP 400."""

    header_description: ClassVar[str]
    repair_hint: ClassVar[str]

    @property
    def severity(self) -> RuleSeverity:
        # Four correlated header-validation rules fail 83-97% of judgeable
        # modern-only servers in the 2026-08-24 registry calibration. Keep the
        # normative findings visible without subtracting 12 points from nearly
        # the entire early-adoption population.
        return RuleSeverity.LOW

    def check(self, audit_data: AuditData) -> RuleResult:
        probe = self._probe(audit_data)
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        message = (
            f"✅ Server rejects {self.header_description} with -32020 and HTTP 400"
            if passed
            else f"❌ Server does not reject {self.header_description} with -32020 (HeaderMismatch) and HTTP 400"
        )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "spec": f"{_STREAMABLE_HTTP_SPEC}#server-validation",
                "target_version": READINESS_TARGET,
                **probe.details,
            },
            suggested_fix=self.repair_hint if not passed else None,
            audit_data=audit_data,
            expected={"error_code": -32020, "http_status": 400},
        )


@register_rule
class MissingProtocolVersionHeaderReadinessRule(
    ModernOnlyHttpProbeBackedReadinessRule,
    HeaderRequirementReadinessRule,
):
    """Modern-only endpoints reject a missing MCP-Protocol-Version header."""

    rule_id = "readiness_2026_missing_protocol_version_rejected"
    rule_order = 17
    probe_id = PROBE_MISSING_PROTOCOL_VERSION
    header_description = "a request missing MCP-Protocol-Version"
    repair_hint = (
        "On a modern-only endpoint, require MCP-Protocol-Version and return JSON-RPC -32020 "
        "with HTTP 400 when absent. Preserve the permitted fallback for supported older "
        "clients."
    )

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - missing protocol-version header rejected"


@register_rule
class MissingMethodHeaderReadinessRule(HeaderRequirementReadinessRule):
    """HTTP endpoints reject a request missing the required Mcp-Method header."""

    rule_id = "readiness_2026_missing_method_header_rejected"
    rule_order = 18
    probe_id = PROBE_MISSING_METHOD_HEADER
    header_description = "a request missing Mcp-Method"
    repair_hint = (
        "Require Mcp-Method on requests to the modern HTTP endpoint. Return JSON-RPC -32020 "
        "(HeaderMismatch) with HTTP 400 when it is absent, before dispatching the method."
    )

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - missing method header rejected"


@register_rule
class ResourceNameHeaderMismatchReadinessRule(HeaderRequirementReadinessRule):
    """HTTP endpoints reject a resources/read request whose Mcp-Name contradicts its URI."""

    rule_id = "readiness_2026_resource_name_header_mismatch_rejected"
    rule_order = 19
    probe_id = PROBE_RESOURCE_NAME_HEADER_MISMATCH
    header_description = "a resources/read request whose Mcp-Name contradicts params.uri"
    repair_hint = (
        "Decode Mcp-Name and compare it with params.uri for resources/read. Return JSON-RPC "
        "-32020 with HTTP 400 on a mismatch, before reading the resource."
    )

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - resource name-header mismatch rejected"


@register_rule
class PromptNameHeaderMismatchReadinessRule(HeaderRequirementReadinessRule):
    """HTTP endpoints reject a prompts/get request whose Mcp-Name contradicts its name."""

    rule_id = "readiness_2026_prompt_name_header_mismatch_rejected"
    rule_order = 20
    probe_id = PROBE_PROMPT_NAME_HEADER_MISMATCH
    header_description = "a prompts/get request whose Mcp-Name contradicts params.name"
    repair_hint = (
        "Decode Mcp-Name and compare it with params.name for prompts/get. Return JSON-RPC "
        "-32020 with HTTP 400 on a mismatch, before resolving the prompt."
    )

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - prompt name-header mismatch rejected"


@register_rule
class GetStreamRemovedReadinessRule(ModernOnlyHttpProbeBackedReadinessRule):
    """Modern-only endpoints reject the removed standalone GET stream with HTTP 405."""

    rule_id = "readiness_2026_no_get_stream"
    rule_order = 21
    probe_id = PROBE_GET_STREAM_REMOVED

    @property
    def rule_name(self) -> str:
        return f"Readiness {READINESS_TARGET} - no standalone GET stream"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        probe = self._probe(audit_data)
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        message = (
            "✅ Streamable HTTP rejects the removed standalone GET stream with HTTP 405"
            if passed
            else "❌ Streamable HTTP does not reject the removed standalone GET stream with HTTP 405"
        )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "spec": f"{_STREAMABLE_HTTP_SPEC}#earlier-streamable-http-revisions",
                "target_version": READINESS_TARGET,
                **probe.details,
            },
            suggested_fix=(
                "Return HTTP 405 for a standalone GET on a modern-only endpoint. Keep legacy GET "
                "streaming where a supported older transport revision requires it."
            )
            if not passed
            else None,
            audit_data=audit_data,
            expected={"http_status": 405},
        )
