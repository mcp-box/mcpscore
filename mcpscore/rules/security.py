import re
from typing import ClassVar

from ..enums import MCPTransportType
from ..probes import PROBE_MALFORMED_JSON, PROBE_ORIGIN_VALIDATION, ProbeOutcome
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
class TLSEnabledRule(BaseRule):
    """Check if the server uses HTTPS with valid TLS.

    This is a critical security check ensuring that the connection is encrypted
    and the TLS certificate is properly verified.

    Scoring: 5 points (CRITICAL)
    """

    rule_id = "security_tls_enabled"
    basis = "MCP 2025-11-25 Transports §Streamable HTTP Security Warning; TLS transport-security best practice"
    group_name = "security"
    group_order = 3
    rule_order = 1

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when TLS does not apply or its remote observation is missing."""
        if audit_data.transport_type == MCPTransportType.STDIO:
            return SKIP_REASON_NOT_APPLICABLE
        if audit_data.url is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        if audit_data.url.startswith("https://") and audit_data.tls_verified is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    @property
    def rule_name(self) -> str:
        return "HTTPS/TLS Enabled"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    @requires_fields("url", "tls_verified", "tls_version")
    def check(self, url: str | None, tls_verified: bool | None, tls_version: str | None) -> RuleResult:  # type: ignore[override]
        """Check if HTTPS/TLS is enabled and properly configured.

        Args:
            url: The server URL
            tls_verified: Whether TLS certificate was verified
            tls_version: TLS version used

        Returns:
            RuleResult indicating pass/fail

        """
        assert url is not None  # noqa: S101 — skip_reason guarantees a remote URL

        # Check if URL uses HTTPS
        if not url.startswith("https://"):
            return diagnostic_result(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message="❌ The audited remote endpoint does not use HTTPS",
                details={"url": url, "scheme": "http"},
                suggested_fix="Serve the remote MCP endpoint over HTTPS with a trusted certificate and TLS 1.2 or 1.3.",
            )

        # Check if TLS was verified
        if tls_verified is False:
            return diagnostic_result(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message="❌ TLS certificate verification failed for the audited endpoint",
                details={"url": url},
                suggested_fix=(
                    "Repair the TLS certificate chain, hostname and expiry at the server or proxy. "
                    "Re-audit with verification enabled; do not bypass certificate validation."
                ),
            )

        # Check TLS version (should be 1.2 or higher)
        if tls_version and tls_version not in ["TLSv1.2", "TLSv1.3"]:
            return diagnostic_result(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message=f"⚠️ Outdated TLS version: {tls_version}. Should use TLS 1.2 or 1.3.",
                details={"url": url, "tls_version": tls_version},
                suggested_fix=(
                    "Enable TLS 1.2 or 1.3 at the MCP endpoint or TLS-terminating proxy, then re-audit the"
                    " negotiated connection."
                ),
            )

        # All checks passed
        message = "✅ Server uses HTTPS with valid TLS"
        if tls_version:
            message += f" ({tls_version})"

        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=True,
            message=message,
            details={"url": url, "tls_version": tls_version},
            suggested_fix=None,
        )


@register_rule
class MalformedRequestHandlingRule(BaseRule):
    """Check the JSON-RPC response to malformed JSON.

    The **normative** requirement this rule enforces is the JSON-RPC 2.0 Parse
    error code (``-32700``). Strict JSON-RPC additionally requires the response
    ``id`` to be present and null when the request id cannot be detected; this
    rule **deliberately relaxes that one point** and also accepts an *absent*
    id — the id is genuinely unknowable when the request never parsed, no
    client correlates a parse error by id, and a registry calibration
    (2026-08-22) found conforming servers that omit it. This is a calibrated
    interoperability allowance, not full JSON-RPC Response Object conformance.
    The transport-agnostic specification does not prescribe an HTTP status, so
    this rule does not either.

    Scoring: 2 points (MEDIUM)
    """

    rule_id = "security_malformed_request_handling"
    basis = (
        "JSON-RPC 2.0 §Response Object / §Error Object: -32700 Parse error (enforced). "
        "Strict JSON-RPC requires the id present and null; a null OR absent id is accepted "
        "as a calibrated interoperability allowance."
    )
    group_name = "security"
    group_order = 3
    rule_order = 2

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when the raw malformed-request response is unobservable."""
        if audit_data.transport_type == MCPTransportType.STDIO:
            # The JSON-RPC requirement applies, but the SDK-backed stdio probe
            # cannot safely inject a truncated wire message. That is missing
            # evidence, not an inapplicable requirement.
            return SKIP_REASON_INSUFFICIENT_DATA
        probe = (audit_data.probes or {}).get(PROBE_MALFORMED_JSON)
        if probe is not None and probe.outcome is ProbeOutcome.NOT_APPLICABLE:
            return SKIP_REASON_NOT_APPLICABLE
        if probe is None or probe.outcome is ProbeOutcome.ERROR:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    @property
    def rule_name(self) -> str:
        return "Malformed Request Handling"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        """Require the exact JSON-RPC parse-error shape, independent of HTTP status."""
        probe = (audit_data.probes or {})[PROBE_MALFORMED_JSON]
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=(
                "✅ Malformed JSON returns JSON-RPC -32700 (Parse error) with a null or absent ID"
                if passed
                else "❌ Malformed JSON does not return JSON-RPC -32700 (Parse error) with a null or absent ID"
            ),
            details={
                "spec": "https://www.jsonrpc.org/specification#response_object",
                "http_status": probe.details.get("http_status"),
                "error_code": probe.details.get("error_code"),
                "response_id_absent_or_null": probe.details.get("response_id_absent_or_null"),
                "control_http_status": probe.details.get("control_http_status"),
            },
            suggested_fix=(
                (
                    "Return id: null for an unparsable JSON request; this check also accepts an absent "
                    "id. Do not echo an unrelated request identifier."
                )
                if probe.details.get("error_code") == -32700
                else (
                    "Catch JSON parsing failures and return JSON-RPC -32700 with id: null. This check also"
                    " accepts an absent id and imposes no HTTP status requirement."
                )
            )
            if not passed
            else None,
            audit_data=audit_data,
            expected={"error_code": -32700, "response_id_absent_or_null": True},
        )


@register_rule
class ErrorDataLeakRule(BaseRule):
    """Check if error responses leak sensitive data.

    Error messages should not contain sensitive information like:
    - File paths
    - Stack traces
    - Credentials
    - API keys or tokens

    Scoring: 2 points (MEDIUM)
    """

    rule_id = "security_error_data_leak"
    basis = "MCP 2025-11-25 Tools §Security Considerations (sanitize outputs); error-hygiene best practice"
    group_name = "security"
    group_order = 3
    rule_order = 3

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip unless the malformed-request probe captured a response body.

        Leakage is judged from the body the malformed-JSON probe elicited —
        the request most likely to make a server dump a stack trace or a file
        path. What matters is only whether a body was captured, not the
        probe's own parse-error verdict: an auth-gated server (probe
        not-applicable) still returns a 401 body worth scanning. The probe is
        HTTP-only, so stdio is the sole not-applicable case; no captured body
        is insufficient data.
        """
        if audit_data.transport_type == MCPTransportType.STDIO:
            return SKIP_REASON_NOT_APPLICABLE
        probe = (audit_data.probes or {}).get(PROBE_MALFORMED_JSON)
        if probe is None or self._probe_body(probe) is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    @staticmethod
    def _probe_body(probe: object) -> str | None:
        """Return the raw error body the probe carries on its payload, if any."""
        payload = getattr(probe, "payload", None)
        body = payload.get("error_body") if isinstance(payload, dict) else None
        return body if isinstance(body, str) else None

    # Structural leaks — the pattern's presence IS the leak (a path or a stack
    # trace in an error body is a defect regardless of any value).
    STRUCTURAL_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (r"/home/\w+", "file path"),
        (r"/usr/\w+", "file path"),
        (r"C:\\Users\\", "file path"),
        (r"Traceback \(most recent call last\)", "stack trace"),
        (r"at \w+\.\w+ \([^)]+:\d+:\d+\)", "stack trace"),  # JavaScript stack trace
    ]

    # The realistic alphabet of a leaked credential value. Covers RFC 6750
    # b64token (base64 / base64url with optional `=` padding — `A-Za-z0-9`
    # `-._~+/`) so an opaque bearer like `Ab1+/cDefGh==` is captured whole and
    # not truncated to `Ab1` and dropped as "too short". `\w` supplies the
    # alphanumerics and `_`.
    _CRED_VALUE_RE: ClassVar[str] = r"[\w.~+/-]+=*"
    _WIDE_CRED_VALUE_RE: ClassVar[str] = r"[\w!@#$%^&*.~+/-]+=*"  # passwords add shell/symbol chars

    # Credential leaks — a match is a leak only if the *captured value* (group
    # 1) looks like a real secret. This rule now scans live auth-gated error
    # bodies, which routinely say "Bearer token required" or
    # "password=redacted"; matching the keyword alone would fail well-behaved
    # servers that leak nothing. See _is_probable_secret.
    CREDENTIAL_PATTERNS: ClassVar[list[tuple[str, str]]] = [
        (rf'password["\']?\s*[:=]\s*["\']?({_WIDE_CRED_VALUE_RE})', "password"),
        (rf'secret["\']?\s*[:=]\s*["\']?({_WIDE_CRED_VALUE_RE})', "secret"),
        (rf'api[_-]?key["\']?\s*[:=]\s*["\']?({_CRED_VALUE_RE})', "API key"),
        (rf'token["\']?\s*[:=]\s*["\']?({_CRED_VALUE_RE})', "token"),
        (rf"Bearer\s+({_CRED_VALUE_RE})", "auth token"),
    ]

    # Values that are descriptions of a secret, not a secret. A credential
    # match whose value contains one of these (or is too short / too
    # low-entropy) is a placeholder, not a leak.
    _PLACEHOLDER_WORDS: ClassVar[frozenset[str]] = frozenset(
        {
            "required",
            "redacted",
            "missing",
            "none",
            "null",
            "empty",
            "example",
            "placeholder",
            "changeme",
            "here",
            "your",
            "token",
            "key",
            "secret",
            "value",
            "string",
            "password",
            "hidden",
            "provided",
            "expected",
            "invalid",
            "unauthorized",
            "masked",
            "omitted",
            "removed",
            "xxx",
        }
    )

    @classmethod
    def _is_probable_secret(cls, value: str) -> bool:
        """Whether a captured credential value looks like a real leaked secret.

        Rejects placeholders ("required", "redacted", ...), short values, and
        low-entropy words — the shapes a well-behaved auth-gated body produces.
        A real key/token is long and mixes character classes.
        """
        stripped = value.strip().strip("'\"`<>*[]{}()")
        if len(stripped) < 8:
            return False
        low = stripped.lower()
        if any(word in low for word in cls._PLACEHOLDER_WORDS):
            return False
        classes = sum(
            (
                any(c.islower() for c in stripped),
                any(c.isupper() for c in stripped),
                any(c.isdigit() for c in stripped),
                any(not c.isalnum() for c in stripped),
            )
        )
        return classes >= 2 or len(stripped) >= 20

    @property
    def rule_name(self) -> str:
        return "No Sensitive Data in Error Messages"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        """Scan the malformed-request response body for sensitive-data leaks."""
        probe = (audit_data.probes or {})[PROBE_MALFORMED_JSON]
        error_response = self._probe_body(probe)
        assert error_response is not None  # noqa: S101 — skip_reason guarantees a captured body

        # Record only the leak TYPE and a count — never the matched value.
        # This report is shareable (the /s share page renders results), so
        # echoing the server's leaked secret back into our own output would
        # re-leak it. The count lets the server owner gauge severity.
        leaks_found = []
        for pattern, leak_type in self.STRUCTURAL_PATTERNS:
            matches = re.findall(pattern, error_response, re.IGNORECASE)
            if matches:
                leaks_found.append({"type": leak_type, "count": len(matches)})
        for pattern, leak_type in self.CREDENTIAL_PATTERNS:
            # A credential keyword is a leak only if its value is a real secret,
            # not a placeholder ("Bearer token required", "password=redacted").
            real = [m for m in re.findall(pattern, error_response, re.IGNORECASE) if self._is_probable_secret(m)]
            if real:
                leaks_found.append({"type": leak_type, "count": len(real)})

        if leaks_found:
            leak_types = ", ".join(dict.fromkeys(leak["type"] for leak in leaks_found))
            return diagnostic_result(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message=f"❌ The sampled error response contains potential sensitive-data findings: {leak_types}",
                details={"leaks": leaks_found},
                suggested_fix=(
                    "Remove stack traces, internal paths and secrets from client errors; keep diagnostic "
                    "context in access-controlled logs. If a finding is a real exposed credential, revoke "
                    "or rotate it."
                ),
                audit_data=audit_data,
            )

        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=True,
            message="✅ No sensitive-data patterns were detected in the sampled error response",
            details={"error_response_length": len(error_response)},
            suggested_fix=None,
            audit_data=audit_data,
        )


@register_rule
class OriginHeaderValidationRule(BaseRule):
    """The Streamable HTTP endpoint rejects an invalid foreign ``Origin`` with HTTP 403.

    Every Streamable HTTP revision requires servers to validate the ``Origin``
    header of incoming connections, the direct mitigation for DNS rebinding.
    The observation comes from ``probe_origin_validation``: a control request
    without the header must be accepted before a foreign-Origin twin is judged,
    so an access-controlled server is never credited for a 403 it gives everyone.

    Scoring: 3 points (HIGH)
    """

    rule_id = "security_origin_validation"
    basis = (
        "MCP 2025-11-25 Transports §Security Warning and 2026-07-28 Streamable HTTP §Security: "
        "servers MUST validate the Origin header on all incoming connections to prevent DNS "
        "rebinding, rejecting an invalid Origin with HTTP 403"
    )
    group_name = "security"
    group_order = 3
    rule_order = 4
    probe_id: ClassVar[str] = PROBE_ORIGIN_VALIDATION

    LEGACY_SPEC: ClassVar[str] = (
        "https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#security-warning"
    )
    MODERN_SPEC: ClassVar[str] = (
        "https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#security-&-endpoint"
    )

    @property
    def rule_name(self) -> str:
        return "Origin Header Validated"

    @property
    def severity(self) -> RuleSeverity:
        # HIGH, not CRITICAL: for local or plain-http targets this is the direct
        # DNS-rebinding mitigation, for the remote HTTPS majority it is defence in depth.
        return RuleSeverity.HIGH

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when Origin handling could not be observed.

        Origin is an HTTP construct, so stdio is not-applicable (the TLS and
        error-leak precedent). The probe reports not-applicable when its
        control request is access-controlled or rejected in both request
        shapes; a missing or errored probe is insufficient data.
        """
        if audit_data.transport_type == MCPTransportType.STDIO:
            return SKIP_REASON_NOT_APPLICABLE
        probe = (audit_data.probes or {}).get(self.probe_id)
        if probe is not None and probe.outcome is ProbeOutcome.NOT_APPLICABLE:
            return SKIP_REASON_NOT_APPLICABLE
        if probe is None or probe.outcome is ProbeOutcome.ERROR:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def check(self, audit_data: AuditData) -> RuleResult:
        """Pass when the foreign-Origin request was refused with HTTP 403."""
        probe = (audit_data.probes or {})[self.probe_id]
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        shape = probe.details.get("control_shape")
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=(
                "✅ Streamable HTTP rejects an invalid foreign Origin with HTTP 403"
                if passed
                else "❌ Streamable HTTP does not reject an invalid foreign Origin with HTTP 403, risking DNS rebinding"
            ),
            details={
                "spec": self.LEGACY_SPEC if shape == "legacy-initialize" else self.MODERN_SPEC,
                "http_status": probe.details.get("http_status"),
                "control_http_status": probe.details.get("control_http_status"),
                "control_shape": shape,
                # Present only after a fallback: the modern control this server rejected.
                **{k: probe.details[k] for k in ("modern_control_http_status",) if k in probe.details},
            },
            suggested_fix=(
                None
                if passed
                else (
                    "Validate supplied Origin headers against the origins allowed for this endpoint. "
                    "Return HTTP 403 for invalid origins; do not allow every origin to satisfy browser requests."
                )
            ),
            audit_data=audit_data,
            expected={"http_status": 403},
        )
