"""Authorization-posture rules (RFC 9728 protected resource metadata).

These rules score how an auth-gated server presents its authorization
surface — the one part of an authenticated server mcpscore can audit without
credentials. They gate on the unauthenticated probe observing HTTP 401 or
403: a server that serves anonymous requests has no auth posture to grade,
and the rules skip as not-applicable rather than handing out free points.

Normative basis (cited per rule, re-verify at spec-final): the MCP
Authorization spec (2025-06-18 and later) makes MCP servers OAuth 2.0
protected resources. Since 2025-11-25 a server may publish its metadata through
the challenge's ``resource_metadata`` URL or at an RFC 9728 well-known location;
the probe follows them in the order a client does. RFC 9728 metadata has a
``resource`` value matching the server, and it MUST list at least one
authorization server. The deeper rules follow the discovery chain to the
authorization server's own metadata, validate its issuer, and check it
advertises PKCE (S256), per the OAuth security BCP (RFC 9700), and a way for
a client with no prior relationship to register. One rule sends a fabricated
bearer token, which the server must refuse with 401.
"""

from typing import ClassVar

from mcpscore.report_evidence import evidence_preview
from mcpscore.spec import compare

from ..probes import (
    AUTH_GATED_STATUSES,
    PROBE_AUTH_METADATA,
    PROBE_INVALID_TOKEN,
    PROBE_UNAUTHENTICATED,
    ProbeOutcome,
    ProbeResult,
    www_authenticate_param,
)
from .base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_NOT_APPLICABLE,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
)
from .probe_diagnostics import diagnostic_result
from .registry import register_rule


def _normalized(url: str) -> str:
    """Normalize a resource URL for comparison (trailing slash only)."""
    return url.rstrip("/")


EITHER_DISCOVERY_SINCE = "2025-11-25"
"""First revision where well-known discovery alone satisfies the server (challenge parameter optional)."""


def _challenge_param_required(audit_data: AuditData) -> bool:
    """Whether the negotiated revision requires ``resource_metadata`` in a 401 challenge.

    2025-06-18 requires it; 2025-11-25 and later accept well-known discovery
    instead. An unknown version is judged by the current revision.
    """
    version = audit_data.protocol_version
    return version is not None and compare(version, EITHER_DISCOVERY_SINCE) < 0


class AuthPostureBaseRule(BaseRule):
    """Base class for auth-posture rules: security group, auth-gated servers only."""

    group_name = "security"
    group_order = 3
    min_spec_version = "2025-06-18"

    required_probe_ids: ClassVar[tuple[str, ...]] = (PROBE_UNAUTHENTICATED,)
    """Probes whose observations this rule needs; unavailable → skip."""

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip unless an unauthenticated request was challenged (HTTP 401/403).

        A server that serves anonymous requests (any other status) has no auth
        posture to grade, so the rules skip as not-applicable.
        """
        probes = audit_data.probes or {}
        for probe_id in self.required_probe_ids:
            result = probes.get(probe_id)
            if result is None or result.outcome in (ProbeOutcome.ERROR, ProbeOutcome.NOT_APPLICABLE):
                return SKIP_REASON_INSUFFICIENT_DATA
        if probes[PROBE_UNAUTHENTICATED].details.get("http_status") not in AUTH_GATED_STATUSES:
            return SKIP_REASON_NOT_APPLICABLE
        return None

    def _probe(self, audit_data: AuditData, probe_id: str) -> ProbeResult:
        """Return a required probe's result (skip_reason guarantees presence)."""
        assert audit_data.probes is not None  # noqa: S101 — guaranteed by skip_reason
        return audit_data.probes[probe_id]


@register_rule
class AuthWwwAuthenticateRule(AuthPostureBaseRule):
    """High check: a gated (401/403) response carries a ``WWW-Authenticate`` challenge."""

    rule_id = "auth_www_authenticate"
    rule_order = 4

    @property
    def rule_name(self) -> str:
        return "Auth - WWW-Authenticate Challenge"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def check(self, audit_data: AuditData) -> RuleResult:
        """High check: the auth challenge includes a WWW-Authenticate header.

        A 401 OAuth response carries an authentication challenge. MCP also permits
        well-known metadata discovery without a resource_metadata challenge
        parameter. This rule runs for 403-gated servers too, so its repair
        distinguishes the observed status from the normative 401 requirement.

        Args:
            audit_data: The collected server data for this audit

        Returns:
            RuleResult with the check outcome

        """
        probe = self._probe(audit_data, PROBE_UNAUTHENTICATED)
        status = probe.details.get("http_status")
        challenge = probe.details.get("www_authenticate")
        passed = isinstance(challenge, str) and bool(challenge.strip())
        message = (
            f"✅ The observed HTTP {status} response carries a non-empty WWW-Authenticate challenge"
            if passed
            else f"❌ The observed HTTP {status} response has no non-empty WWW-Authenticate challenge"
        )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "basis": "MCP Authorization (2025-06-18+); RFC 9728 §5.1",
                "www_authenticate": challenge,
                "http_status": status,
            },
            suggested_fix=(
                "Check why anonymous access returns 403 and whether OAuth discovery applies. "
                "Provide an appropriate challenge when authentication is needed; do not change "
                "valid permission-denied responses to 401 just to pass this check."
                if status == 403
                else "Return a non-empty WWW-Authenticate challenge on HTTP 401 using the appropriate "
                "authentication scheme. Check that a reverse proxy does not remove the header."
            )
            if not passed
            else None,
            audit_data=audit_data,
        )


@register_rule
class AuthProtectedResourceMetadataRule(AuthPostureBaseRule):
    """High check: RFC 9728 protected resource metadata exists and names this server."""

    rule_id = "auth_protected_resource_metadata"
    rule_order = 5
    required_probe_ids = (PROBE_UNAUTHENTICATED, PROBE_AUTH_METADATA)

    @property
    def rule_name(self) -> str:
        return "Auth - Protected Resource Metadata"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def check(self, audit_data: AuditData) -> RuleResult:
        """High check: a discoverable metadata document exists and matches.

        The document is the one a client would use: the challenge's
        ``resource_metadata`` URL when it serves metadata, otherwise the RFC
        9728 well-known locations. RFC 9728 §3.3 requires its ``resource``
        value to identify the protected resource; clients must not use a
        document naming a different one.

        Args:
            audit_data: The collected server data for this audit

        Returns:
            RuleResult with the check outcome

        """
        probe = self._probe(audit_data, PROBE_AUTH_METADATA)
        details = {
            "basis": (
                "MCP Authorization (Protected Resource Metadata Discovery Requirements); "
                "RFC 9728 §3 (well-known location), §3.3 (resource validation), §5.1 (resource_metadata)"
            ),
            **probe.details,
        }
        if probe.outcome is not ProbeOutcome.SUPPORTED:
            return diagnostic_result(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message="❌ No usable RFC 9728 metadata was observed at the challenge URL or the well-known locations",
                details=details,
                suggested_fix=(
                    "Serve an anonymous HTTP 200 JSON metadata document at the RFC 9728 well-known "
                    "location or at a resource_metadata URL in the 401 challenge, with resource identifying "
                    "the MCP endpoint and authorization_servers naming its trusted issuers."
                ),
                audit_data=audit_data,
            )

        resource = str(probe.details.get("resource"))
        matches = audit_data.url is not None and _normalized(resource) == _normalized(audit_data.url)
        details["resource_matches"] = matches
        message = (
            f"✅ Protected resource metadata identifies {evidence_preview(resource)}"
            if matches
            else (
                f"❌ Metadata resource {evidence_preview(resource)} does not match "
                f"endpoint {evidence_preview(audit_data.url)}"
            )
        )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=matches,
            message=message,
            details=details,
            suggested_fix=(
                (
                    "Set resource in the metadata to the audited MCP resource identifier. Check "
                    "proxy/public URL configuration and RFC 9728 resource identity validation."
                )
                if not matches
                else None
            ),
            audit_data=audit_data,
        )


@register_rule
class AuthAuthorizationServersHttpsRule(AuthPostureBaseRule):
    """High check: the metadata lists authorization servers, all on HTTPS."""

    rule_id = "auth_authorization_servers_https"
    rule_order = 6
    required_probe_ids = (PROBE_UNAUTHENTICATED, PROBE_AUTH_METADATA)

    @property
    def rule_name(self) -> str:
        return "Auth - Authorization Servers Present and HTTPS"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Additionally skip when there is no metadata document to inspect.

        The metadata rule already grades absence; failing here too would
        double-count one defect.
        """
        reason = super().skip_reason(audit_data)
        if reason is not None:
            return reason
        if self._probe(audit_data, PROBE_AUTH_METADATA).outcome is not ProbeOutcome.SUPPORTED:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def check(self, audit_data: AuditData) -> RuleResult:
        """High check: at least one authorization server, every entry HTTPS.

        Clients authenticate against the listed authorization servers; an
        empty list leaves them nowhere to go, and a plain-HTTP entry exposes
        the token exchange.

        Args:
            audit_data: The collected server data for this audit

        Returns:
            RuleResult with the check outcome

        """
        servers = self._probe(audit_data, PROBE_AUTH_METADATA).details.get("authorization_servers") or []
        # An entry is valid only if it is a string on HTTPS; anything else
        # (plain HTTP, null, a number) is a malformed entry, not a pass.
        invalid = [
            server for server in servers if not (isinstance(server, str) and server.lower().startswith("https://"))
        ]
        if not servers:
            passed = False
            message = "❌ Protected resource metadata lists no authorization servers to authenticate against"
        elif invalid:
            passed = False
            message = f"❌ Number of authorization servers not on HTTPS or malformed: {len(invalid)}"
        else:
            passed = True
            message = f"✅ All {len(servers)} authorization server(s) use HTTPS"
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "basis": "RFC 9728 §2 (authorization_servers)",
                "authorization_servers": servers,
                "invalid": invalid,
            },
            suggested_fix=(
                "Add at least one trusted HTTPS OAuth issuer to authorization_servers."
                if not servers
                else (
                    "Replace malformed or non-HTTPS authorization_servers entries with the actual trusted "
                    "HTTPS issuer identifiers."
                )
            )
            if not passed
            else None,
            audit_data=audit_data,
        )


class AuthMetadataBaseRule(AuthPostureBaseRule):
    """Auth-posture rule that needs the RFC 9728 protected-resource metadata.

    Beyond the base 401/403 gate, these rules skip when no metadata document
    was found — that absence is already the AuthProtectedResourceMetadataRule's
    finding, so re-failing here would double-count one defect.
    """

    required_probe_ids = (PROBE_UNAUTHENTICATED, PROBE_AUTH_METADATA)

    def skip_reason(self, audit_data: AuditData) -> str | None:
        reason = super().skip_reason(audit_data)
        if reason is not None:
            return reason
        if self._probe(audit_data, PROBE_AUTH_METADATA).outcome is not ProbeOutcome.SUPPORTED:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def _metadata(self, audit_data: AuditData) -> dict:
        return self._probe(audit_data, PROBE_AUTH_METADATA).details


@register_rule
class AuthChallengeReferencesMetadataRule(AuthPostureBaseRule):
    """Medium check: a challenge's ``resource_metadata`` URL serves the resource metadata."""

    rule_id = "auth_challenge_references_metadata"
    rule_order = 7

    @property
    def rule_name(self) -> str:
        return "Auth - Challenge References Resource Metadata"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when the challenge carries no reference the spec requires, or nothing was observed.

        A missing challenge header is AuthWwwAuthenticateRule's finding. A
        challenge without ``resource_metadata`` is compliant on a 403, and from
        2025-11-25 on a 401 too: the server may use well-known discovery, which
        AuthProtectedResourceMetadataRule judges. A reference whose fetch never
        completed is unverified.
        """
        reason = super().skip_reason(audit_data)
        if reason is not None:
            return reason
        unauthenticated = self._probe(audit_data, PROBE_UNAUTHENTICATED).details
        challenge = unauthenticated.get("www_authenticate")
        if not (isinstance(challenge, str) and challenge.strip()):
            return SKIP_REASON_INSUFFICIENT_DATA
        if www_authenticate_param(challenge, "resource_metadata") is None:
            if unauthenticated.get("http_status") == 401 and _challenge_param_required(audit_data):
                return None
            return SKIP_REASON_NOT_APPLICABLE
        metadata = (audit_data.probes or {}).get(PROBE_AUTH_METADATA)
        if metadata is None or "challenge_metadata_url" not in metadata.details:
            return SKIP_REASON_INSUFFICIENT_DATA
        observed = metadata.details
        if "challenge_metadata_error" in observed and "challenge_metadata_http_status" not in observed:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: the challenge's ``resource_metadata`` URL serves RFC 9728 metadata.

        The URL may be on any host (RFC 9728 §5.1); what makes it usable is that
        it returns a metadata document. Whether that document's ``resource``
        identifies this server is AuthProtectedResourceMetadataRule's check. On
        2025-06-18, a 401 challenge without the parameter fails.

        Args:
            audit_data: The collected server data for this audit

        Returns:
            RuleResult with the check outcome

        """
        status = self._probe(audit_data, PROBE_UNAUTHENTICATED).details.get("http_status")
        challenge = str(self._probe(audit_data, PROBE_UNAUTHENTICATED).details.get("www_authenticate"))
        referenced = www_authenticate_param(challenge, "resource_metadata")
        observed = self._probe(audit_data, PROBE_AUTH_METADATA).details if referenced is not None else {}
        fetched_status = observed.get("challenge_metadata_http_status")
        suggested_fix: str | None = None
        if referenced is None:
            passed = False
            message = f"❌ The HTTP {status} challenge has no resource_metadata parameter, which 2025-06-18 requires"
            suggested_fix = (
                "Add a quoted resource_metadata URL pointing to your protected-resource metadata in the "
                "401 WWW-Authenticate challenge, or negotiate 2025-11-25 or later and serve the metadata "
                "at the RFC 9728 well-known location."
            )
        elif observed.get("challenge_metadata_invalid"):
            passed = False
            message = f"❌ Challenge resource_metadata {evidence_preview(referenced)} is not an absolute http(s) URL"
            suggested_fix = "Set resource_metadata to the absolute HTTPS URL of your protected-resource metadata."
        elif observed.get("challenge_metadata_blocked"):
            passed = False
            message = (
                f"❌ Challenge resource_metadata {evidence_preview(referenced)} points at a non-public "
                "address that remote clients cannot reach"
            )
            suggested_fix = (
                "Point resource_metadata at the public URL of your protected-resource metadata. Check "
                "proxy or public-URL configuration."
            )
        elif observed.get("challenge_metadata_resource") is None:
            passed = False
            message = (
                f"❌ Challenge resource_metadata {evidence_preview(referenced)} did not serve RFC 9728 "
                f"metadata (HTTP {fetched_status})"
            )
            suggested_fix = (
                "Serve an anonymous HTTP 200 JSON document with a resource field at the resource_metadata "
                "URL, or correct the URL in the challenge."
            )
        else:
            passed = True
            message = f"✅ HTTP {status} challenge references metadata served at {evidence_preview(referenced)}"
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "basis": (
                    "RFC 9728 §5.1 (resource_metadata parameter); MCP Authorization 2025-06-18 "
                    "(Authorization Server Location), 2025-11-25+ (Protected Resource Metadata Discovery)"
                ),
                "resource_metadata": referenced,
                "http_status": fetched_status,
            },
            suggested_fix=suggested_fix if not passed else None,
            audit_data=audit_data,
        )


@register_rule
class AuthMetadataHttpsRule(AuthMetadataBaseRule):
    """Medium check: the protected-resource metadata is served and named over HTTPS."""

    rule_id = "auth_metadata_https"
    rule_order = 8

    @property
    def rule_name(self) -> str:
        return "Auth - Resource Metadata Uses HTTPS"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: the metadata URL and its `resource` value are HTTPS.

        RFC 9728 requires the metadata endpoint to use HTTPS; a plain-HTTP
        metadata document or resource identifier is spoofable in transit.

        Args:
            audit_data: The collected server data for this audit

        Returns:
            RuleResult with the check outcome

        """
        details = self._metadata(audit_data)
        metadata_url = str(details.get("metadata_url", ""))
        resource = str(details.get("resource", ""))
        insecure = [u for u in (metadata_url, resource) if not u.lower().startswith("https://")]
        passed = not insecure
        message = (
            "✅ The protected-resource metadata URL and resource identifier use HTTPS"
            if passed
            else f"❌ Number of protected-resource metadata URLs not using HTTPS: {len(insecure)}"
        )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "basis": "RFC 9728 §2 (resource), §3 (HTTPS well-known)",
                "metadata_url": metadata_url,
                "resource": resource,
            },
            suggested_fix=(
                "Serve the metadata over HTTPS and set resource to the HTTPS MCP resource identifier. "
                "Check both fields; do not disable TLS verification to make discovery work."
            )
            if not passed
            else None,
            audit_data=audit_data,
        )


@register_rule
class AuthScopesAdvertisedRule(AuthMetadataBaseRule):
    """Low check: the metadata advertises scopes so clients can request least privilege."""

    rule_id = "auth_scopes_advertised"
    rule_order = 9

    @property
    def rule_name(self) -> str:
        return "Auth - Scopes Advertised"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def check(self, audit_data: AuditData) -> RuleResult:
        """Low check: `scopes_supported` is present and non-empty (RFC 9728).

        Advertised scopes let clients request only the access they need; their
        absence pushes clients toward over-broad authorization.

        Args:
            audit_data: The collected server data for this audit

        Returns:
            RuleResult with the check outcome

        """
        scopes = self._metadata(audit_data).get("scopes_supported")
        count = len(scopes) if isinstance(scopes, list) else 0
        passed = count > 0
        message = (
            f"✅ The protected-resource metadata advertises {count} scope(s)"
            if passed
            else "❌ scopes_supported is absent, empty or not an array. Advertising scopes is a quality recommendation"
        )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"basis": "RFC 9728 §2 (scopes_supported)", "scopes_supported": scopes},
            suggested_fix=(
                "Advertise a non-empty scopes_supported array of actual least-privilege scopes. This "
                "is a recommendation; RFC 9728 permits omitting some supported scopes."
            )
            if not passed
            else None,
            audit_data=audit_data,
        )


@register_rule
class AuthServerMetadataPresentRule(AuthMetadataBaseRule):
    """High check: the authorization server publishes RFC 8414 metadata with endpoints."""

    rule_id = "auth_server_metadata_present"
    rule_order = 10

    @property
    def rule_name(self) -> str:
        return "Auth - Authorization Server Metadata Present"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when the metadata lists no HTTPS authorization server to discover."""
        reason = super().skip_reason(audit_data)
        if reason is not None:
            return reason
        if self._metadata(audit_data).get("auth_server_issuer") is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def check(self, audit_data: AuditData) -> RuleResult:
        """High check: the authorization server's metadata is discoverable and valid.

        The probe tries the MCP discovery order (RFC 8414 and OpenID Connect,
        with path insertion for an issuer with a path) and accepts a document
        only when its ``issuer`` is identical to the listed issuer (RFC 8414
        §3.3), apart from a trailing slash, which is reported. It must advertise the authorization and token endpoints;
        without it the flow is undiscoverable.

        Args:
            audit_data: The collected server data for this audit

        Returns:
            RuleResult with the check outcome

        """
        details = self._metadata(audit_data)
        issuer = details.get("auth_server_issuer")
        present = details.get("auth_server_metadata_present") is True
        has_endpoints = details.get("auth_server_has_endpoints") is True
        passed = present and has_endpoints
        mismatch = details.get("auth_server_issuer_mismatch")
        declared = details.get("auth_server_issuer_declared")
        if details.get("auth_server_metadata_blocked"):
            message = f"❌ Issuer {evidence_preview(issuer)} is a non-public address that remote clients cannot reach"
        elif not present and isinstance(mismatch, dict):
            message = (
                f"❌ Metadata at {evidence_preview(mismatch.get('metadata_url'))} declares issuer "
                f"{evidence_preview(mismatch.get('issuer'))}, not {evidence_preview(issuer)}; clients must reject it"
            )
        elif not present:
            message = f"❌ No usable discovery metadata was observed for issuer {evidence_preview(issuer)}"
        elif not has_endpoints:
            message = (
                f"❌ Issuer {evidence_preview(issuer)} metadata lacks string "
                "authorization_endpoint or token_endpoint fields"
            )
        elif isinstance(declared, str):
            message = (
                f"✅ Issuer {evidence_preview(issuer)} metadata includes string authorization and token endpoints "
                f"(it declares issuer {evidence_preview(declared)}, which differs only by a trailing slash)"
            )
        else:
            message = f"✅ Issuer {evidence_preview(issuer)} metadata includes string authorization and token endpoints"
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "basis": (
                    "RFC 8414 §3.1 (well-known location), §3.3 (issuer validation), §2 (endpoints); "
                    "MCP Authorization (Authorization Server Metadata Discovery)"
                ),
                "issuer": issuer,
                "present": present,
                "has_endpoints": has_endpoints,
                "issuer_mismatch": mismatch,
                "declared_issuer": declared,
            },
            suggested_fix=(
                ("Advertise the issuer's public HTTPS identifier in authorization_servers.")
                if details.get("auth_server_metadata_blocked")
                else (
                    "Make the metadata's issuer identical to the identifier in authorization_servers, "
                    "including any trailing slash, or list the issuer exactly as the metadata declares it."
                )
                if not present and isinstance(mismatch, dict)
                else ("Check DNS, TLS and network access to the selected issuer; no discovery location was reachable.")
                if details.get("auth_server_metadata_error") is not None
                else ("Check the issuer discovery URLs and serve RFC 8414 or OpenID Connect JSON metadata.")
                if not present
                else (
                    "Include string authorization_endpoint and token_endpoint URLs for the actual OAuth "
                    "endpoints in the issuer metadata."
                )
            )
            if not passed
            else None,
            audit_data=audit_data,
        )


@register_rule
class AuthServerPkceRule(AuthMetadataBaseRule):
    """High check: the authorization server advertises PKCE with S256."""

    rule_id = "auth_server_metadata_pkce"
    rule_order = 11

    @property
    def rule_name(self) -> str:
        return "Auth - Authorization Server Advertises PKCE (S256)"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when there is no reachable AS metadata to inspect (that rule's finding)."""
        reason = super().skip_reason(audit_data)
        if reason is not None:
            return reason
        if self._metadata(audit_data).get("auth_server_metadata_present") is not True:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def check(self, audit_data: AuditData) -> RuleResult:
        """High check: `code_challenge_methods_supported` includes S256.

        PKCE with S256 is required by the OAuth security BCP (RFC 9700) and the
        MCP authorization spec; without it the authorization-code flow is open
        to code-interception attacks.

        Args:
            audit_data: The collected server data for this audit

        Returns:
            RuleResult with the check outcome

        """
        details = self._metadata(audit_data)
        passed = details.get("auth_server_pkce_s256") is True
        message = (
            "✅ The authorization server advertises PKCE with S256"
            if passed
            else "❌ The authorization server does not advertise PKCE with S256 (code_challenge_methods_supported)"
        )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "basis": "RFC 9700 §2.1.1 (PKCE); RFC 8414 §2 (code_challenge_methods_supported)",
                "issuer": details.get("auth_server_issuer"),
            },
            suggested_fix=(
                "If S256 is supported, include it in code_challenge_methods_supported. Otherwise "
                "implement S256 before advertising it. This check does not verify runtime enforcement."
            )
            if not passed
            else None,
            audit_data=audit_data,
        )


CIMD_SINCE = "2025-11-25"
"""First revision with Client ID Metadata Documents (SHOULD) and Dynamic Client Registration demoted to MAY."""


@register_rule
class AuthClientRegistrationAdvertisedRule(AuthMetadataBaseRule):
    """Medium check: the authorization server tells a new client how to register."""

    rule_id = "auth_client_registration_advertised"
    rule_order = 12

    @property
    def rule_name(self) -> str:
        return "Auth - Client Registration Advertised"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when there is no reachable AS metadata to inspect (that rule's finding)."""
        reason = super().skip_reason(audit_data)
        if reason is not None:
            return reason
        if self._metadata(audit_data).get("auth_server_metadata_present") is not True:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: the metadata advertises Client ID Metadata Documents or Dynamic Client Registration.

        A client that has never seen this server registers through one of them. With neither,
        only pre-registered clients connect, and every other client must ask the user for
        client credentials. Since 2025-11-25 Client ID Metadata Documents are the SHOULD and
        Dynamic Client Registration is kept for backwards compatibility; before, Dynamic
        Client Registration was the SHOULD. Whether the server then accepts a given client is
        its trust policy and is not judged.

        Args:
            audit_data: The collected server data for this audit

        Returns:
            RuleResult with the check outcome

        """
        details = self._metadata(audit_data)
        cimd = details.get("auth_server_cimd_supported") is True
        dcr = details.get("auth_server_registration_endpoint") is True
        version = audit_data.protocol_version
        cimd_era = version is None or compare(version, CIMD_SINCE) >= 0
        passed = cimd or dcr
        if cimd:
            message = "✅ The authorization server supports Client ID Metadata Documents"
        elif dcr and cimd_era:
            message = (
                "✅ The authorization server offers Dynamic Client Registration (registration_endpoint). "
                "Advertising client_id_metadata_document_supported is the recommended path for new clients"
            )
        elif dcr:
            message = "✅ The authorization server offers Dynamic Client Registration (registration_endpoint)"
        else:
            message = (
                "❌ The authorization server advertises neither client_id_metadata_document_supported nor a "
                "registration_endpoint, so only pre-registered clients can sign in without asking the user "
                "for client credentials"
            )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "basis": (
                    "MCP Authorization 2025-11-25 §Client Registration Approaches, §Client ID Metadata Documents "
                    "(SHOULD), §Dynamic Client Registration (MAY); 2025-06-18 §Dynamic Client Registration (SHOULD)"
                ),
                "issuer": details.get("auth_server_issuer"),
                "client_id_metadata_document_supported": cimd,
                "registration_endpoint": dcr,
            },
            suggested_fix=(
                "Fetch HTTPS client_id metadata documents and set client_id_metadata_document_supported: true in "
                "the authorization server metadata, or expose an RFC 7591 registration_endpoint. An allowlist of "
                "trusted client domains still works with either."
            )
            if not passed
            else None,
            audit_data=audit_data,
        )


@register_rule
class AuthInvalidTokenRejectedRule(AuthPostureBaseRule):
    """High check: a fabricated bearer token is refused like a missing one."""

    rule_id = "auth_invalid_token_rejected"
    rule_order = 13
    required_probe_ids = (PROBE_UNAUTHENTICATED, PROBE_INVALID_TOKEN)

    @property
    def rule_name(self) -> str:
        return "Auth - Invalid Token Rejected"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip as not-applicable for a server that serves anonymous requests, before looking at the token probe."""
        probes = audit_data.probes or {}
        unauthenticated = probes.get(PROBE_UNAUTHENTICATED)
        if (
            unauthenticated is not None
            and unauthenticated.outcome is ProbeOutcome.SUPPORTED
            and unauthenticated.details.get("http_status") not in AUTH_GATED_STATUSES
        ):
            return SKIP_REASON_NOT_APPLICABLE
        return super().skip_reason(audit_data)

    def check(self, audit_data: AuditData) -> RuleResult:
        """High check: a request with a made-up bearer token is refused, not served.

        A 2xx answer means the token got past the server's auth check. Invalid tokens
        MUST receive HTTP 401; another refusal (403, or a 4xx with an ``invalid_token``
        challenge) still keeps the server closed and passes, and the message names the
        401 the spec asks for.

        Args:
            audit_data: The collected server data for this audit

        Returns:
            RuleResult with the check outcome

        """
        probe = self._probe(audit_data, PROBE_INVALID_TOKEN)
        status = probe.details.get("http_status")
        anonymous_status = self._probe(audit_data, PROBE_UNAUTHENTICATED).details.get("http_status")
        passed = probe.outcome is ProbeOutcome.SUPPORTED
        if passed and status == 401:
            message = "✅ A fabricated bearer token was refused with HTTP 401"
        elif passed:
            message = (
                f"✅ A fabricated bearer token was refused with HTTP {status}. "
                "The spec asks for HTTP 401 on an invalid token"
            )
        else:
            message = (
                f"❌ A fabricated bearer token was accepted: {probe.details.get('method')} answered HTTP {status}, "
                f"where a request without a token gets HTTP {anonymous_status}"
            )
        return diagnostic_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "basis": (
                    "MCP Authorization (2025-06-18+) §Token Handling: invalid or expired tokens MUST "
                    "receive HTTP 401; OAuth 2.1 §5.2 (token validation)"
                ),
                "method": probe.details.get("method"),
                "http_status": status,
                "anonymous_http_status": anonymous_status,
            },
            suggested_fix=(
                "Validate every bearer token (signature or introspection, expiry, audience) before handling the "
                "request, and answer an invalid one with HTTP 401. A failed check must never fall back to a "
                "default identity."
            )
            if not passed
            else None,
            audit_data=audit_data,
        )
