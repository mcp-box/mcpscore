"""Authorization-posture rules (RFC 9728 protected resource metadata).

These rules score how an auth-gated server presents its authorization
surface — the one part of an authenticated server mcpscore can audit without
credentials. They gate on the unauthenticated probe observing HTTP 401 or
403: a server that serves anonymous requests has no auth posture to grade,
and the rules skip as not-applicable rather than handing out free points.

Normative basis (cited per rule, re-verify at spec-final): the MCP
Authorization spec (2025-06-18 and later) makes MCP servers OAuth 2.0
protected resources — a 401 MUST carry ``WWW-Authenticate`` pointing at the
resource metadata, the RFC 9728 metadata document MUST exist with its
``resource`` value matching the server, and it MUST list at least one
authorization server. The deeper rules follow the discovery chain to the
authorization server's own RFC 8414 metadata and check it advertises PKCE
(S256), per the OAuth security BCP (RFC 9700).
"""

from typing import ClassVar
from urllib.parse import urlsplit

from ..probes import AUTH_GATED_STATUSES, PROBE_AUTH_METADATA, PROBE_UNAUTHENTICATED, ProbeOutcome, ProbeResult
from .base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_NOT_APPLICABLE,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
)
from .registry import register_rule


def _normalized(url: str) -> str:
    """Normalize a resource URL for comparison (trailing slash only)."""
    return url.rstrip("/")


def _origin(url: str) -> str:
    """Return the scheme://host[:port] origin of a URL, for same-origin comparison."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


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

        The Authorization spec requires servers to use ``WWW-Authenticate`` on
        401 responses to point clients at the resource metadata; without it a
        client cannot discover how to authenticate. The rule also runs for
        403-gated servers, so messages report the observed status.

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
            f"✅ HTTP {status} responses carry a WWW-Authenticate challenge: '{challenge}'"
            if passed
            else f"❌ HTTP {status} responses lack the WWW-Authenticate header needed to discover how to authenticate"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"basis": "MCP Authorization (2025-06-18+); RFC 9728 §5.1", "www_authenticate": challenge},
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
        """High check: the well-known metadata document exists and matches.

        RFC 9728 requires the metadata's ``resource`` value to identify the
        protected resource; a mismatched value sends clients to authenticate
        for a different resource than the one they connected to.

        Args:
            audit_data: The collected server data for this audit

        Returns:
            RuleResult with the check outcome

        """
        probe = self._probe(audit_data, PROBE_AUTH_METADATA)
        details = {"basis": "RFC 9728 §3 (well-known location), §2 (resource)", **probe.details}
        if probe.outcome is not ProbeOutcome.SUPPORTED:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message="❌ No RFC 9728 protected resource metadata found at the well-known locations",
                details=details,
            )

        resource = str(probe.details.get("resource"))
        matches = audit_data.url is not None and _normalized(resource) == _normalized(audit_data.url)
        details["resource_matches"] = matches
        message = (
            f"✅ Protected resource metadata found at '{probe.details.get('metadata_url')}'"
            if matches
            else f"❌ Protected resource metadata 'resource' is '{resource}', which does not match this server"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=matches,
            message=message,
            details=details,
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
        invalid = [server for server in servers if not (isinstance(server, str) and server.startswith("https://"))]
        if not servers:
            passed = False
            message = "❌ Protected resource metadata lists no authorization servers to authenticate against"
        elif invalid:
            passed = False
            message = f"❌ Number of authorization servers not on HTTPS or malformed: {len(invalid)}"
        else:
            passed = True
            message = f"✅ All {len(servers)} authorization server(s) use HTTPS"
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "basis": "RFC 9728 §2 (authorization_servers)",
                "authorization_servers": servers,
                "invalid": invalid,
            },
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


def _parse_www_authenticate_param(header: str, param: str) -> str | None:
    """Extract a quoted parameter (e.g. resource_metadata="…") from a challenge."""
    marker = f'{param}="'
    start = header.find(marker)
    if start == -1:
        return None
    start += len(marker)
    end = header.find('"', start)
    return header[start:end] if end != -1 else None


@register_rule
class AuthChallengeReferencesMetadataRule(AuthPostureBaseRule):
    """Medium check: the auth challenge points clients at the resource metadata."""

    rule_id = "auth_challenge_references_metadata"
    rule_order = 7

    @property
    def rule_name(self) -> str:
        return "Auth - Challenge References Resource Metadata"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when the challenge header is absent (AuthWwwAuthenticateRule's finding)."""
        reason = super().skip_reason(audit_data)
        if reason is not None:
            return reason
        challenge = self._probe(audit_data, PROBE_UNAUTHENTICATED).details.get("www_authenticate")
        if not (isinstance(challenge, str) and challenge.strip()):
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: WWW-Authenticate carries resource_metadata (RFC 9728 §5.1).

        Without the ``resource_metadata`` parameter a client cannot discover
        the protected-resource metadata from the challenge alone.

        Args:
            audit_data: The collected server data for this audit

        Returns:
            RuleResult with the check outcome

        """
        probe = self._probe(audit_data, PROBE_UNAUTHENTICATED)
        status = probe.details.get("http_status")
        challenge = str(probe.details.get("www_authenticate"))
        referenced = _parse_www_authenticate_param(challenge, "resource_metadata")
        # RFC 9728 serves the metadata from the resource's own origin; the exact
        # path (root vs path-aware form) is a legitimate server choice, so we
        # compare origins, not full URLs — a *different origin* is the real red
        # flag (it points clients at someone else's metadata).
        if referenced is None:
            passed = False
            message = f"❌ The HTTP {status} challenge has no resource_metadata parameter for discovering the metadata"
        elif audit_data.url is not None and _origin(referenced) != _origin(audit_data.url):
            passed = False
            message = f"❌ The challenge's resource_metadata '{referenced}' is not on this server's origin"
        else:
            passed = True
            message = f"✅ The HTTP {status} challenge references the resource metadata: '{referenced}'"
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"basis": "RFC 9728 §5.1 (resource_metadata parameter)", "resource_metadata": referenced},
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
        insecure = [u for u in (metadata_url, resource) if not u.startswith("https://")]
        passed = not insecure
        message = (
            "✅ The protected-resource metadata URL and resource identifier use HTTPS"
            if passed
            else f"❌ Number of protected-resource metadata URLs not using HTTPS: {len(insecure)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "basis": "RFC 9728 §2 (resource), §3 (HTTPS well-known)",
                "metadata_url": metadata_url,
                "resource": resource,
            },
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
            else "❌ The protected-resource metadata advertises no scopes_supported for least-privilege requests"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"basis": "RFC 9728 §2 (scopes_supported)", "scopes_supported": scopes},
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
        """High check: the authorization server's RFC 8414 metadata is reachable.

        It must advertise the authorization and token endpoints; clients
        discover how to authorize and exchange tokens from this
        document; without it the flow is undiscoverable.

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
        if not present:
            message = f"❌ Authorization server '{issuer}' publishes no RFC 8414 metadata document"
        elif not has_endpoints:
            message = f"❌ Authorization server '{issuer}' metadata omits the authorization or token endpoint"
        else:
            message = f"✅ Authorization server '{issuer}' publishes RFC 8414 metadata with the required endpoints"
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "basis": "RFC 8414 §3 (well-known location), §2 (endpoints)",
                "issuer": issuer,
                "present": present,
                "has_endpoints": has_endpoints,
            },
        )


@register_rule
class AuthServerPkceRule(AuthMetadataBaseRule):
    """High check: the authorization server advertises PKCE with S256."""

    rule_id = "auth_server_metadata_pkce"
    rule_order = 11

    @property
    def rule_name(self) -> str:
        return "Auth - Authorization Server Enforces PKCE (S256)"

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
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "basis": "RFC 9700 §2.1.1 (PKCE); RFC 8414 §2 (code_challenge_methods_supported)",
                "issuer": details.get("auth_server_issuer"),
            },
        )
