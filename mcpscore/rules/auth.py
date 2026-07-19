"""Authorization-posture rules (RFC 9728 protected resource metadata).

These rules score how an auth-gated server presents its authorization
surface — the one part of an authenticated server mcpscore can audit without
credentials. They gate on the unauthenticated probe observing HTTP 401: a
server that serves anonymous requests has no auth posture to grade, and the
rules skip as not-applicable rather than handing out free points.

Normative basis (cited per rule, re-verify at spec-final): the MCP
Authorization spec (2025-06-18 and later) makes MCP servers OAuth 2.0
protected resources — a 401 MUST carry ``WWW-Authenticate`` pointing at the
resource metadata, the RFC 9728 metadata document MUST exist with its
``resource`` value matching the server, and it MUST list at least one
authorization server.
"""

from typing import ClassVar

from ..probes import PROBE_AUTH_METADATA, PROBE_UNAUTHENTICATED, ProbeOutcome, ProbeResult
from .base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_NOT_APPLICABLE,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
)
from .registry import register_rule

_AUTH_BASIS = "MCP Authorization (2025-06-18+) / RFC 9728"


def _normalized(url: str) -> str:
    """Normalize a resource URL for comparison (trailing slash only)."""
    return url.rstrip("/")


class AuthPostureBaseRule(BaseRule):
    """Base class for auth-posture rules: security group, auth-gated servers only."""

    group_name = "security"
    group_order = 3
    min_spec_version = "2025-06-18"

    required_probe_ids: ClassVar[tuple[str, ...]] = (PROBE_UNAUTHENTICATED,)
    """Probes whose observations this rule needs; unavailable → skip."""

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip unless an unauthenticated request was actually challenged with 401."""
        probes = audit_data.probes or {}
        for probe_id in self.required_probe_ids:
            result = probes.get(probe_id)
            if result is None or result.outcome in (ProbeOutcome.ERROR, ProbeOutcome.NOT_APPLICABLE):
                return SKIP_REASON_INSUFFICIENT_DATA
        if probes[PROBE_UNAUTHENTICATED].details.get("http_status") != 401:
            return SKIP_REASON_NOT_APPLICABLE
        return None

    def _probe(self, audit_data: AuditData, probe_id: str) -> ProbeResult:
        """Return a required probe's result (skip_reason guarantees presence)."""
        assert audit_data.probes is not None  # noqa: S101 — guaranteed by skip_reason
        return audit_data.probes[probe_id]


@register_rule
class AuthWwwAuthenticateRule(AuthPostureBaseRule):
    """High check: a 401 response carries a ``WWW-Authenticate`` challenge."""

    rule_id = "auth_www_authenticate"
    rule_order = 4

    @property
    def rule_name(self) -> str:
        return "Auth - 401 Carries WWW-Authenticate"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def check(self, audit_data: AuditData) -> RuleResult:
        """High check: the 401 challenge includes a WWW-Authenticate header.

        The Authorization spec requires servers to use ``WWW-Authenticate`` on
        401 responses to point clients at the resource metadata; without it a
        client cannot discover how to authenticate.

        Args:
            audit_data: The collected server data for this audit

        Returns:
            RuleResult with the check outcome

        """
        challenge = self._probe(audit_data, PROBE_UNAUTHENTICATED).details.get("www_authenticate")
        passed = isinstance(challenge, str) and bool(challenge.strip())
        message = (
            f"✅ 401 responses carry a WWW-Authenticate challenge: '{challenge}'"
            if passed
            else "❌ 401 responses lack the WWW-Authenticate header clients need to discover how to authenticate"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"basis": _AUTH_BASIS, "www_authenticate": challenge},
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
        details = {"basis": _AUTH_BASIS, **probe.details}
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
        insecure = [server for server in servers if isinstance(server, str) and not server.startswith("https://")]
        if not servers:
            passed = False
            message = "❌ Protected resource metadata lists no authorization servers to authenticate against"
        elif insecure:
            passed = False
            message = f"❌ Number of authorization servers not using HTTPS: {len(insecure)}"
        else:
            passed = True
            message = f"✅ All {len(servers)} authorization server(s) use HTTPS"
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"basis": _AUTH_BASIS, "authorization_servers": servers, "insecure": insecure},
        )
