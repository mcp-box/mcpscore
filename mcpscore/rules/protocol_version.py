from abc import abstractmethod
from typing import ClassVar

from mcpscore.probes import GATEWAY_PROBE_IDS, ProbeOutcome, ProbeResult, has_modern_support
from mcpscore.spec import LATEST, allowed_versions, compare, deprecated_versions

from .base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
    requires_protocol_version,
)
from .registry import register_rule


def _probes_observed(probes: dict[str, ProbeResult] | None) -> bool:
    """Whether a modern-lifecycle gateway probe reached the server.

    NOT_APPLICABLE and ERROR are both non-observations: the first means the
    question does not exist on this transport, the second that it could not be
    asked. Neither is evidence that a server lacks modern support. Unrelated
    observations (an auth well-known document, for example) do not make the
    gateway observable and must not turn an unknown lifecycle into a failure.
    """
    observations = probes or {}
    return any(
        probe_id in observations
        and observations[probe_id].outcome not in (ProbeOutcome.NOT_APPLICABLE, ProbeOutcome.ERROR)
        for probe_id in GATEWAY_PROBE_IDS
    )


class ProtocolVersionBaseRule(BaseRule):
    """Base class for all protocol version related audit rules.

    This abstract base class provides common functionality for rules that
    validate MCP protocol version compliance. It handles the case where
    no protocol version is available and delegates the actual validation
    to subclasses via the _check_protocol_version method.
    """

    group_name = "protocol_version"
    group_order = 1

    @requires_protocol_version
    def check(self, protocol_version: str) -> RuleResult:
        """Execute the protocol version rule check.

        Args:
            protocol_version: The protocol version string to validate

        Returns:
            RuleResult indicating whether the protocol version check passed

        """
        if not protocol_version:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message="❌ Protocol version is not available",
                details={"protocol_version": None},
            )

        return self._check_protocol_version(protocol_version)

    @abstractmethod
    def _check_protocol_version(self, protocol_version: str) -> RuleResult:
        """Perform the actual protocol version validation.

        Args:
            protocol_version: The protocol version string to validate

        Returns:
            RuleResult with the validation outcome

        Note:
            This method must be implemented by subclasses to define
            the specific validation logic for each rule type.

        """
        ...


@register_rule
class AllowedVersionRule(ProtocolVersionBaseRule):
    """Critical check: Verify the MCP protocol version is one of the allowed versions."""

    rule_id = "protocol_version_allowed"
    basis = "MCP 2025-11-25 Lifecycle §Version Negotiation (server MUST respond with a version it supports)"
    rule_order = 1

    @property
    def rule_name(self) -> str:
        return "MCP Protocol Version - Allowed Versions"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    def _check_protocol_version(self, protocol_version: str) -> RuleResult:
        """Critical check: Verify the MCP protocol version is one of the allowed versions.

        Args:
            protocol_version: The protocol version string to check
        Returns:
            RuleResult with the check outcome

        """
        # Check if the version is in the spec registry's allowed list
        allowed = allowed_versions()
        passed = protocol_version in allowed

        message = (
            f"✅ Protocol version '{protocol_version}' is one of the allowed versions"
            if passed
            else f"❌ Protocol version '{protocol_version}' is not in the allowed versions list"
        )

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"version": protocol_version, "allowed_versions": allowed},
        )


@register_rule
class LatestVersionRule(BaseRule):
    """Medium check: Verify the server speaks the latest available protocol version.

    "Speaks", not "negotiated". From 2026-07-28 the newest revisions are
    reachable only through the stateless per-request lifecycle, which has no
    ``initialize`` handshake — so a server can fully support the latest spec
    while its handshake correctly settles on an older one. Judging the
    handshake result alone would make this rule unpassable for every such
    server, and would report a current server as behind.

    The probes are the evidence that closes the gap (see mcpscore.probes):
    a server answering ``server/discover`` or a stateless request supports the
    modern lifecycle whatever its handshake said.
    """

    group_name = "protocol_version"
    group_order = 1
    rule_id = "protocol_version_latest"
    basis = (
        "MCP 2026-07-28 Basic §Lifecycle and MCP 2025-11-25 Lifecycle §Version Negotiation "
        "(use the latest supported revision)"
    )
    rule_order = 3

    @property
    def rule_name(self) -> str:
        return "MCP Protocol Version - Latest Version"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when neither the handshake nor the probes observed anything.

        A negotiated version below the latest is only a finding when the
        probes actually looked for modern support and did not find it. With no
        probe observations at all the rule cannot tell "behind" from
        "supports the latest by a route the handshake cannot express", and
        must not guess — guessing in that gap is what made this rule
        unpassable over stdio before probes ran there.
        """
        if audit_data.protocol_version is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        if compare(audit_data.protocol_version, LATEST.version) >= 0:
            return None
        if not _probes_observed(audit_data.probes):
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def check(self, audit_data: AuditData) -> RuleResult:
        """Judge the newest revision the server was observed to speak."""
        protocol_version = audit_data.protocol_version
        if not protocol_version:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message="❌ Protocol version is not available",
                details={"protocol_version": None},
            )

        modern = has_modern_support(audit_data.probes)
        # At least the most recent final version (a newer draft is not "behind")
        negotiated_is_latest = compare(protocol_version, LATEST.version) >= 0
        passed: bool = negotiated_is_latest or modern

        if protocol_version == LATEST.version:
            message = f"✅ Protocol version '{protocol_version}' is the latest version"
        elif negotiated_is_latest:
            message = (
                f"✅ Protocol version '{protocol_version}' is newer than the latest final version '{LATEST.version}'"
            )
        elif modern:
            message = (
                f"✅ Server supports the latest protocol version '{LATEST.version}' via the stateless "
                f"lifecycle (the handshake negotiated '{protocol_version}', the newest revision it can carry)"
            )
        else:
            message = (
                f"❌ Not using the latest protocol version: negotiated '{protocol_version}', "
                f"latest is '{LATEST.version}', and no stateless-lifecycle support was observed"
            )

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "version": protocol_version,
                "latest_version": LATEST.version,
                "modern_lifecycle_support": modern,
            },
        )


@register_rule
class DeprecatedVersionRule(ProtocolVersionBaseRule):
    """High check: Verify the MCP protocol version is not deprecated."""

    rule_id = "protocol_version_not_deprecated"
    basis = "MCP Versioning §Revisions (draft/current/final status)"
    rule_order = 2

    deprecated_versions: ClassVar[list[str]] = deprecated_versions()
    """Protocol versions deprecated by the MCP specification (from the spec registry)."""

    @property
    def rule_name(self) -> str:
        return "MCP Protocol Version - Deprecated Version"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_protocol_version(self, protocol_version: str) -> RuleResult:
        """High check: Verify the MCP protocol version is not deprecated.

        Args:
            protocol_version: The protocol version string to check

        Returns:
            RuleResult with the check outcome

        """
        passed: bool = protocol_version not in self.deprecated_versions
        if passed:
            message: str = f"✅ Protocol version '{protocol_version}' is not deprecated"
        else:
            message: str = f"❌ Protocol version '{protocol_version}' is deprecated"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"version": protocol_version, "deprecated_versions": list(self.deprecated_versions)},
        )
