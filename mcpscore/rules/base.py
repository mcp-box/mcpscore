from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum
from functools import wraps
from typing import TYPE_CHECKING, Any

from mcpscore.spec import compare

if TYPE_CHECKING:
    from collections.abc import Callable

    from mcp_types import Implementation, Prompt, Resource, ResourceTemplate, ServerCapabilities, Tool

    from mcpscore.packages import PackageMetadata

    from ..enums import MCPTransportType
    from ..probes import ProbeResult

SKIP_REASON_NOT_APPLICABLE = "not-applicable"
"""Skip reason for rules whose spec-version range excludes the negotiated version."""

SKIP_REASON_REQUIRES_MODERN_SUPPORT = "requires-modern-support"
"""Skip reason for detail readiness rules when the server shows no modern-lifecycle
support at all — the gateway rules already carry that verdict; piling on adds noise."""

SKIP_REASON_INSUFFICIENT_DATA = "insufficient-data"
"""Skip reason when the observations a rule needs are unavailable (probe errored,
probes not applicable to the transport, or session data missing) — the rule can
neither pass nor fail, so it must not count against the score."""

READINESS_GROUP = "readiness"
"""Group name of readiness rules. The auditor scores this group on a separate
readiness axis, never in the main score (see the multi-spec-version design)."""


class RuleSeverity(IntEnum):
    """Severity levels for audit rules."""

    CRITICAL = 5
    HIGH = 3
    MEDIUM = 2
    LOW = 1


@dataclass
class RuleResult:
    """Result of a rule check."""

    rule_name: str
    severity: RuleSeverity
    passed: bool
    message: str
    details: dict | None = None
    rule_id: str = ""
    """Stable identifier of the rule that produced this result.

    Stamped by the auditor from the rule's rule_id; unlike rule_name and
    message, it is a stable contract for machine consumers (JSON reports,
    snapshot-based acceptance tests)."""

    def to_dict(self) -> dict:
        """Serialize this result for machine-readable reports.

        Returns:
            Dictionary with the rule identity, severity (name and numeric
            score weight), pass/fail status, message, and details.

        """
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.name,
            "severity_value": int(self.severity),
            "passed": self.passed,
            "message": self.message,
            "details": self.details,
        }


@dataclass(frozen=True)
class SkippedRule:
    """Record of a rule that was considered but not executed.

    Skipped rules contribute to neither the score nor the maximum score;
    they appear in the report so machine consumers (and snapshot tests) can
    see the rule was considered rather than silently dropped.
    """

    rule_id: str
    rule_name: str
    reason: str
    """Why the rule was skipped, e.g. SKIP_REASON_NOT_APPLICABLE."""

    group_name: str = "default"
    """Group of the skipped rule — lets report consumers (and the summary)
    attribute the skip to the right scoring axis (main vs readiness)."""

    def to_dict(self) -> dict:
        """Serialize this record for machine-readable reports."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "reason": self.reason,
            "group_name": self.group_name,
        }


@dataclass
class AuditData:
    """Container for all data needed for audit rules."""

    # Protocol and server information
    protocol_version: str | None = None
    server_info: Implementation | None = None
    capabilities: ServerCapabilities | None = None
    instructions: str | None = None
    tools: list[Tool] | None = None
    resources: list[Resource] | None = None
    resource_templates: list[ResourceTemplate] | None = None
    prompts: list[Prompt] | None = None

    # Transport and connection information (for HTTP/SSE audits)
    transport_type: MCPTransportType | None = None
    url: str | None = None
    tls_verified: bool | None = None
    tls_version: str | None = None
    connection_time_ms: int | None = None
    server_headers: dict[str, str] | None = None

    # Sessionless probe observations (see mcpscore.probes), keyed by probe_id.
    # None until the auditor's probe-collection phase has run.
    probes: dict[str, ProbeResult] | None = None

    # Package-registry metadata, for a package audit (mcpscore --package).
    # None for every server audit — the packaging rules are the only ones that
    # read it, and they are the only rules a package audit runs. Nothing here
    # comes from executing the package; see mcpscore.packages.
    package: PackageMetadata | None = None

    # Partial audit: no server session was available (e.g. an auth-gated
    # server), so only probe-derived rules were scored and session-dependent
    # rules skipped as insufficient-data. False for a normal full audit.
    partial: bool = False
    partial_reason: str | None = None

    # Which listings (tools, resources, resource_templates, prompts) the auditor actually
    # attempted. `tools=None` is ambiguous on its own — the listing may have
    # failed, or may never have been tried (the session path only lists a
    # feature the server declares; the modern-only probe path collects tools
    # alone). Rules that judge declared-vs-served must skip what was never
    # attempted instead of reading silence as failure.
    listings_attempted: frozenset[str] = frozenset()

    # Listings for which the client returned only partial evidence because
    # pagination failed, repeated a cursor, or exceeded its safety bound.
    incomplete_listings: frozenset[str] = frozenset()


# Decorators to specify what data a rule needs
def requires_protocol_version(func: Callable) -> Callable:
    """Indicate this rule only needs protocol_version."""

    @wraps(func)
    def wrapper(self: BaseRule, audit_data: AuditData) -> RuleResult:
        return func(self, audit_data.protocol_version)

    wrapper._requires = "protocol_version"  # type: ignore[attr-defined]
    return wrapper


def requires_server_info(func: Callable) -> Callable:
    """Indicate this rule only needs server_info."""

    @wraps(func)
    def wrapper(self: BaseRule, audit_data: AuditData) -> RuleResult:
        return func(self, audit_data.server_info)

    wrapper._requires = "server_info"  # type: ignore[attr-defined]
    return wrapper


def requires_capabilities(func: Callable) -> Callable:
    """Indicate this rule only needs capabilities."""

    @wraps(func)
    def wrapper(self: BaseRule, audit_data: AuditData) -> RuleResult:
        return func(self, audit_data.capabilities)

    wrapper._requires = "capabilities"  # type: ignore[attr-defined]
    return wrapper


def requires_tools(func: Callable) -> Callable:
    """Indicate this rule only needs tools."""

    @wraps(func)
    def wrapper(self: BaseRule, audit_data: AuditData) -> RuleResult:
        return func(self, audit_data.tools)

    wrapper._requires = "tools"  # type: ignore[attr-defined]
    return wrapper


def requires_fields(
    *field_names: str,
) -> Callable[[Callable[..., RuleResult]], Callable[[BaseRule, AuditData], RuleResult]]:
    """Indicate this rule needs specific fields from audit_data.

    Args:
        *field_names: Names of the fields from AuditData that this rule needs

    Usage:
        @requires_fields('protocol_version', 'server_info')
        def check(self, protocol_version: str, server_info: Implementation | None) -> RuleResult:
            # Rule implementation

    """

    def decorator(
        func: Callable[..., RuleResult],
    ) -> Callable[[BaseRule, AuditData], RuleResult]:
        @wraps(func)
        def wrapper(self: BaseRule, audit_data: AuditData) -> RuleResult:
            # Extract the requested fields from audit_data
            args = []
            for field_name in field_names:
                if hasattr(audit_data, field_name):
                    args.append(getattr(audit_data, field_name))
                else:
                    raise AttributeError(f"AuditData has no field '{field_name}'")
            return func(self, *args)

        wrapper._requires = field_names  # type: ignore[attr-defined]
        return wrapper

    return decorator


def requires_full_data(
    func: Callable[[BaseRule, AuditData], RuleResult],
) -> Callable[[BaseRule, AuditData], RuleResult]:
    """Indicate this rule needs the full AuditData object."""

    @wraps(func)
    def wrapper(self: BaseRule, audit_data: AuditData) -> RuleResult:
        return func(self, audit_data)

    wrapper._requires = "full_data"  # type: ignore[attr-defined]
    return wrapper


class BaseRule(ABC):
    """Abstract base class for all MCP audit rules.

    This class defines the interface that all audit rules must implement.
    Each rule represents a specific compliance check that can be performed
    on an MCP server during the audit process.

    Rules are automatically registered when decorated with @register_rule
    and must define a unique rule_id attribute.

    Rules can be organized into groups and ordered within those groups
    for controlled execution order during audits.
    """

    rule_id: str = ""
    """Unique identifier for this rule. Must be set by subclasses."""

    basis: str | None = None
    """Primary-source citation for the requirement this rule enforces, e.g.
    an MCP spec section or a labeled best practice. The auditor injects it
    into every result's ``details["basis"]`` unless the check already set
    that key itself. Two rule families cite differently and leave this
    attribute unset: auth-posture rules build ``details["basis"]`` inline
    (per-result RFC sections), and readiness rules cite SEPs via their
    ``details["sep"]`` key."""

    group_name: str = "default"
    """Group name for organizing related rules. Rules in the same group
    are executed together. Groups are executed in alphabetical order
    unless overridden by group_order."""

    group_order: int = 0
    """Order for rule groups. Lower numbers execute first.
    Groups with the same group_order are sorted alphabetically by group_name."""

    rule_order: int = 0
    """Order for rules within the same group. Lower numbers execute first.
    Rules with the same rule_order are sorted alphabetically by rule_id."""

    min_spec_version: str | None = None
    """Oldest spec version this rule applies to (inclusive), e.g. the version
    that introduced the behavior it checks. None = applies since the first
    spec revision."""

    max_spec_version: str | None = None
    """Newest spec version this rule applies to (inclusive), e.g. the last
    version before the behavior it checks was removed. None = still applies
    to the current spec."""

    uses_modern_probe_evidence: bool = False
    """Whether applicability follows an observed modern probe surface.

    Dual-era audits retain the legacy session's negotiated version in
    ``AuditData``. Rules that judge an independently probed modern surface set
    this flag so their static version range is evaluated against the modern
    revision instead.
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__()
        # kwargs maybe used by subclasses to store additional data
        self.kwargs = kwargs

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Give a reason to skip this rule for this audit, or None to run it.

        Unlike applies_to (a static spec-version range), this hook sees the
        collected audit data — rules whose observations are unavailable
        (e.g. an errored probe) or redundant (e.g. detail readiness checks on
        a server with no modern support) return a reason string and are
        recorded as skipped instead of failing.

        Args:
            audit_data: The collected server data for this audit

        Returns:
            A skip-reason string (see the SKIP_REASON_* constants), or None

        """
        return None

    def applies_to(self, negotiated_version: str | None) -> bool:
        """Whether this rule applies to a server on the given spec version.

        A rule declares the spec-version range it is meaningful for via
        min_spec_version/max_spec_version; outside that range the auditor
        skips it (excluded from both score and max score) instead of failing
        it, so servers on different spec versions get comparable scores.

        Args:
            negotiated_version: The spec version the server negotiated, or
                None when no version is available (the rule then runs — a
                missing version is a finding for the version rules, not a
                reason to silently skip everything else)

        Returns:
            True if the rule should be executed against this server

        """
        if negotiated_version is None:
            return True
        if self.min_spec_version is not None and compare(negotiated_version, self.min_spec_version) < 0:
            return False
        return not (self.max_spec_version is not None and compare(negotiated_version, self.max_spec_version) > 0)

    @property
    @abstractmethod
    def rule_name(self) -> str:
        """Human-readable name of this rule.

        Returns:
            Descriptive name for display in audit reports

        """
        ...

    @property
    @abstractmethod
    def severity(self) -> RuleSeverity:
        """Severity level of this rule.

        Returns:
            RuleSeverity enum value indicating the importance of this check

        """
        ...

    @abstractmethod
    def check(self, audit_data: AuditData) -> RuleResult:
        """Execute the rule check against the provided audit data.

        Args:
            audit_data: Container with all server data needed for the audit

        Returns:
            RuleResult indicating whether the rule passed or failed

        """
        ...


def rule_sort_key(rule: BaseRule) -> tuple[int, str, int, str]:
    """Sort key implementing exactly the ordering the attributes document.

    Lower ``group_order`` first; groups sharing a ``group_order`` sort
    alphabetically by ``group_name``; within a group, ``rule_order`` then
    ``rule_id``. Every tie-break is total, so the resulting order is
    deterministic regardless of registration (import) order.

    A module function, deliberately not a ``BaseRule`` property: the previous
    ``sort_order`` property (``group_order * 1000 + rule_order``) had no
    tie-breakers — equal keys fell back to import order, which made the
    ``capabilities`` and ``security`` groups (both ``group_order`` 3)
    interleave in report output — and, being overridable, let a subclass keep
    returning the old ``int`` shape and blow up the mixed-key sort with a
    ``TypeError``. Ordering is collection policy, not per-rule behavior, so
    no subclass gets a say in it.

    Args:
        rule: The rule to derive the key for.

    Returns:
        The (group_order, group_name, rule_order, rule_id) sort key.

    """
    return (rule.group_order, rule.group_name, rule.rule_order, rule.rule_id)
