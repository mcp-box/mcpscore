from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum
from functools import wraps
from typing import TYPE_CHECKING, Any

from mcpscore.spec import compare

if TYPE_CHECKING:
    from collections.abc import Callable

    from mcp.types import Implementation, Prompt, Resource, ServerCapabilities, Tool

    from ..enums import MCPTransportType
    from ..probes import ProbeResult

SKIP_REASON_NOT_APPLICABLE = "not-applicable"
"""Skip reason for rules whose spec-version range excludes the negotiated version."""


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

    def to_dict(self) -> dict:
        """Serialize this record for machine-readable reports."""
        return {"rule_id": self.rule_id, "rule_name": self.rule_name, "reason": self.reason}


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
    prompts: list[Prompt] | None = None

    # Transport and connection information (for HTTP/SSE audits)
    transport_type: MCPTransportType | None = None
    url: str | None = None
    tls_verified: bool | None = None
    tls_version: str | None = None
    connection_time_ms: int | None = None
    server_headers: dict[str, str] | None = None
    error_response: str | None = None

    # Sessionless probe observations (see mcpscore.probes), keyed by probe_id.
    # None until the auditor's probe-collection phase has run.
    probes: dict[str, ProbeResult] | None = None


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

    def __init__(self, **kwargs: Any) -> None:
        super().__init__()
        # kwargs maybe used by subclasses to store additional data
        self.kwargs = kwargs

    @property
    def sort_order(self) -> int:
        """Sort order of this rule.

        Returns:
            A numerical value used for sorting rules

        """
        return self.group_order * 1000 + self.rule_order

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
