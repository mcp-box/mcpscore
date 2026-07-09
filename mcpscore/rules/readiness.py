"""Readiness rules for the next MCP spec revision (2026-07-28).

These rules answer "is this server ready for the upcoming spec?" — a separate
question from "does it comply with the spec it speaks today". The auditor
scores the ``readiness`` group on its own axis (readiness_score/readiness_max)
so a fully compliant legacy server keeps its clean main score and readiness is
purely informative, never punitive.

Most rules here consume probe observations (see ``mcpscore.probes``): the two
CRITICAL gateway rules check modern-lifecycle support itself, and the detail
rules skip with ``requires-modern-support`` when both gateways failed — the
verdict "not ready" is already carried by the gateways; repeating it per
detail adds noise, not information. The two session-based rules (deprecated
features, tool schema dialect) run regardless: a legacy server can fix those
today.

Each rule cites the SEP / spec section it enforces in its result details.
When 2026-07-28 goes final and adoption normalizes, these rules migrate into
the main groups (group_name flip + min_spec_version="2026-07-28") with their
rule_ids unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from jsonschema.exceptions import SchemaError
from jsonschema.validators import Draft202012Validator

from mcpscore.probes import (
    GATEWAY_PROBE_IDS,
    PROBE_DISCOVER,
    PROBE_HEADER_MISMATCH,
    PROBE_MALFORMED_META,
    PROBE_MISSING_RESOURCE,
    PROBE_REMOVED_METHOD,
    PROBE_SESSION_ID_ECHO,
    PROBE_STATELESS_LIST,
    PROBE_UNKNOWN_VERSION,
    REMOVED_METHOD,
    ProbeOutcome,
    has_modern_support,
)
from mcpscore.spec import DRAFT, LATEST

from .base import (
    READINESS_GROUP,
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_REQUIRES_MODERN_SUPPORT,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
)
from .registry import register_rule

if TYPE_CHECKING:
    from mcpscore.probes import ProbeResult

READINESS_TARGET = (DRAFT or LATEST).version
"""Spec version the readiness rules assess against."""

_JSON_SCHEMA_2020_12 = "https://json-schema.org/draft/2020-12/schema"

_VALID_CACHE_SCOPES = frozenset({"public", "private"})


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
        if result is None or result.outcome in (ProbeOutcome.ERROR, ProbeOutcome.NOT_APPLICABLE):
            return SKIP_REASON_INSUFFICIENT_DATA
        if self.requires_modern_support and not has_modern_support(probes):
            return SKIP_REASON_REQUIRES_MODERN_SUPPORT
        return None

    def _probe(self, audit_data: AuditData) -> ProbeResult:
        """Return this rule's probe result (skip_reason guarantees presence)."""
        assert audit_data.probes is not None  # noqa: S101 — guaranteed by skip_reason
        return audit_data.probes[self.probe_id]


@register_rule
class ServerDiscoverReadinessRule(ProbeBackedReadinessRule):
    """Gateway check: the server implements the mandatory ``server/discover`` (SEP-2567)."""

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
                f"✅ Server answers server/discover (supported versions: {probe.details.get('supported_versions')})"
            )
        else:
            message = f"❌ Server does not answer server/discover — mandatory from {READINESS_TARGET} (SEP-2567)"
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2567", "target_version": READINESS_TARGET, **probe.details},
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
            message = (
                f"❌ Server rejects stateless requests — from {READINESS_TARGET} the initialize "
                "handshake is removed and every request carries its context in _meta (SEP-2575)"
            )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2575", "target_version": READINESS_TARGET, **probe.details},
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
            message = "✅ Server rejects requests missing required _meta fields with -32602 and HTTP 400"
        else:
            message = (
                "❌ Server does not reject a request missing required _meta fields with "
                "-32602 (Invalid params) and HTTP 400, as the spec requires"
            )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2575", "target_version": READINESS_TARGET, **probe.details},
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
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2243", "target_version": READINESS_TARGET, **probe.details},
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
        passed = not missing
        if passed:
            message = "✅ Modern results carry valid caching hints (ttlMs >= 0, cacheScope public/private)"
        else:
            message = (
                f"❌ Results are missing the mandatory caching hints ttlMs/cacheScope (SEP-2549): "
                f"{', '.join(sorted(missing))}"
            )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "sep": "SEP-2549",
                "target_version": READINESS_TARGET,
                "observed": {pid: probe.details for pid, probe in supported.items()},
            },
        )


@register_rule
class UnsupportedVersionErrorReadinessRule(ProbeBackedReadinessRule):
    """Unknown protocol versions are rejected with -32022 naming the supported versions."""

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
            message = (
                f"✅ Unknown protocol versions are rejected with -32022 (supported: {probe.details.get('supported')})"
            )
        else:
            message = (
                "❌ An unknown protocol version is not rejected with -32022 "
                "(UnsupportedProtocolVersion) listing the supported versions"
            )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2575", "target_version": READINESS_TARGET, **probe.details},
        )


@register_rule
class ErrorCodeMigrationReadinessRule(ProbeBackedReadinessRule):
    """Missing resources yield -32602, not the legacy -32002 (SEP-2164)."""

    rule_id = "readiness_2026_error_code_migration"
    rule_order = 7
    probe_id = PROBE_MISSING_RESOURCE

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
            observed_code = probe.details.get("error_code")
            message = f"❌ Missing resources are not rejected with -32602 (observed error code: {observed_code})"
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2164", "target_version": READINESS_TARGET, **probe.details},
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
        return CacheMetadataReadinessRule.skip_reason(self, audit_data)  # type: ignore[arg-type]

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
                f"❌ Results are missing the mandatory resultType discriminator (SEP-2322): "
                f"{', '.join(sorted(missing))}"
            )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "sep": "SEP-2322",
                "target_version": READINESS_TARGET,
                "observed": {pid: probe.details.get("result_type") for pid, probe in supported.items()},
            },
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
            message = f"✅ No features deprecated in {READINESS_TARGET} are declared"
        else:
            message = (
                f"❌ Server declares features deprecated in {READINESS_TARGET}: {', '.join(flagged)} "
                "(logging: migrate to stderr for stdio or OpenTelemetry; SEP-2577)"
            )
        return RuleResult(
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
    def _schema_problems(schema: dict[str, Any]) -> list[str]:
        declared = schema.get("$schema")
        problems: list[str] = []
        network_refs: list[str] = []
        _find_network_refs(schema, network_refs)
        problems.extend(f"network $ref: {ref}" for ref in network_refs)
        if declared is None or declared == _JSON_SCHEMA_2020_12:
            try:
                Draft202012Validator.check_schema(schema)
            except SchemaError as e:
                problems.append(f"invalid under JSON Schema 2020-12: {e.message}")
        return problems

    def check(self, audit_data: AuditData) -> RuleResult:
        offending: dict[str, list[str]] = {}
        for tool in audit_data.tools or []:
            problems: list[str] = []
            input_schema = getattr(tool, "inputSchema", None)
            if isinstance(input_schema, dict):
                problems.extend(self._schema_problems(input_schema))
            output_schema = getattr(tool, "outputSchema", None)
            if isinstance(output_schema, dict):
                problems.extend(self._schema_problems(output_schema))
            if problems:
                offending[getattr(tool, "name", "<unnamed>")] = problems

        passed = not offending
        if passed:
            message = "✅ All tool schemas are valid under the JSON Schema 2020-12 default dialect"
        else:
            message = (
                f"❌ Tool schemas not valid under the {READINESS_TARGET} default dialect "
                f"(JSON Schema 2020-12): {', '.join(sorted(offending))}"
            )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2106", "target_version": READINESS_TARGET, "offending_tools": offending},
        )


@register_rule
class NoSessionIdReadinessRule(ProbeBackedReadinessRule):
    """Legacy-leakage check: no ``Mcp-Session-Id`` minted or echoed on modern requests.

    Session IDs are removed in the target revision; a server serving modern
    requests must ignore an incoming ``Mcp-Session-Id`` and never mint or echo
    one. Runs only when modern support was detected (inverse gating): a
    legacy-only server keeping sessions is correct behavior, not leakage.
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
                f"❌ Server echoes/mints an Mcp-Session-Id ('{echoed}') on a modern request — "
                f"session IDs are removed in {READINESS_TARGET} and must not be emitted (SEP-2575)"
            )
        else:
            message = (
                "❌ Server does not serve a modern request carrying a spurious Mcp-Session-Id — "
                "the header must be ignored, not treated as an error (SEP-2575)"
            )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2575", "target_version": READINESS_TARGET, **probe.details},
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
            message = f"✅ Removed method '{REMOVED_METHOD}' is rejected with HTTP 404 and -32601"
        elif probe.details.get("method_served"):
            message = (
                f"❌ Server still serves '{REMOVED_METHOD}', which is removed in {READINESS_TARGET} — "
                "leaked legacy surface (SEP-2575)"
            )
        else:
            message = (
                f"❌ Removed method '{REMOVED_METHOD}' is not rejected with HTTP 404 and -32601 "
                "(Method not found) as the spec requires"
            )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"sep": "SEP-2575", "target_version": READINESS_TARGET, **probe.details},
        )
