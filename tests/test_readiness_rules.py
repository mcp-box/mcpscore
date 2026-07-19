"""Tests for the 2026 readiness rule pack and its scoring axis."""

from types import SimpleNamespace

from mcpscore.mcp_auditor import MCPAuditor
from mcpscore.probes import (
    PROBE_DISCOVER,
    PROBE_HEADER_MISMATCH,
    PROBE_IDS,
    PROBE_MALFORMED_META,
    PROBE_MISSING_RESOURCE,
    PROBE_REMOVED_METHOD,
    PROBE_SESSION_ID_ECHO,
    PROBE_STATELESS_LIST,
    PROBE_UNAUTHENTICATED,
    PROBE_UNKNOWN_VERSION,
    ProbeOutcome,
    ProbeResult,
    detect_era,
    not_applicable_results,
)
from mcpscore.rules import AuditData
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_REQUIRES_MODERN_SUPPORT
from mcpscore.rules.readiness import (
    CacheMetadataReadinessRule,
    DeprecatedFeaturesReadinessRule,
    ErrorCodeMigrationReadinessRule,
    HeaderValidationReadinessRule,
    MetaValidationReadinessRule,
    NoSessionIdReadinessRule,
    RemovedMethodsReadinessRule,
    ResultTypeReadinessRule,
    ServerDiscoverReadinessRule,
    StatelessRequestReadinessRule,
    ToolSchemaDialectReadinessRule,
    UnsupportedVersionErrorReadinessRule,
)
from mcpscore.spec import Era

from .conftest import FakeLoggingCaps, FakeServerCapabilities


def modern_probes(**overrides: ProbeResult) -> dict[str, ProbeResult]:
    """Probe observations of a fully 2026-ready server."""
    good_hints = {"http_status": 200, "result_type": "complete", "ttl_ms": 60000, "cache_scope": "public"}
    results = {
        PROBE_DISCOVER: ProbeResult(
            PROBE_DISCOVER, ProbeOutcome.SUPPORTED, {**good_hints, "supported_versions": ["2026-07-28"]}
        ),
        PROBE_STATELESS_LIST: ProbeResult(PROBE_STATELESS_LIST, ProbeOutcome.SUPPORTED, dict(good_hints)),
        PROBE_MALFORMED_META: ProbeResult(PROBE_MALFORMED_META, ProbeOutcome.SUPPORTED, {"http_status": 400}),
        PROBE_HEADER_MISMATCH: ProbeResult(PROBE_HEADER_MISMATCH, ProbeOutcome.SUPPORTED, {"http_status": 400}),
        PROBE_UNKNOWN_VERSION: ProbeResult(
            PROBE_UNKNOWN_VERSION, ProbeOutcome.SUPPORTED, {"supported": ["2026-07-28"], "requested": "2099-01-01"}
        ),
        PROBE_MISSING_RESOURCE: ProbeResult(
            PROBE_MISSING_RESOURCE, ProbeOutcome.SUPPORTED, {"error_code": -32602, "legacy_code_emitted": False}
        ),
        PROBE_UNAUTHENTICATED: ProbeResult(
            PROBE_UNAUTHENTICATED, ProbeOutcome.SUPPORTED, {"http_status": 200, "www_authenticate": None}
        ),
        PROBE_SESSION_ID_ECHO: ProbeResult(
            PROBE_SESSION_ID_ECHO,
            ProbeOutcome.SUPPORTED,
            {"http_status": 200, "request_served": True, "response_session_id": None},
        ),
        PROBE_REMOVED_METHOD: ProbeResult(
            PROBE_REMOVED_METHOD,
            ProbeOutcome.SUPPORTED,
            {"http_status": 404, "error_code": -32601, "method_served": False},
        ),
    }
    results.update(overrides)
    return results


def legacy_probes() -> dict[str, ProbeResult]:
    """Probe observations of a legacy-only server (rejects everything modern)."""
    details = {"http_status": 400, "error_code": -32600}
    results = {probe_id: ProbeResult(probe_id, ProbeOutcome.UNSUPPORTED, dict(details)) for probe_id in PROBE_IDS}
    results[PROBE_UNAUTHENTICATED] = ProbeResult(PROBE_UNAUTHENTICATED, ProbeOutcome.SUPPORTED, dict(details))
    results[PROBE_MISSING_RESOURCE] = ProbeResult(
        PROBE_MISSING_RESOURCE, ProbeOutcome.UNSUPPORTED, {**details, "legacy_code_emitted": False}
    )
    return results


class TestGatewayRules:
    def test_pass_against_modern_server(self):
        data = AuditData(probes=modern_probes())
        assert ServerDiscoverReadinessRule().check(data).passed
        assert StatelessRequestReadinessRule().check(data).passed

    def test_fail_against_legacy_server(self):
        data = AuditData(probes=legacy_probes())
        for rule in (ServerDiscoverReadinessRule(), StatelessRequestReadinessRule()):
            assert rule.skip_reason(data) is None  # gateways run even without modern support
            result = rule.check(data)
            assert not result.passed
            assert result.details["sep"]

    def test_skipped_when_probes_not_applicable(self):
        data = AuditData(probes=not_applicable_results(reason="stdio"))
        assert ServerDiscoverReadinessRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_skipped_when_probes_missing(self):
        data = AuditData(probes=None)
        assert ServerDiscoverReadinessRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA


class TestDetailProbeRules:
    DETAIL_RULES = (
        MetaValidationReadinessRule,
        HeaderValidationReadinessRule,
        UnsupportedVersionErrorReadinessRule,
        ErrorCodeMigrationReadinessRule,
    )

    def test_pass_against_modern_server(self):
        data = AuditData(probes=modern_probes())
        for rule_cls in self.DETAIL_RULES:
            rule = rule_cls()
            assert rule.skip_reason(data) is None
            assert rule.check(data).passed, rule.rule_id

    def test_skip_without_modern_support(self):
        data = AuditData(probes=legacy_probes())
        for rule_cls in self.DETAIL_RULES:
            assert rule_cls().skip_reason(data) == SKIP_REASON_REQUIRES_MODERN_SUPPORT, rule_cls.rule_id

    def test_skip_when_own_probe_errored(self):
        probes = modern_probes(
            probe_malformed_meta=ProbeResult(PROBE_MALFORMED_META, ProbeOutcome.ERROR, {"exception": "ConnectError"})
        )
        data = AuditData(probes=probes)
        assert MetaValidationReadinessRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_fail_when_behavior_missing_despite_modern_support(self):
        probes = modern_probes(
            probe_header_mismatch=ProbeResult(PROBE_HEADER_MISMATCH, ProbeOutcome.UNSUPPORTED, {"http_status": 200})
        )
        data = AuditData(probes=probes)
        rule = HeaderValidationReadinessRule()
        assert rule.skip_reason(data) is None
        assert not rule.check(data).passed

    def test_error_code_migration_flags_legacy_code(self):
        probes = modern_probes(
            probe_missing_resource=ProbeResult(
                PROBE_MISSING_RESOURCE,
                ProbeOutcome.UNSUPPORTED,
                {"error_code": -32002, "legacy_code_emitted": True},
            )
        )
        result = ErrorCodeMigrationReadinessRule().check(AuditData(probes=probes))
        assert not result.passed
        assert "-32002" in result.message


class TestCacheMetadataRule:
    def test_pass_with_valid_hints(self):
        assert CacheMetadataReadinessRule().check(AuditData(probes=modern_probes())).passed

    def test_fail_when_hints_missing(self):
        probes = modern_probes(
            probe_stateless_list=ProbeResult(
                PROBE_STATELESS_LIST,
                ProbeOutcome.SUPPORTED,
                {"result_type": "complete", "ttl_ms": None, "cache_scope": None},
            )
        )
        result = CacheMetadataReadinessRule().check(AuditData(probes=probes))
        assert not result.passed
        assert PROBE_STATELESS_LIST in result.message

    def test_fail_when_cache_scope_invalid(self):
        probes = modern_probes(
            probe_discover=ProbeResult(
                PROBE_DISCOVER,
                ProbeOutcome.SUPPORTED,
                {"supported_versions": ["2026-07-28"], "result_type": "complete", "ttl_ms": 0, "cache_scope": "shared"},
            )
        )
        assert not CacheMetadataReadinessRule().check(AuditData(probes=probes)).passed

    def test_skip_without_modern_support(self):
        data = AuditData(probes=legacy_probes())
        assert CacheMetadataReadinessRule().skip_reason(data) == SKIP_REASON_REQUIRES_MODERN_SUPPORT


class TestResultTypeRule:
    def test_pass_with_complete_result_type(self):
        assert ResultTypeReadinessRule().check(AuditData(probes=modern_probes())).passed

    def test_fail_when_result_type_absent(self):
        probes = modern_probes(
            probe_stateless_list=ProbeResult(
                PROBE_STATELESS_LIST,
                ProbeOutcome.SUPPORTED,
                {"result_type": None, "ttl_ms": 0, "cache_scope": "public"},
            )
        )
        assert not ResultTypeReadinessRule().check(AuditData(probes=probes)).passed

    def test_skip_without_modern_support(self):
        data = AuditData(probes=legacy_probes())
        assert ResultTypeReadinessRule().skip_reason(data) == SKIP_REASON_REQUIRES_MODERN_SUPPORT


class TestDeprecatedFeaturesRule:
    def test_fail_when_logging_capability_declared(self):
        data = AuditData(capabilities=FakeServerCapabilities(logging=FakeLoggingCaps()))
        result = DeprecatedFeaturesReadinessRule().check(data)
        assert not result.passed
        assert "logging" in result.message
        assert result.details["deprecated_features_declared"] == ["logging"]

    def test_pass_without_deprecated_capabilities(self):
        data = AuditData(capabilities=FakeServerCapabilities())
        assert DeprecatedFeaturesReadinessRule().check(data).passed

    def test_skip_without_capabilities(self):
        data = AuditData(capabilities=None)
        assert DeprecatedFeaturesReadinessRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA


def _tool(name: str = "tool", input_schema: dict | None = None, output_schema: dict | None = None):
    return SimpleNamespace(
        name=name,
        input_schema=input_schema if input_schema is not None else {"type": "object", "properties": {}},
        output_schema=output_schema,
    )


class TestToolSchemaDialectRule:
    def test_pass_with_valid_2020_12_schemas(self):
        data = AuditData(tools=[_tool(input_schema={"type": "object", "properties": {"q": {"type": "string"}}})])
        assert ToolSchemaDialectReadinessRule().check(data).passed

    def test_pass_with_no_tools(self):
        assert ToolSchemaDialectReadinessRule().check(AuditData(tools=[])).passed

    def test_skip_when_tools_not_collected(self):
        assert ToolSchemaDialectReadinessRule().skip_reason(AuditData(tools=None)) == SKIP_REASON_INSUFFICIENT_DATA

    def test_fail_with_invalid_schema(self):
        data = AuditData(
            tools=[_tool(name="broken", input_schema={"type": "object", "properties": {"a": {"type": 123}}})]
        )
        result = ToolSchemaDialectReadinessRule().check(data)
        assert not result.passed
        assert "broken" in result.details["offending_tools"]

    def test_fail_with_network_ref(self):
        schema = {"type": "object", "properties": {"a": {"$ref": "https://evil.example/schema.json"}}}
        result = ToolSchemaDialectReadinessRule().check(AuditData(tools=[_tool(name="reffy", input_schema=schema)]))
        assert not result.passed
        assert any("network $ref" in p for p in result.details["offending_tools"]["reffy"])

    def test_other_declared_dialect_is_not_validated(self):
        schema = {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {"a": {"type": 123}},
        }
        result = ToolSchemaDialectReadinessRule().check(AuditData(tools=[_tool(input_schema=schema)]))
        # draft-07 declared: not validated against 2020-12... but the network $schema value is not a $ref
        assert result.passed

    def test_output_schema_is_checked_too(self):
        data = AuditData(
            tools=[_tool(name="out", output_schema={"type": "object", "properties": {"a": {"type": 123}}})]
        )
        assert not ToolSchemaDialectReadinessRule().check(data).passed


class TestEraDetection:
    def test_modern_only(self):
        assert detect_era(None, modern_probes()) is Era.MODERN

    def test_legacy_only(self):
        assert detect_era("2025-11-25", legacy_probes()) is Era.LEGACY

    def test_dual_era(self):
        assert detect_era("2025-11-25", modern_probes()) is Era.DUAL

    def test_modern_via_recognized_error_only(self):
        probes = legacy_probes()
        probes[PROBE_UNKNOWN_VERSION] = ProbeResult(
            PROBE_UNKNOWN_VERSION, ProbeOutcome.SUPPORTED, {"supported": ["2026-07-28"]}
        )
        assert detect_era(None, probes) is Era.MODERN

    def test_no_evidence(self):
        assert detect_era(None, not_applicable_results(reason="stdio")) is None
        assert detect_era(None, None) is None


class TestReadinessScoringAxis:
    def _audit(self, protocol_version: str | None, probes: dict[str, ProbeResult]) -> MCPAuditor:
        auditor = MCPAuditor()
        auditor.audit_data = AuditData(protocol_version=protocol_version, probes=probes)
        auditor._run_all_rules()
        return auditor

    def test_readiness_never_touches_main_score(self):
        auditor = self._audit("2025-11-25", modern_probes())

        readiness_ids = {r.rule_id for r in auditor.readiness_results}
        main_ids = {r.rule_id for r in auditor.results}
        assert readiness_ids
        assert all(rid.startswith("readiness_") for rid in readiness_ids)
        assert not any(rid.startswith("readiness_") for rid in main_ids)
        assert auditor.readiness_max > 0

    def test_legacy_server_readiness_gateways_fail_details_skip(self):
        auditor = self._audit("2025-11-25", legacy_probes())

        failed = {r.rule_id for r in auditor.readiness_results if not r.passed}
        assert "readiness_2026_server_discover" in failed
        assert "readiness_2026_stateless_request" in failed

        skipped = {s.rule_id: s.reason for s in auditor.skipped_rules}
        assert skipped["readiness_2026_meta_validation"] == SKIP_REASON_REQUIRES_MODERN_SUPPORT
        assert skipped["readiness_2026_header_validation"] == SKIP_REASON_REQUIRES_MODERN_SUPPORT

    def test_report_carries_spec_and_readiness_sections(self):
        auditor = self._audit("2025-11-25", legacy_probes())
        auditor.era = detect_era("2025-11-25", legacy_probes())

        report = auditor.get_audit_report()
        assert report["spec"]["negotiated_version"] == "2025-11-25"
        assert report["spec"]["latest_version"] == "2025-11-25"
        assert report["spec"]["readiness_target"] == "2026-07-28"
        assert report["spec"]["era"] == "legacy"
        assert report["readiness"]["max_score"] > 0
        assert report["readiness"]["score"] < report["readiness"]["max_score"]
        assert all(r["rule_id"].startswith("readiness_") for r in report["readiness"]["results"])


class TestLegacyLeakageRules:
    def test_pass_against_clean_modern_server(self):
        data = AuditData(probes=modern_probes())
        assert NoSessionIdReadinessRule().check(data).passed
        assert RemovedMethodsReadinessRule().check(data).passed

    def test_skip_without_modern_support(self):
        data = AuditData(probes=legacy_probes())
        assert NoSessionIdReadinessRule().skip_reason(data) == SKIP_REASON_REQUIRES_MODERN_SUPPORT
        assert RemovedMethodsReadinessRule().skip_reason(data) == SKIP_REASON_REQUIRES_MODERN_SUPPORT

    def test_fail_when_session_id_is_echoed(self):
        probes = modern_probes(
            probe_session_id_echo=ProbeResult(
                PROBE_SESSION_ID_ECHO,
                ProbeOutcome.UNSUPPORTED,
                {"http_status": 200, "request_served": True, "response_session_id": "leaky-session-1"},
            )
        )
        result = NoSessionIdReadinessRule().check(AuditData(probes=probes))
        assert not result.passed
        assert "leaky-session-1" in result.message

    def test_fail_when_session_id_request_rejected(self):
        probes = modern_probes(
            probe_session_id_echo=ProbeResult(
                PROBE_SESSION_ID_ECHO,
                ProbeOutcome.UNSUPPORTED,
                {"http_status": 400, "request_served": False, "response_session_id": None},
            )
        )
        result = NoSessionIdReadinessRule().check(AuditData(probes=probes))
        assert not result.passed
        assert "ignored" in result.message

    def test_fail_when_removed_method_still_served(self):
        probes = modern_probes(
            probe_removed_method=ProbeResult(
                PROBE_REMOVED_METHOD,
                ProbeOutcome.UNSUPPORTED,
                {"http_status": 200, "method_served": True},
            )
        )
        result = RemovedMethodsReadinessRule().check(AuditData(probes=probes))
        assert not result.passed
        assert "still serves" in result.message

    def test_fail_when_rejection_shape_is_wrong(self):
        probes = modern_probes(
            probe_removed_method=ProbeResult(
                PROBE_REMOVED_METHOD,
                ProbeOutcome.UNSUPPORTED,
                {"http_status": 400, "error_code": -32600, "method_served": False},
            )
        )
        result = RemovedMethodsReadinessRule().check(AuditData(probes=probes))
        assert not result.passed
        assert "-32601" in result.message


class TestUncoveredBranches:
    def test_meta_validation_fail_message(self):
        probes = modern_probes(
            probe_malformed_meta=ProbeResult(PROBE_MALFORMED_META, ProbeOutcome.UNSUPPORTED, {"http_status": 200})
        )
        result = MetaValidationReadinessRule().check(AuditData(probes=probes))
        assert not result.passed
        assert "-32602" in result.message

    def test_unsupported_version_error_fail_message(self):
        probes = modern_probes(
            probe_unknown_version=ProbeResult(PROBE_UNKNOWN_VERSION, ProbeOutcome.UNSUPPORTED, {"http_status": 200})
        )
        result = UnsupportedVersionErrorReadinessRule().check(AuditData(probes=probes))
        assert not result.passed
        assert "-32022" in result.message

    def test_error_code_migration_reports_unexpected_code(self):
        probes = modern_probes(
            probe_missing_resource=ProbeResult(
                PROBE_MISSING_RESOURCE,
                ProbeOutcome.UNSUPPORTED,
                {"error_code": -32000, "legacy_code_emitted": False},
            )
        )
        result = ErrorCodeMigrationReadinessRule().check(AuditData(probes=probes))
        assert not result.passed
        assert "-32000" in result.message

    def test_cache_metadata_skips_without_any_probe_data(self):
        assert CacheMetadataReadinessRule().skip_reason(AuditData(probes=None)) == SKIP_REASON_INSUFFICIENT_DATA

    def test_cache_metadata_skips_when_gateways_errored(self):
        probes = {
            PROBE_DISCOVER: ProbeResult(PROBE_DISCOVER, ProbeOutcome.ERROR, {"exception": "ConnectError"}),
            PROBE_STATELESS_LIST: ProbeResult(PROBE_STATELESS_LIST, ProbeOutcome.NOT_APPLICABLE, {}),
        }
        rule = CacheMetadataReadinessRule()
        assert rule.skip_reason(AuditData(probes=probes)) == SKIP_REASON_INSUFFICIENT_DATA

    def test_result_type_skips_without_any_probe_data(self):
        assert ResultTypeReadinessRule().skip_reason(AuditData(probes=None)) == SKIP_REASON_INSUFFICIENT_DATA

    def test_network_ref_found_inside_schema_lists(self):
        schema = {
            "type": "object",
            "properties": {"a": {"anyOf": [{"type": "string"}, {"$ref": "https://evil.example/x.json"}]}},
        }
        result = ToolSchemaDialectReadinessRule().check(AuditData(tools=[_tool(name="listy", input_schema=schema)]))
        assert not result.passed
        assert any("network $ref" in p for p in result.details["offending_tools"]["listy"])

    def test_non_dict_input_schema_is_ignored(self):
        tool = _tool(name="odd")
        tool.inputSchema = None
        assert ToolSchemaDialectReadinessRule().check(AuditData(tools=[tool])).passed
