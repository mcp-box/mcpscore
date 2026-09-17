"""A dual-era server whose legacy tools/list fails is judged on its stateless catalog."""

import logging
from typing import Any

from mcp_types import InitializeResult
import pytest

from mcpscore import mcp_auditor
from mcpscore.mcp_auditor import MCPAuditor
from mcpscore.mcp_client import MCPClient
from mcpscore.probes import (
    PROBE_DISCOVER,
    PROBE_STATELESS_LIST,
    ProbeOutcome,
    ProbeResult,
    not_applicable_results,
)
from mcpscore.rules import AuditData, BaseRule, RuleResult, RuleSeverity
from mcpscore.rules.base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_NOT_APPLICABLE,
    requires_fields,
    requires_full_data,
    requires_tools,
)
from mcpscore.rules.capabilities import CapabilityToolsPresentRule
from mcpscore.spec import Era

URL = "https://dual.example/mcp"
LEGACY_ERROR = {"outcome": "rpc_error", "page_index": 0, "error_code": -32603}

INIT_RESULT = InitializeResult.model_validate(
    {
        "protocolVersion": "2025-11-25",
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {"name": "weather", "version": "1.0"},
    }
)

ARRAY_ROOT_TOOL = {
    "name": "get_alerts",
    "description": "Get weather alerts for a US state.",
    "inputSchema": {
        "type": "object",
        "properties": {"state": {"type": "string", "description": "Two-letter US state code"}},
        "required": ["state"],
    },
    # Legal from 2026-07-28; forbidden on 2025-11-25, which is why the legacy listing failed.
    "outputSchema": {"type": "array", "items": {"type": "object"}},
}


PARTIAL_LEGACY_ERROR = {"outcome": "rpc_error", "page_index": 1, "error_code": -32602}
"""The second page of the session listing failed; page one was served."""

SESSION_TOOL = {"name": "echo", "description": "Echo", "inputSchema": {"type": "object"}}


class LegacyListingFailsClient(MCPClient):
    """A connected client whose session tools/list answered with a JSON-RPC error."""

    def __init__(self, tools: list[Any] | None = None, *, partial: bool = False) -> None:
        super().__init__()
        self._tools = tools
        self.url = URL
        self.transport_type = "streamable-http"  # type: ignore[assignment]
        self.connection_time_ms = 10
        if tools is None:
            self.listing_errors["tools"] = dict(LEGACY_ERROR)
            self.incomplete_listings.add("tools")
        elif partial:
            self.listing_errors["tools"] = dict(PARTIAL_LEGACY_ERROR)
            self.incomplete_listings.add("tools")

    async def initialize(self):
        return INIT_RESULT

    async def list_tools(self):
        return self._tools


def _probes(stateless_payload: dict | None, outcome: ProbeOutcome = ProbeOutcome.SUPPORTED) -> dict:
    results = not_applicable_results(reason="unset")
    results[PROBE_DISCOVER] = ProbeResult(
        PROBE_DISCOVER,
        ProbeOutcome.SUPPORTED,
        {"supported_versions": ["2025-11-25", "2026-07-28"]},
        payload={"supportedVersions": ["2025-11-25", "2026-07-28"], "capabilities": {"tools": {}}},
    )
    results[PROBE_STATELESS_LIST] = ProbeResult(
        PROBE_STATELESS_LIST,
        outcome,
        {"result_type": "complete", "ttl_ms": 0, "cache_scope": "private"},
        payload=stateless_payload,
    )
    return results


@pytest.fixture
def stateless_probes(monkeypatch: pytest.MonkeyPatch):
    """Let each test choose what the stateless probes observed."""

    def install(payload: dict | None, outcome: ProbeOutcome = ProbeOutcome.SUPPORTED) -> None:
        async def run_all_probes(url: str, client: Any = None, headers: Any = None) -> dict:
            return _probes(payload, outcome)

        monkeypatch.setattr(mcp_auditor, "run_all_probes", run_all_probes)

    return install


async def test_legacy_failure_recovers_the_stateless_catalog(stateless_probes):
    stateless_probes({"resultType": "complete", "tools": [ARRAY_ROOT_TOOL]})
    auditor = MCPAuditor()

    await auditor.audit(LegacyListingFailsClient())

    data = auditor.audit_data
    assert auditor.era is Era.DUAL
    assert [tool.name for tool in data.tools or []] == ["get_alerts"]
    assert data.catalog_versions == {"tools": "2026-07-28"}
    assert data.listing_errors["tools"] == LEGACY_ERROR
    assert "tools" not in data.incomplete_listings
    assert data.protocol_version == "2025-11-25"

    results = {result.rule_id: result for result in auditor.results}
    skipped = {rule.rule_id: rule.reason for rule in auditor.skipped_rules}
    assert results["tools_at_least_one"].passed
    assert "tools_names_unique" in results
    # Scoped to the older revision: it must not fail the array root the catalog's revision allows.
    assert skipped["tools_output_schema_root_object"] == SKIP_REASON_NOT_APPLICABLE
    assert "readiness_2026_tool_schema_dialect" not in skipped
    # Needs the legacy capabilities too: evidence from two lifecycles is not comparable.
    assert skipped["tools_execution_consistent"] == SKIP_REASON_INSUFFICIENT_DATA
    capability = results[CapabilityToolsPresentRule.rule_id]
    assert not capability.passed
    assert "returned JSON-RPC error -32603" in capability.message
    assert "2026-07-28 stateless lifecycle" in capability.message

    report = auditor.get_audit_report()
    assert report["spec"]["catalog_versions"] == {"tools": "2026-07-28"}
    assert report["listing_errors"]["tools"] == LEGACY_ERROR


async def test_incomplete_session_catalog_is_replaced_by_a_complete_modern_one(stateless_probes):
    """Page two of the legacy listing failed; the stateless listing serves the whole catalog."""
    from mcp_types import Tool

    stateless_probes({"resultType": "complete", "tools": [ARRAY_ROOT_TOOL, SESSION_TOOL]})
    auditor = MCPAuditor()

    await auditor.audit(LegacyListingFailsClient(tools=[Tool.model_validate(SESSION_TOOL)], partial=True))

    data = auditor.audit_data
    assert [tool.name for tool in data.tools or []] == ["get_alerts", "echo"]
    assert data.catalog_versions == {"tools": "2026-07-28"}
    assert "tools" not in data.incomplete_listings
    assert data.listing_errors["tools"] == PARTIAL_LEGACY_ERROR
    results = {result.rule_id: result for result in auditor.results}
    assert "tools_names_unique" in results
    capability = results[CapabilityToolsPresentRule.rule_id]
    assert capability.passed
    assert "tools/list on the negotiated session served part of the catalog" in capability.message
    assert "the 2 tools judged come from the 2026-07-28 stateless listing" in capability.message
    assert "serves 2 via" not in capability.message
    assert capability.details["collection_error"] == PARTIAL_LEGACY_ERROR
    assert capability.details["catalog_version"] == "2026-07-28"


async def test_incomplete_session_catalog_is_kept_when_the_modern_one_is_not_complete(stateless_probes, monkeypatch):
    from mcp_types import Tool

    async def run_all_probes(url: str, client: Any = None, headers: Any = None) -> dict:
        probes = _probes({"resultType": "partial", "tools": [ARRAY_ROOT_TOOL, SESSION_TOOL]})
        probes[PROBE_STATELESS_LIST].details["result_type"] = "partial"
        return probes

    monkeypatch.setattr(mcp_auditor, "run_all_probes", run_all_probes)
    auditor = MCPAuditor()

    await auditor.audit(LegacyListingFailsClient(tools=[Tool.model_validate(SESSION_TOOL)], partial=True))

    assert [tool.name for tool in auditor.audit_data.tools or []] == ["echo"]
    assert auditor.audit_data.catalog_versions == {}
    assert "tools" in auditor.audit_data.incomplete_listings


async def test_session_catalog_wins_when_the_legacy_listing_works(stateless_probes):
    stateless_probes({"resultType": "complete", "tools": [ARRAY_ROOT_TOOL]})
    auditor = MCPAuditor()
    session_tool = {"name": "echo", "description": "Echo", "inputSchema": {"type": "object"}}
    from mcp_types import Tool

    await auditor.audit(LegacyListingFailsClient(tools=[Tool.model_validate(session_tool)]))

    assert [tool.name for tool in auditor.audit_data.tools or []] == ["echo"]
    assert auditor.audit_data.catalog_versions == {}
    assert auditor.get_audit_report()["spec"]["catalog_versions"] == {}


async def test_partial_stateless_result_keeps_the_catalog_incomplete(stateless_probes, monkeypatch):
    payload = {"resultType": "partial", "tools": [ARRAY_ROOT_TOOL]}

    async def run_all_probes(url: str, client: Any = None, headers: Any = None) -> dict:
        probes = _probes(payload)
        probes[PROBE_STATELESS_LIST].details["result_type"] = "partial"
        return probes

    monkeypatch.setattr(mcp_auditor, "run_all_probes", run_all_probes)
    auditor = MCPAuditor()

    await auditor.audit(LegacyListingFailsClient())

    assert auditor.audit_data.catalog_versions == {"tools": "2026-07-28"}
    assert "tools" in auditor.audit_data.incomplete_listings


async def test_missing_result_type_keeps_the_catalog_incomplete(stateless_probes, monkeypatch):
    """ResultType is mandatory on the modern lifecycle; without it completeness is unproven."""

    async def run_all_probes(url: str, client: Any = None, headers: Any = None) -> dict:
        probes = _probes({"tools": [ARRAY_ROOT_TOOL]})
        probes[PROBE_STATELESS_LIST].details["result_type"] = None
        return probes

    monkeypatch.setattr(mcp_auditor, "run_all_probes", run_all_probes)
    auditor = MCPAuditor()

    await auditor.audit(LegacyListingFailsClient())

    assert auditor.audit_data.catalog_versions == {"tools": "2026-07-28"}
    assert "tools" in auditor.audit_data.incomplete_listings
    skipped = {rule.rule_id: rule.reason for rule in auditor.skipped_rules}
    assert skipped["tools_names_unique"] == SKIP_REASON_INSUFFICIENT_DATA
    readiness = {result.rule_id: result for result in auditor.readiness_results}
    assert not readiness["readiness_2026_result_type"].passed


async def test_no_recovery_when_the_stateless_listing_is_unsupported(stateless_probes):
    stateless_probes(None, outcome=ProbeOutcome.UNSUPPORTED)
    auditor = MCPAuditor()

    await auditor.audit(LegacyListingFailsClient())

    assert auditor.audit_data.tools is None
    assert auditor.audit_data.catalog_versions == {}
    skipped = {rule.rule_id: rule.reason for rule in auditor.skipped_rules}
    assert skipped["tools_at_least_one"] == SKIP_REASON_INSUFFICIENT_DATA


async def test_malformed_stateless_catalog_keeps_the_legacy_error(stateless_probes, caplog):
    caplog.set_level(logging.INFO, logger="mcpscore.mcp_auditor")
    stateless_probes({"resultType": "complete", "tools": [{"description": "no name"}]})
    auditor = MCPAuditor()

    await auditor.audit(LegacyListingFailsClient())

    assert auditor.audit_data.tools is None
    assert auditor.audit_data.catalog_versions == {}
    assert auditor.audit_data.listing_errors["tools"] == LEGACY_ERROR
    assert "Invalid tools catalog response from the stateless probe" in caplog.text


async def test_no_recovery_when_tools_were_never_attempted(stateless_probes):
    """A server without a tools capability never listed tools, so there is nothing to recover."""
    stateless_probes({"resultType": "complete", "tools": [ARRAY_ROOT_TOOL]})

    class NoToolsClient(LegacyListingFailsClient):
        async def initialize(self):
            return InitializeResult.model_validate(
                {"protocolVersion": "2025-11-25", "capabilities": {}, "serverInfo": {"name": "w", "version": "1"}}
            )

    auditor = MCPAuditor()
    await auditor.audit(NoToolsClient())

    assert auditor.audit_data.tools is None
    assert auditor.audit_data.catalog_versions == {}


class _ToolsRule(BaseRule):
    rule_id = "dummy_tools_rule"
    max_spec_version = "2025-11-25"

    @property
    def rule_name(self) -> str:
        return "dummy"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    @requires_tools
    def check(self, tools) -> RuleResult:
        return RuleResult(rule_name=self.rule_name, severity=self.severity, passed=True, message="ok")


class _FullDataRule(_ToolsRule):
    rule_id = "dummy_full_data_rule"

    @requires_full_data
    def check(self, audit_data: AuditData) -> RuleResult:
        return RuleResult(rule_name=self.rule_name, severity=self.severity, passed=True, message="ok")


class _ToolsAndCapabilitiesRule(_ToolsRule):
    rule_id = "dummy_tools_capabilities_rule"

    @requires_fields("tools", "capabilities")
    def check(self, tools, capabilities) -> RuleResult:  # type: ignore[override]
        return RuleResult(rule_name=self.rule_name, severity=self.severity, passed=True, message="ok")


def test_rules_spanning_both_lifecycles_are_skipped():
    auditor = MCPAuditor()
    auditor.audit_data.catalog_versions["tools"] = "2026-07-28"

    assert auditor._evidence_spans_lifecycles(_ToolsAndCapabilitiesRule())
    assert not auditor._evidence_spans_lifecycles(_ToolsRule())
    assert not auditor._evidence_spans_lifecycles(_FullDataRule())
    auditor.audit_data.catalog_versions.clear()
    assert not auditor._evidence_spans_lifecycles(_ToolsAndCapabilitiesRule())


def test_applicability_follows_the_catalog_revision():
    """A rule judging a recovered catalog applies the revision it was served on."""
    auditor = MCPAuditor()
    auditor.audit_data.protocol_version = "2025-11-25"
    auditor.audit_data.catalog_versions["tools"] = "2026-07-28"

    assert auditor._applicability_version(_ToolsRule()) == "2026-07-28"
    assert auditor._applicability_version(_FullDataRule()) == "2025-11-25"
    auditor.audit_data.catalog_versions.clear()
    assert auditor._applicability_version(_ToolsRule()) == "2025-11-25"
