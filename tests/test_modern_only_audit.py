"""Tests for the modern-only (probe-based, sessionless) audit flow."""

import pytest

from mcpscore import mcp_auditor
from mcpscore.enums import MCPTransportType
from mcpscore.mcp_auditor import MCPAuditor
from mcpscore.probes import (
    PROBE_DISCOVER,
    PROBE_STATELESS_LIST,
    ProbeOutcome,
    ProbeResult,
    not_applicable_results,
)
from mcpscore.spec import Era

URL = "https://modern.example/mcp"

DISCOVER_PAYLOAD = {
    "resultType": "complete",
    "supportedVersions": ["2025-11-25", "2026-07-28"],
    "serverInfo": {"name": "modern-server", "version": "2.0", "title": "Modern Server"},
    "capabilities": {"tools": {"listChanged": True}},
    "instructions": "Use the echo tool.",
    "ttlMs": 60000,
    "cacheScope": "public",
}

TOOLS_PAYLOAD = {
    "resultType": "complete",
    "tools": [{"name": "echo", "description": "Echo a message", "inputSchema": {"type": "object"}}],
    "ttlMs": 60000,
    "cacheScope": "public",
}


def _modern_probe_results(discover_payload: dict | None = DISCOVER_PAYLOAD) -> dict[str, ProbeResult]:
    results = not_applicable_results(reason="unset")
    results[PROBE_DISCOVER] = ProbeResult(
        PROBE_DISCOVER,
        ProbeOutcome.SUPPORTED,
        {"supported_versions": (discover_payload or {}).get("supportedVersions")},
        payload=discover_payload,
    )
    results[PROBE_STATELESS_LIST] = ProbeResult(
        PROBE_STATELESS_LIST,
        ProbeOutcome.SUPPORTED,
        {"result_type": "complete", "ttl_ms": 60000, "cache_scope": "public"},
        payload=TOOLS_PAYLOAD,
    )
    return results


@pytest.fixture
def stub_probes(monkeypatch: pytest.MonkeyPatch):
    """Point the auditor's probe runner at canned results."""

    def install(results: dict[str, ProbeResult]) -> None:
        async def fake_run_all_probes(url: str, client=None) -> dict[str, ProbeResult]:
            return results

        monkeypatch.setattr(mcp_auditor, "run_all_probes", fake_run_all_probes)

    return install


async def test_returns_false_for_non_url_targets():
    assert await MCPAuditor().audit_modern_only("/path/to/server.py") is False


async def test_returns_false_without_modern_support(stub_probes):
    stub_probes(not_applicable_results(reason="no modern support"))
    assert await MCPAuditor().audit_modern_only(URL) is False


async def test_modern_only_audit_extracts_data_and_scores(stub_probes, monkeypatch: pytest.MonkeyPatch):
    stub_probes(_modern_probe_results())
    monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(_fake_tls))

    auditor = MCPAuditor()
    assert await auditor.audit_modern_only(URL) is True

    data = auditor.audit_data
    assert data.protocol_version == "2026-07-28"  # newest of supportedVersions
    assert data.server_info is not None
    assert data.server_info.name == "modern-server"
    assert data.capabilities is not None
    assert data.capabilities.tools is not None
    assert data.instructions == "Use the echo tool."
    assert data.tools is not None
    assert data.tools[0].name == "echo"
    assert data.transport_type is MCPTransportType.STREAMABLE_HTTP
    assert data.tls_verified is True
    assert data.tls_version == "TLSv1.3"

    assert auditor.era is Era.MODERN
    assert auditor.max_score > 0  # main rules ran on the extracted data
    assert auditor.readiness_max > 0

    report = auditor.get_audit_report()
    assert report["spec"]["era"] == "modern"
    assert report["spec"]["negotiated_version"] == "2026-07-28"


async def _fake_tls(url: str) -> str:
    return "TLSv1.3"


async def test_http_url_marks_tls_unverified(stub_probes):
    stub_probes(_modern_probe_results())

    auditor = MCPAuditor()
    assert await auditor.audit_modern_only("http://modern.example/mcp") is True
    assert auditor.audit_data.tls_verified is False
    assert auditor.audit_data.tls_version is None


async def test_unparseable_payloads_degrade_to_none(stub_probes, monkeypatch: pytest.MonkeyPatch):
    broken_payload = {
        "resultType": "complete",
        "supportedVersions": ["2026-07-28"],
        "serverInfo": {"title": "no name or version"},  # fails Implementation validation
        "capabilities": "not-a-dict",
        "ttlMs": 0,
        "cacheScope": "public",
    }
    stub_probes(_modern_probe_results(discover_payload=broken_payload))
    monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(_fake_tls))

    auditor = MCPAuditor()
    assert await auditor.audit_modern_only(URL) is True
    assert auditor.audit_data.server_info is None
    assert auditor.audit_data.capabilities is None
    assert auditor.audit_data.protocol_version == "2026-07-28"


async def test_missing_discover_payload_falls_back_to_target_version(stub_probes, monkeypatch: pytest.MonkeyPatch):
    results = _modern_probe_results()
    results[PROBE_DISCOVER] = ProbeResult(PROBE_DISCOVER, ProbeOutcome.UNSUPPORTED, {"http_status": 404})
    stub_probes(results)
    monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(_fake_tls))

    auditor = MCPAuditor()
    assert await auditor.audit_modern_only(URL) is True
    assert auditor.audit_data.protocol_version == "2026-07-28"
    assert auditor.audit_data.tools is not None  # still parsed from the stateless payload


async def test_invalid_supported_versions_falls_back_to_target(stub_probes, monkeypatch: pytest.MonkeyPatch):
    results = _modern_probe_results()
    results[PROBE_DISCOVER] = ProbeResult(
        PROBE_DISCOVER,
        ProbeOutcome.SUPPORTED,
        {"supported_versions": "not-a-list"},
        payload={"resultType": "complete", "serverInfo": {"name": "x", "version": "1"}},
    )
    stub_probes(results)
    monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(_fake_tls))

    auditor = MCPAuditor()
    assert await auditor.audit_modern_only(URL) is True
    assert auditor.audit_data.protocol_version == "2026-07-28"


async def test_non_list_tools_payload_is_ignored(stub_probes, monkeypatch: pytest.MonkeyPatch):
    results = _modern_probe_results()
    results[PROBE_STATELESS_LIST] = ProbeResult(
        PROBE_STATELESS_LIST,
        ProbeOutcome.SUPPORTED,
        {"result_type": "complete"},
        payload={"resultType": "complete", "tools": "not-a-list"},
    )
    stub_probes(results)
    monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(_fake_tls))

    auditor = MCPAuditor()
    assert await auditor.audit_modern_only(URL) is True
    assert auditor.audit_data.tools is None


async def test_invalid_tool_entries_degrade_to_none(stub_probes, monkeypatch: pytest.MonkeyPatch):
    results = _modern_probe_results()
    results[PROBE_STATELESS_LIST] = ProbeResult(
        PROBE_STATELESS_LIST,
        ProbeOutcome.SUPPORTED,
        {"result_type": "complete"},
        payload={"resultType": "complete", "tools": [{"description": "missing name and inputSchema"}]},
    )
    stub_probes(results)
    monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(_fake_tls))

    auditor = MCPAuditor()
    assert await auditor.audit_modern_only(URL) is True
    assert auditor.audit_data.tools is None


async def test_stateless_probe_without_payload_leaves_tools_none(stub_probes, monkeypatch: pytest.MonkeyPatch):
    results = _modern_probe_results()
    results[PROBE_STATELESS_LIST] = ProbeResult(
        PROBE_STATELESS_LIST, ProbeOutcome.SUPPORTED, {"result_type": "complete"}
    )
    stub_probes(results)
    monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(_fake_tls))

    auditor = MCPAuditor()
    assert await auditor.audit_modern_only(URL) is True
    assert auditor.audit_data.tools is None


class TestAuditorReuseDoesNotLeakState:
    """Regression tests for per-run state reset (PR #21 review)."""

    async def test_two_modern_only_runs_produce_identical_state(self, stub_probes, monkeypatch: pytest.MonkeyPatch):
        stub_probes(_modern_probe_results())
        monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(_fake_tls))

        auditor = MCPAuditor()
        assert await auditor.audit_modern_only(URL) is True
        first = (
            auditor.score,
            auditor.max_score,
            len(auditor.results),
            len(auditor.skipped_rules),
            auditor.readiness_score,
            auditor.readiness_max,
            len(auditor.readiness_results),
        )

        assert await auditor.audit_modern_only(URL) is True
        second = (
            auditor.score,
            auditor.max_score,
            len(auditor.results),
            len(auditor.skipped_rules),
            auditor.readiness_score,
            auditor.readiness_max,
            len(auditor.readiness_results),
        )

        assert first == second

    async def test_failed_modern_only_run_preserves_previous_results(
        self, stub_probes, monkeypatch: pytest.MonkeyPatch
    ):
        """A False return (no modern support) must not wipe a prior audit's state."""
        stub_probes(_modern_probe_results())
        monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(_fake_tls))

        auditor = MCPAuditor()
        assert await auditor.audit_modern_only(URL) is True
        results_before = len(auditor.results)

        stub_probes(not_applicable_results(reason="gone"))
        assert await auditor.audit_modern_only(URL) is False

        assert len(auditor.results) == results_before
