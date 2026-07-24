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
        async def fake_run_all_probes(url: str, client=None, headers=None) -> dict[str, ProbeResult]:
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


# --- Partial audit (auth-gated servers) --------------------------------------

from mcpscore.probes import PROBE_AUTH_METADATA, PROBE_UNAUTHENTICATED  # noqa: E402


def _auth_gated_probe_results() -> dict[str, ProbeResult]:
    """Probe results for a well-behaved auth-gated server: 401 + RFC 9728 metadata."""
    results = not_applicable_results(reason="unset")
    results[PROBE_UNAUTHENTICATED] = ProbeResult(
        PROBE_UNAUTHENTICATED,
        ProbeOutcome.SUPPORTED,
        {"http_status": 401, "www_authenticate": 'Bearer resource_metadata="..."'},
    )
    results[PROBE_AUTH_METADATA] = ProbeResult(
        PROBE_AUTH_METADATA,
        ProbeOutcome.SUPPORTED,
        {
            "urls_tried": ["https://gated.example/.well-known/oauth-protected-resource/mcp"],
            "metadata_url": "https://gated.example/.well-known/oauth-protected-resource/mcp",
            "resource": "https://gated.example/mcp",
            "authorization_servers": ["https://auth.example"],
        },
    )
    return results


GATED_URL = "https://gated.example/mcp"


async def test_audit_partial_returns_false_for_non_url():
    assert await MCPAuditor().audit_partial("/path/to/server.py", reason="x") is False


async def test_audit_partial_scores_auth_and_skips_session(stub_probes, monkeypatch: pytest.MonkeyPatch):
    stub_probes(_auth_gated_probe_results())
    monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(_fake_tls))

    auditor = MCPAuditor()
    assert await auditor.audit_partial(GATED_URL, reason="requires auth (HTTP 401)") is True

    report = auditor.get_audit_report()
    assert report["partial"] is True
    assert report["partial_reason"] == "requires auth (HTTP 401)"

    scored = {r["rule_id"] for r in report["results"]}
    # Auth-posture and TLS rules run on probe/transport data.
    assert "auth_www_authenticate" in scored
    assert "auth_protected_resource_metadata" in scored
    assert "security_tls_enabled" in scored
    # Session-dependent rules skip as insufficient-data, never fail.
    skipped = {s["rule_id"]: s["reason"] for s in report["skipped_rules"]}
    assert skipped.get("tools_at_least_one") == "insufficient-data"
    assert skipped.get("server_name_present") == "insufficient-data"
    assert skipped.get("capability_tools_present") == "insufficient-data"
    # No transport was established, so the transport rule cannot claim a pass.
    assert "transport_streamable_http" not in scored
    assert skipped.get("transport_streamable_http") == "insufficient-data"
    # error_response is never collected, so its rules must not auto-pass here.
    assert "security_malformed_request_handling" not in scored
    assert "security_error_data_leak" not in scored
    assert skipped.get("security_malformed_request_handling") == "insufficient-data"
    assert skipped.get("security_error_data_leak") == "insufficient-data"
    # Transport left unverified in the audit data.
    assert auditor.audit_data.transport_type is None


async def test_audit_partial_threads_headers_to_probes(monkeypatch: pytest.MonkeyPatch):
    captured = {}

    async def fake_run_all_probes(url: str, client=None, headers=None) -> dict[str, ProbeResult]:
        captured["headers"] = headers
        return _auth_gated_probe_results()

    monkeypatch.setattr(mcp_auditor, "run_all_probes", fake_run_all_probes)
    monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(_fake_tls))

    auditor = MCPAuditor(headers={"Authorization": "Bearer tok"})
    await auditor.audit_partial(GATED_URL, reason="auth")
    assert captured["headers"] == {"Authorization": "Bearer tok"}
    assert auditor.get_audit_report()["authenticated"] is True


async def test_non_authorization_headers_do_not_mark_authenticated(stub_probes, monkeypatch: pytest.MonkeyPatch):
    """A tracing/custom header is not a credential — the report must not claim auth."""
    stub_probes(_auth_gated_probe_results())
    monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(_fake_tls))

    auditor = MCPAuditor(headers={"X-Trace-Id": "abc123"})
    await auditor.audit_partial(GATED_URL, reason="auth")
    assert auditor.get_audit_report()["authenticated"] is False


async def test_audit_partial_over_http_records_unverified_tls(stub_probes):
    """A plain-http target cannot verify TLS; the report must not claim it did."""
    stub_probes(_auth_gated_probe_results())

    auditor = MCPAuditor()
    assert await auditor.audit_partial("http://server.example/mcp", reason="auth") is True
    assert auditor.audit_data.tls_verified is False
    assert auditor.audit_data.tls_version is None


async def test_modern_server_readiness_counts_in_main_score(stub_probes, monkeypatch: pytest.MonkeyPatch):
    """A modern-lifecycle server's readiness points are promoted into the main score."""
    stub_probes(_modern_probe_results())
    monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(_fake_tls))

    auditor = MCPAuditor()
    assert await auditor.audit_modern_only("https://modern.example/mcp") is True

    report = auditor.get_audit_report()
    assert auditor.era is Era.MODERN
    assert report["readiness"]["counted_in_main"] is True
    # Ground truth recomputed from the per-result severities: the main score
    # must equal main-axis points PLUS readiness points — no more (double
    # counting) and no less (flag set but scoring not updated).
    main_max = sum(r.severity.value for r in auditor.results)
    main_score = sum(r.severity.value for r in auditor.results if r.passed)
    ready_max = sum(r.severity.value for r in auditor.readiness_results)
    ready_score = sum(r.severity.value for r in auditor.readiness_results if r.passed)
    assert ready_max > 0
    assert main_max > 0  # main-axis rules still scored on their own
    assert auditor.max_score == main_max + ready_max
    assert auditor.score == main_score + ready_score
    # The readiness axis itself is not inflated by the promotion.
    assert auditor.readiness_max == ready_max
    assert auditor.readiness_score == ready_score


async def test_partial_audit_never_promotes_readiness(stub_probes, monkeypatch: pytest.MonkeyPatch):
    """Even a modern-era server keeps readiness informative in a partial audit.

    A partial score is already not comparable to a full audit's; folding the
    readiness axis in would make it less interpretable.
    """
    stub_probes(_modern_probe_results())
    monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(_fake_tls))

    auditor = MCPAuditor()
    assert await auditor.audit_partial("https://gated-modern.example/mcp", reason="auth") is True

    report = auditor.get_audit_report()
    assert auditor.era is Era.MODERN
    assert report["partial"] is True
    assert report["readiness"]["counted_in_main"] is False
    # Main score equals exactly the main-axis points — readiness contributes
    # nothing to it in a partial audit, even for a modern-era server.
    assert auditor.max_score == sum(r.severity.value for r in auditor.results)
    assert auditor.score == sum(r.severity.value for r in auditor.results if r.passed)
    assert auditor.readiness_max == sum(r.severity.value for r in auditor.readiness_results)
    readiness_ids = {r["rule_id"] for r in report["readiness"]["results"]}
    main_ids = {r["rule_id"] for r in report["results"]}
    assert not (readiness_ids & main_ids)
