"""Exercise protocol repair guidance through actual rule checks and report serialization."""

from copy import deepcopy
import json
from typing import Any

from mcp_types import LoggingCapability, ServerCapabilities, Tool
import pytest

from mcpscore.enums import MCPTransportType
from mcpscore.probes import (
    PROBE_AUTH_METADATA,
    PROBE_DISCOVER,
    PROBE_MALFORMED_JSON,
    PROBE_PAGINATION_CACHE_SCOPE,
    PROBE_STATELESS_LIST,
    PROBE_UNAUTHENTICATED,
    ProbeOutcome,
    ProbeResult,
)
from mcpscore.report_evidence import report_evidence
from mcpscore.rules.base import AuditData
from mcpscore.rules.protocol_version import DeprecatedVersionRule
from mcpscore.rules.registry import create_all_rules

from .conftest import FakePromptsCaps, FakeResourcesCaps, FakeServerCapabilities, FakeToolsCaps
from .test_readiness_rules import modern_probes

MODULES = {"protocol_version", "transport", "security", "auth", "pagination", "catalog_stability", "readiness"}
RULES = {r.rule_id: r for r in create_all_rules() if type(r).__module__.rsplit(".", 1)[-1] in MODULES}
URL = "https://example.com/mcp"


def data_for(rule_id: str, *, failure: bool) -> AuditData:
    """Build server observations, keeping the rule's own verdict out of the fixture."""
    probes = modern_probes()
    probes[PROBE_UNAUTHENTICATED] = ProbeResult(
        PROBE_UNAUTHENTICATED,
        ProbeOutcome.SUPPORTED,
        {
            "http_status": 401,
            "www_authenticate": 'Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"',
        },
    )
    metadata: dict[str, Any] = {
        "resource": URL,
        "metadata_url": "https://example.com/.well-known/oauth-protected-resource",
        "authorization_servers": ["https://auth.example.com"],
        "scopes_supported": ["read"],
        "auth_server_issuer": "https://auth.example.com",
        "auth_server_metadata_present": True,
        "auth_server_has_endpoints": True,
        "auth_server_pkce_s256": True,
    }
    probes[PROBE_AUTH_METADATA] = ProbeResult(PROBE_AUTH_METADATA, ProbeOutcome.SUPPORTED, metadata)
    probes[PROBE_MALFORMED_JSON] = ProbeResult(
        PROBE_MALFORMED_JSON,
        ProbeOutcome.SUPPORTED,
        {"http_status": 400, "error_code": -32700, "response_id_absent_or_null": True},
        payload={"error_body": '{"error":{"code":-32700,"message":"Parse error"}}'},
    )
    data = AuditData(
        protocol_version="2026-07-28",
        url=URL,
        transport_type=MCPTransportType.STREAMABLE_HTTP,
        tls_verified=True,
        tls_version="TLSv1.3",
        probes=probes,
        capabilities=FakeServerCapabilities(
            tools=FakeToolsCaps(), resources=FakeResourcesCaps(), prompts=FakePromptsCaps()
        ),
        tools=[Tool(name="工具🔎", input_schema={"type": "object"})],
    )
    rule = RULES[rule_id]
    probe_id = (
        PROBE_PAGINATION_CACHE_SCOPE
        if rule_id == "pagination_cache_scope_consistent"
        else getattr(rule, "probe_id", None)
    )
    if probe_id and (failure or probe_id not in probes):
        probes[probe_id] = ProbeResult(
            probe_id,
            ProbeOutcome.UNSUPPORTED if failure else ProbeOutcome.SUPPORTED,
            {"http_status": 200, "error_code": -32603},
        )
    if rule_id == "protocol_version_supported_versions_include_negotiated":
        data.session_protocol_version = "2025-11-25" if failure else "2026-07-28"
    if not failure:
        return data
    if rule_id in {"protocol_version_allowed", "protocol_version_not_deprecated"}:
        data.protocol_version = "1900-01-01"
    elif rule_id == "protocol_version_latest":
        data.protocol_version = "2025-11-25"
        for pid in (PROBE_DISCOVER, PROBE_STATELESS_LIST):
            probes[pid] = ProbeResult(pid, ProbeOutcome.UNSUPPORTED, {"error_code": -32601})
    elif rule_id == "transport_streamable_http":
        data.transport_type = MCPTransportType.SSE
    elif rule_id == "security_tls_enabled":
        data.url = "http://example.com/mcp"
    elif rule_id == "security_malformed_request_handling":
        probes[PROBE_MALFORMED_JSON] = ProbeResult(
            PROBE_MALFORMED_JSON, ProbeOutcome.UNSUPPORTED, {"error_code": -32603}
        )
    elif rule_id == "security_error_data_leak":
        probes[PROBE_MALFORMED_JSON] = ProbeResult(
            PROBE_MALFORMED_JSON, ProbeOutcome.UNSUPPORTED, payload={"error_body": "Traceback (most recent call last)"}
        )
    elif rule_id.startswith("auth_"):
        _fail_auth(rule_id, probes, metadata)
    elif rule_id in {
        "readiness_2026_cache_metadata",
        "readiness_2026_result_type",
        "readiness_2026_response_content_type",
        "readiness_2026_supported_versions",
    }:
        probes[PROBE_DISCOVER] = ProbeResult(PROBE_DISCOVER, ProbeOutcome.SUPPORTED, {})
    elif rule_id == "readiness_2026_deprecated_features":
        data.capabilities = ServerCapabilities(logging=LoggingCapability())
    elif rule_id == "readiness_2026_tool_schema_dialect":
        data.tools = [Tool(name="工具🔎", input_schema={"type": "bad"})]
    return data


def _fail_auth(rule_id, probes, metadata):
    if rule_id == "auth_www_authenticate":
        probes[PROBE_UNAUTHENTICATED].details["www_authenticate"] = None
    elif rule_id == "auth_challenge_references_metadata":
        probes[PROBE_UNAUTHENTICATED].details["www_authenticate"] = "Bearer"
    else:
        field, value = {
            "auth_protected_resource_metadata": ("resource", "https://other.example/mcp"),
            "auth_authorization_servers_https": ("authorization_servers", []),
            "auth_metadata_https": ("metadata_url", "http://example.com/metadata"),
            "auth_scopes_advertised": ("scopes_supported", []),
            "auth_server_metadata_present": ("auth_server_has_endpoints", False),
            "auth_server_metadata_pkce": ("auth_server_pkce_s256", False),
        }[rule_id]
        metadata[field] = value


@pytest.mark.parametrize("rule_id", RULES)
@pytest.mark.parametrize("failure", [False, True])
def test_each_rule_guidance_contract(rule_id, failure, monkeypatch):
    # No real revision is currently deprecated: exercise the dormant branch explicitly.
    monkeypatch.setattr(DeprecatedVersionRule, "deprecated_versions", ["1900-01-01"])
    rule = RULES[rule_id]
    data = data_for(rule_id, failure=failure)
    assert rule.skip_reason(data) is None
    result = rule.check(data)
    assert result.passed is not failure
    assert result.severity == rule.severity
    assert result.message.endswith(".")
    wire = result.to_dict()
    if failure:
        assert 0 < len(wire["suggested_fix"]) <= 255
    else:
        assert "suggested_fix" not in wire


def test_inventory_covers_all_45_rules():
    assert len(RULES) == 45
    assert sum(r.group_name == "readiness" for r in RULES.values()) == 21


@pytest.mark.parametrize("outcome", [ProbeOutcome.ERROR, ProbeOutcome.NOT_APPLICABLE])
def test_unobserved_probe_does_not_become_a_failure(outcome):
    for rule_id, rule in RULES.items():
        if not getattr(rule, "probe_id", None):
            continue
        data = data_for(rule_id, failure=False)
        data.probes[rule.probe_id] = ProbeResult(rule.probe_id, outcome)
        assert rule.skip_reason(data) is not None, rule_id


def test_redaction_covers_rule_and_probe_reports_without_mutation():
    data = data_for("readiness_2026_no_session_id", failure=True)
    pid = RULES["readiness_2026_no_session_id"].probe_id
    data.probes[pid].details["response_session_id"] = "SessionSecret123"
    before = deepcopy(data.probes[pid].details)
    result = RULES["readiness_2026_no_session_id"].check(data)
    for wire in (result.to_dict(), data.probes[pid].to_dict()):
        assert "SessionSecret123" not in json.dumps(wire)
        assert "[redacted]" in json.dumps(wire)
    assert data.probes[pid].details == before
    assert "Stop adding" in result.suggested_fix


def test_safe_evidence_keeps_spec_anchors_and_removes_credentials():
    raw = {
        "spec": "https://example.com/spec#section",
        "nested": {"url": "https://user:Password123@example.com/mcp?token=Token123#Secret"},
        "urls_tried": ["https://example.com/mcp?secret=Token123"],
        "www_authenticate": 'Bearer error_description="Token123"',
        "response_session_id": None,
        "error": "Token123",
        "auth_server_metadata_error": "Token123",
        "bad_url": "https://[invalid",
        "count": 2,
    }
    result = report_evidence(raw)
    assert result["spec"] == raw["spec"]
    assert result["nested"]["url"] == "https://example.com/mcp"
    assert result["response_session_id"] is None
    assert result["bad_url"] == "[invalid URL omitted]"
    assert result["count"] == 2
    assert "Token123" not in json.dumps(result)
    assert "Password123" not in json.dumps(result)


@pytest.mark.parametrize("transport", [MCPTransportType.STDIO, MCPTransportType.STREAMABLE_HTTP])
def test_expected_error_preserves_transport_context(transport):
    rule = RULES["readiness_2026_unknown_method_error"]
    data = data_for(rule.rule_id, failure=True)
    data.transport_type = transport
    if transport is MCPTransportType.STDIO:
        data.probes[rule.probe_id].details.pop("http_status")
    result = rule.check(data)
    assert result.details["expected"]["error_code"] == -32601
    assert result.details["context"]["transport_type"] == transport
    assert ("HTTP" in result.suggested_fix) is (transport is MCPTransportType.STREAMABLE_HTTP)
    assert "Observed JSON-RPC error code: -32603" in result.message


@pytest.mark.parametrize(
    ("rule_id", "probe_key", "updates", "action"),
    [
        ("readiness_2026_no_session_id", None, {"response_session_id": None}, "Ignore"),
        ("readiness_2026_unsupported_version_error", None, {"data_well_formed": False}, "well-formed data"),
        ("readiness_2026_removed_methods", None, {"method_served": True}, "Stop dispatching"),
        ("readiness_2026_removed_methods", None, {"method_served": False}, "Correct"),
        ("security_malformed_request_handling", PROBE_MALFORMED_JSON, {"error_code": -32700}, "id: null"),
        (
            "auth_server_metadata_present",
            PROBE_AUTH_METADATA,
            {"auth_server_metadata_present": False},
            "discovery URLs",
        ),
        (
            "auth_server_metadata_present",
            PROBE_AUTH_METADATA,
            {"auth_server_metadata_present": False, "auth_server_metadata_error": "timeout"},
            "DNS, TLS",
        ),
        (
            "auth_authorization_servers_https",
            PROBE_AUTH_METADATA,
            {"authorization_servers": ["http://auth.example"]},
            "Replace malformed",
        ),
        (
            "auth_challenge_references_metadata",
            PROBE_UNAUTHENTICATED,
            {"www_authenticate": 'Bearer resource_metadata="https://other.example/metadata"'},
            "before relocating",
        ),
    ],
)
def test_distinct_failure_repairs(rule_id, probe_key, updates, action):
    rule = RULES[rule_id]
    data = data_for(rule_id, failure=True)
    pid = probe_key or rule.probe_id
    data.probes[pid].details.update(updates)
    result = rule.check(data)
    assert not result.passed
    assert action in result.suggested_fix
    assert len(result.suggested_fix) <= 255


@pytest.mark.parametrize(
    ("tls_verified", "tls_version", "action"),
    [
        (False, "TLSv1.3", "certificate chain"),
        (True, "TLSv1.1", "Enable TLS 1.2"),
    ],
)
def test_tls_failure_repairs(tls_verified, tls_version, action):
    rule = RULES["security_tls_enabled"]
    data = data_for(rule.rule_id, failure=False)
    data.tls_verified, data.tls_version = tls_verified, tls_version
    result = rule.check(data)
    assert not result.passed
    assert action in result.suggested_fix
    assert "disable verification" not in result.suggested_fix


@pytest.mark.parametrize(
    ("value", "diagnosis"), [(None, "absent"), ({}, "not an array"), ([], "empty"), ([12], "non-string")]
)
def test_supported_versions_diagnoses(value, diagnosis):
    rule = RULES["readiness_2026_supported_versions"]
    data = data_for(rule.rule_id, failure=False)
    data.probes[PROBE_DISCOVER].details["supported_versions"] = value
    result = rule.check(data)
    assert not result.passed
    assert diagnosis in result.message
    assert "non-empty array" in result.suggested_fix


def test_result_evidence_distinguishes_invalid_from_unobserved():
    rule = RULES["readiness_2026_cache_metadata"]
    data = data_for(rule.rule_id, failure=False)
    data.probes[PROBE_DISCOVER].details.update(ttl_ms=-1, cache_scope=None)
    result = rule.check(data)
    assert [(i["path"], i["reason"]) for i in result.details["issues"]] == [
        ("/ttlMs", "invalid_value"),
        ("/cacheScope", "missing_or_null"),
    ]
    assert 'response from probe_discover "/ttlMs"' in result.message
    assert "private" in result.suggested_fix


def test_schema_evidence_is_indexed_bounded_and_does_not_echo_values():
    rule = RULES["readiness_2026_tool_schema_dialect"]
    data = data_for(rule.rule_id, failure=False)
    data.tools = [Tool(name="same", input_schema={"type": "SensitiveValue123"}) for _ in range(25)]
    result = rule.check(data)
    assert not result.passed
    assert result.details["issues_total"] == 25
    assert result.details["issues_omitted"] == 5
    assert len(result.details["issues"]) == 20
    assert result.details["issues"][1]["entity_index"] == 1
    assert result.details["issues"][0]["path"].startswith("/inputSchema/type")
    assert "SensitiveValue123" not in json.dumps(result.to_dict())
    assert 'tool at index 0 "/inputSchema/type"' in result.message


def test_network_reference_is_a_resolution_review_not_a_claim_of_fetching():
    rule = RULES["readiness_2026_tool_schema_dialect"]
    data = data_for(rule.rule_id, failure=False)
    data.tools = [Tool(name="工具🔎", input_schema={"$ref": "https://example.com/Secret123"})]
    result = rule.check(data)
    assert not result.passed
    assert "Secret123" not in json.dumps(result.to_dict())
    assert result.details["issues"][0]["reason"] == "network_reference"
    assert "preloaded resolution" in result.suggested_fix


@pytest.mark.parametrize(("code", "diagnosis"), [(None, "not observed"), ("Secret123", "invalid type")])
def test_observed_error_does_not_echo_invalid_values(code, diagnosis):
    rule = RULES["readiness_2026_unknown_method_error"]
    data = data_for(rule.rule_id, failure=True)
    data.probes[rule.probe_id].details["error_code"] = code
    result = rule.check(data)
    assert f"Observed JSON-RPC error code: {diagnosis}" in result.message
    assert "Secret123" not in result.message


def test_challenge_value_is_not_echoed_on_a_pass():
    rule = RULES["auth_www_authenticate"]
    data = data_for(rule.rule_id, failure=False)
    data.probes[PROBE_UNAUTHENTICATED].details["www_authenticate"] = 'Bearer error_description="Secret123"'
    result = rule.check(data)
    assert result.passed
    assert "Secret123" not in json.dumps(result.to_dict())
    assert "Secret123" not in json.dumps(data.probes[PROBE_UNAUTHENTICATED].to_dict())


def test_schema_path_is_omitted_without_truncation_when_too_long():
    rule = RULES["readiness_2026_tool_schema_dialect"]
    data = data_for(rule.rule_id, failure=False)
    data.tools = [Tool(name="test", input_schema={"properties": {"x" * 260: {"type": "bad"}}})]
    result = rule.check(data)
    assert not result.passed
    issue = result.details["issues"][0]
    assert issue["entity_index"] == 0
    assert issue["path_omitted"] is True
    assert "path" not in issue
    assert "First affected field: tool at index 0." in result.message


def test_403_hint_does_not_tell_users_to_weaken_permission_checks():
    rule = RULES["auth_www_authenticate"]
    data = data_for(rule.rule_id, failure=True)
    data.probes[PROBE_UNAUTHENTICATED].details["http_status"] = 403
    result = rule.check(data)
    assert not result.passed
    assert "403" in result.message
    assert "do not change valid permission-denied responses" in result.suggested_fix
    assert len(result.suggested_fix) <= 255
