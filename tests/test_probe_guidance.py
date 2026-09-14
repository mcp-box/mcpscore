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


def test_safe_evidence_keeps_public_values_and_masks_credentials():
    raw = {
        "spec": "https://example.com/spec#section",
        "nested": {"url": "HTTPS://user:Password123@example.com/mcp?scope=read&token=Token123#section"},
        "urls_tried": ["https://example.com/mcp?secret=Token123"],
        "www_authenticate": 'Bearer resource_metadata="https://example.com/meta?tenant=acme&api_key=Token123"',
        "response_session_id": None,
        "error": "connection refused",
        "auth_server_metadata_error": "certificate verify failed",
        "bad_url": "https://[invalid",
        "count": 2,
    }
    result = report_evidence(raw)
    assert result["spec"] == raw["spec"]
    assert result["nested"]["url"] == "HTTPS://example.com/mcp?scope=read&token=[redacted]#section"
    assert result["response_session_id"] is None
    assert result["bad_url"] == raw["bad_url"]
    assert result["error"] == "connection refused"
    assert result["auth_server_metadata_error"] == "certificate verify failed"
    assert "tenant=acme" in result["www_authenticate"]
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
    assert "context" not in result.details
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
            "alternative discovery",
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
    assert "SensitiveValue123" not in json.dumps(result.details["issues"])
    assert "SensitiveValue123" in result.message
    assert "affect 25 tool(s)" in result.message
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
    if code is None:
        assert "JSON-RPC error code:" not in result.message
    else:
        assert f"Observed JSON-RPC error code: {diagnosis}" in result.message
    assert "Secret123" not in result.message


def test_public_challenge_is_retained_on_a_pass():
    rule = RULES["auth_www_authenticate"]
    data = data_for(rule.rule_id, failure=False)
    data.probes[PROBE_UNAUTHENTICATED].details["www_authenticate"] = 'Bearer error_description="Secret123"'
    result = rule.check(data)
    assert result.passed
    assert "Secret123" in json.dumps(result.to_dict())
    assert "Secret123" in json.dumps(data.probes[PROBE_UNAUTHENTICATED].to_dict())


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


@pytest.mark.parametrize("scheme", ["https", "HTTPS", "hTtPs", "HTTP"])
def test_embedded_url_credentials_are_masked_without_losing_error_reason(scheme):
    raw = (
        f"certificate verify failed for {scheme}://user:Secret123@example.com/mcp"
        "?tenant=A%20B&%61ccess_token=Token123&scope=read&scope=write#section"
    )
    masked = report_evidence({"exception": "SSLError", "reason": raw})
    assert "certificate verify failed" in masked["reason"]
    assert "tenant=A%20B" in masked["reason"]
    assert "scope=read&scope=write#section" in masked["reason"]
    assert "Secret123" not in masked["reason"]
    assert "Token123" not in masked["reason"]
    assert "%61ccess_token=[redacted]" in masked["reason"]


@pytest.mark.parametrize("rule_id", ["auth_protected_resource_metadata", "auth_server_metadata_present"])
def test_auth_failures_identify_the_public_resource_or_issuer(rule_id):
    result = RULES[rule_id].check(data_for(rule_id, failure=True))
    assert '"https://' in result.message
    assert ("other.example" if rule_id == "auth_protected_resource_metadata" else "auth.example.com") in result.message


def test_invalid_content_type_is_visible_with_unicode_and_escaped_controls():
    rule = RULES["readiness_2026_response_content_type"]
    data = data_for(rule.rule_id, failure=False)
    data.probes[PROBE_DISCOVER].details["content_type"] = 'text/工具🔎\n"bad"'
    result = rule.check(data)
    assert 'text/工具🔎\\n\\"bad\\"' in result.message
    assert "\n" not in result.message


def test_duplicate_tools_count_once_each_when_both_schemas_fail():
    rule = RULES["readiness_2026_tool_schema_dialect"]
    data = data_for(rule.rule_id, failure=False)
    data.tools = [Tool(name="same", input_schema={"type": "first-bad"}, output_schema={"type": "second-bad"})] * 2
    result = rule.check(data)
    assert "affect 2 tool(s)" in result.message
    assert result.details["issues_total"] == 4
    assert "first-bad" in result.message


@pytest.mark.parametrize("kind", ["page", "unexpected_response", None])
def test_cursor_diagnosis_requires_positive_page_evidence(kind):
    rule = RULES["pagination_tools_invalid_cursor"]
    data = data_for(rule.rule_id, failure=True)
    data.probes[rule.probe_id].details.clear()
    if kind:
        data.probes[rule.probe_id].details["response_kind"] = kind
    result = rule.check(data)
    assert ("returned a page" in result.message) is (kind == "page")
    assert "not observed" not in result.message
    assert "Observed" not in result.message


def test_stdio_never_describes_an_http_status_even_if_stale_evidence_contains_one():
    rule = RULES["readiness_2026_server_discover"]
    data = data_for(rule.rule_id, failure=True)
    data.transport_type = MCPTransportType.STDIO
    result = rule.check(data)
    assert "HTTP" not in result.message
    assert "context" not in result.details


def test_version_context_is_reported_once_and_sanitized():
    from mcpscore.mcp_auditor import MCPAuditor

    auditor = MCPAuditor()
    auditor.audit_data = data_for("protocol_version_allowed", failure=True)
    auditor.audit_data.protocol_version = "HTTPS://user:Secret123@example.com/?token=Token123"
    auditor.audit_data.session_protocol_version = auditor.audit_data.protocol_version
    result = RULES["protocol_version_allowed"].check(auditor.audit_data)
    auditor.results = [result]
    report = auditor.get_audit_report()
    assert report["spec"]["session_protocol_version"] == "HTTPS://example.com/?token=[redacted]"
    assert "Secret123" not in json.dumps(report)
    assert "Token123" not in json.dumps(report)
    assert "context" not in result.details


@pytest.mark.parametrize("scheme", ["postgres", "PostgreSQL", "ftp", "wss", "custom+v1"])
def test_resource_uri_credentials_are_masked(scheme):
    raw = f"{scheme}://user:Secret123@host/db?password=Token123&database=public#table"
    masked = report_evidence({"only_first": [raw]})
    assert masked["only_first"] == [f"{scheme}://host/db?password=[redacted]&database=public#table"]


def test_late_added_evidence_and_human_message_are_masked():
    from mcpscore.rules.base import RuleSeverity
    from mcpscore.rules.probe_diagnostics import diagnostic_result

    value = "postgres://user:Secret123@host/db?token=Token123"
    issues = [{"entity_kind": "response", "path": "/value", "reason": "invalid", "expected": value}]
    result = diagnostic_result(
        rule_name="test",
        severity=RuleSeverity.LOW,
        passed=False,
        message=f"❌ Unexpected endpoint {value}",
        details={},
        expected={"url": value},
        issues=issues,
        suggested_fix="Check the endpoint.",
    )
    wire = json.dumps(result.to_dict())
    assert "Secret123" not in wire
    assert "Token123" not in wire
    assert "[redacted]" in wire
    assert issues[0]["expected"] == value


@pytest.mark.parametrize(
    "rule_id",
    ["readiness_2026_server_discover", "readiness_2026_supported_versions", "readiness_2026_unsupported_version_error"],
)
def test_version_list_messages_scrub_credentials_and_bound_values(rule_id):
    rule = RULES[rule_id]
    data = data_for(rule_id, failure=False)
    key = "supported" if rule_id == "readiness_2026_unsupported_version_error" else "supported_versions"
    data.probes[rule.probe_id].details[key] = ["HTTPS://user:Secret123@host/path?token=Token123", "工具🔎" * 50]
    result = rule.check(data)
    assert result.passed
    assert "Secret123" not in json.dumps(result.to_dict())
    assert "Token123" not in json.dumps(result.to_dict())
    assert "[truncated]" in result.message
    assert len(result.message) < 250


def test_auth_repairs_match_the_independent_checks():
    challenge = RULES["auth_www_authenticate"].check(data_for("auth_www_authenticate", failure=True))
    assert "WWW-Authenticate" in challenge.suggested_fix
    assert "resource_metadata" not in challenge.suggested_fix
    metadata = RULES["auth_challenge_references_metadata"].check(
        data_for("auth_challenge_references_metadata", failure=True)
    )
    assert "Add a quoted resource_metadata URL" in metadata.suggested_fix
    assert "review applicability" not in metadata.suggested_fix
    pkce = RULES["auth_server_metadata_pkce"].check(data_for("auth_server_metadata_pkce", failure=True))
    assert "implement S256 before advertising" in pkce.suggested_fix
    assert "does not verify runtime enforcement" in pkce.suggested_fix


def test_duplicate_schema_names_retain_labels_and_every_affected_index():
    rule = RULES["readiness_2026_tool_schema_dialect"]
    data = data_for(rule.rule_id, failure=False)
    data.tools = [
        Tool(name="same", input_schema={"type": "PublisherSchemaValue123"}),
        Tool(name="valid", input_schema={"type": "object"}),
        Tool(name="same", input_schema={"$ref": "https://example.com/schema"}),
        Tool(name="same", input_schema={"type": "bad"}, output_schema={"type": "bad"}),
    ]
    result = rule.check(data)
    assert not result.passed
    assert "affect 3 tool(s)" in result.message
    assert "PublisherSchemaValue123" in result.message
    assert "PublisherSchemaValue123" not in json.dumps(result.details)
    assert result.details["offending_tools"] == {
        "same": ["invalid under JSON Schema 2020-12", "network $ref requires resolution review"],
    }
    assert result.details["offending_tool_indexes"] == {"same": [0, 2, 3]}
    assert [issue["entity_index"] for issue in result.details["issues"]] == [0, 2, 3, 3]


def test_network_ref_and_schema_error_keep_preview_out_of_summary():
    rule = RULES["readiness_2026_tool_schema_dialect"]
    data = data_for(rule.rule_id, failure=False)
    data.tools = [Tool(name="test", input_schema={"$ref": "https://example.com/schema", "type": "PublisherValue123"})]
    result = rule.check(data)
    assert "First finding: network $ref requires resolution review" in result.message
    assert "PublisherValue123" not in json.dumps(result.details)
    assert result.details["offending_tools"]["test"] == [
        "network $ref requires resolution review",
        "invalid under JSON Schema 2020-12",
    ]
    assert result.details["offending_tool_indexes"] == {"test": [0]}


def test_masked_dictionary_names_preserve_collisions_and_literal_aliases():
    first = "https://user:Password123@host/?token=Token123"
    second = "https://user:Password456@host/?token=Token456"
    masked = "https://host/?token=[redacted]"
    raw = {first: 1, second: 2, masked: 3, f"{masked} [masked name 2]": 4}
    original = deepcopy(raw)
    result = report_evidence(raw)
    assert len(result) == len(raw)
    assert sorted(result.values()) == [1, 2, 3, 4]
    assert result[masked] == 3
    assert result[f"{masked} [masked name 2]"] == 4
    assert result[f"{masked} [masked name 3]"] == 1
    assert result[f"{masked} [masked name 4]"] == 2
    assert result == report_evidence(dict(reversed(list(raw.items()))))
    assert result == report_evidence(result)
    assert raw == original
    assert "Password" not in json.dumps(result)
    assert "Token" not in json.dumps(result)


def test_schema_summary_masks_names_without_losing_tools():
    rule = RULES["readiness_2026_tool_schema_dialect"]
    data = data_for(rule.rule_id, failure=False)
    names = ["https://user:Password123@host/?token=Token123", "https://host/?token=Token456"]
    data.tools = [Tool(name=name, input_schema={"type": "bad"}) for name in names]
    result = rule.check(data)
    wire = json.dumps(result.to_dict())
    assert "Password123" not in wire
    assert "Token123" not in wire
    assert "Token456" not in wire
    assert len(result.details["offending_tools"]) == 2
    assert result.details["offending_tools"].keys() == result.details["offending_tool_indexes"].keys()
    assert sorted(result.details["offending_tool_indexes"].values()) == [[0], [1]]
    assert [tool.name for tool in data.tools] == names


@pytest.mark.parametrize("response_kind", ["page", "unexpected_response", "error"])
def test_cursor_repair_matches_observed_response(response_kind):
    rule = RULES["pagination_tools_invalid_cursor"]
    data = data_for(rule.rule_id, failure=True)
    data.probes[rule.probe_id].details["response_kind"] = response_kind
    result = rule.check(data)
    assert not result.passed
    assert "-32602" in result.suggested_fix
    assert "first page" not in result.suggested_fix
    assert ("returning a page" in result.suggested_fix) == (response_kind == "page")


def test_version_repairs_preserve_alternative_paths():
    latest = RULES["protocol_version_latest"].check(data_for("protocol_version_latest", failure=True))
    assert "or expose modern" in latest.suggested_fix
    assert "changing only the version string is insufficient" in latest.suggested_fix
    rule_id = "protocol_version_supported_versions_include_negotiated"
    discovery = RULES[rule_id].check(data_for(rule_id, failure=True))
    assert "or disable the legacy lifecycle if intentionally retired" in discovery.suggested_fix
    assert "older clients you still support" in discovery.suggested_fix


def test_missing_issuer_metadata_repair_is_actionable():
    rule = RULES["auth_server_metadata_present"]
    data = data_for(rule.rule_id, failure=True)
    data.probes[PROBE_AUTH_METADATA].details["auth_server_metadata_present"] = False
    result = rule.check(data)
    assert not result.passed
    assert "discovery URLs" in result.suggested_fix
    assert "RFC 8414 or OpenID Connect" in result.suggested_fix
    assert "applicability review" not in result.suggested_fix
