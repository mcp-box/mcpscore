"""Exercise repair hints, diagnostic locations and collection error provenance."""

import json
from unittest.mock import AsyncMock, MagicMock

from mcp import ListToolsResult
from mcp.shared.exceptions import MCPError
from mcp_types import REQUEST_TIMEOUT, ServerCapabilities, Tool, ToolsCapability
from pydantic import ValidationError
import pytest

from mcpscore.mcp_client import MCPClient
from mcpscore.rules import AuditData, RuleResult, RuleSeverity
from mcpscore.rules.capabilities import CapabilityToolsPresentRule
from mcpscore.rules.tools import ToolsInputSchemaValidRule, ToolsOutputSchemaValidRule


def test_fix_serialization_and_unicode_boundary():
    hint = "🔧" * 255
    result = RuleResult("rule", RuleSeverity.HIGH, passed=False, message="failure", suggested_fix=hint)
    assert result.to_dict()["suggested_fix"] == hint
    assert "suggested_fix" not in RuleResult("rule", RuleSeverity.HIGH, passed=True, message="pass").to_dict()
    assert "suggested_fix" not in RuleResult("rule", RuleSeverity.HIGH, passed=False, message="old failure").to_dict()
    for bad in ("", " \n", "🔧" * 256):
        with pytest.raises(ValueError, match="suggested_fix"):
            RuleResult("rule", RuleSeverity.HIGH, passed=False, message="failure", suggested_fix=bad)
    with pytest.raises(ValueError, match="suggested_fix"):
        RuleResult("rule", RuleSeverity.HIGH, passed=True, message="pass", suggested_fix="Do something")


@pytest.mark.parametrize("output", [False, True])
def test_schema_locations_disambiguate_duplicate_tools_without_copying_values(output):
    schema = {"type": "object", "properties": {"a/b~c": {"type": "SECRET-invalid-type"}}}
    tools = [
        Tool(name="same", input_schema={"type": "object"}),
        Tool(
            name="same",
            input_schema=schema if not output else {"type": "object"},
            output_schema=schema if output else None,
        ),
    ]
    rule = ToolsOutputSchemaValidRule() if output else ToolsInputSchemaValidRule()
    result = rule.check(AuditData(tools=tools))
    assert not result.passed
    assert result.suggested_fix
    issue = result.details["issues"][0]
    assert issue["entity_index"] == 1
    assert issue["path"] == f"/{'outputSchema' if output else 'inputSchema'}/properties/a~1b~0c/type"
    assert issue["reason"] == "invalid_type"
    assert "string" in issue["expected"]
    assert "SECRET" not in json.dumps(result.to_dict())


def test_schema_evidence_is_bounded_and_preserves_pointer_characters():
    tools = [Tool(name="", input_schema={"type": "object", "properties": {"x\n": {"type": "bad"}}})] * 25
    result = ToolsInputSchemaValidRule().check(AuditData(tools=tools))
    assert len(result.details["issues"]) == 20
    assert result.details["issues_total"] == 25
    assert result.details["issues_omitted"] == 5
    assert "\n" in result.details["issues"][0]["path"]
    long = Tool(name="", input_schema={"type": "object", "properties": {"x" * 300: {"type": "bad"}}})
    assert ToolsInputSchemaValidRule().check(AuditData(tools=[long])).details["issues"][0]["path_omitted"]


@pytest.mark.parametrize(
    ("schema", "path", "reason"),
    [
        ({"type": "string"}, "/type", "object_root_expected"),
        ({"type": "object", "properties": []}, "/properties", "invalid_properties"),
        ({"type": "object", "required": "bad"}, "/required", "invalid_required"),
        ({"type": "object", "title": 1}, "/title", "invalid_title"),
        ({"type": "object", "required": ["missing"]}, "/required/0", "undeclared_required_property"),
        ({"type": "object", "properties": {"x": 1}}, "/properties/x", "invalid_property_schema"),
    ],
)
def test_existing_predicate_reasons(schema, path, reason):
    # Bypass SDK catalog validation to cover each existing engine predicate.
    tool = Tool.model_construct(name="test", input_schema=schema)
    result = ToolsInputSchemaValidRule().check(AuditData(tools=[tool]))
    assert not result.passed
    assert result.details["issues"][0]["path"] == "/inputSchema" + path
    assert result.details["issues"][0]["reason"] == reason


def test_optional_output_and_legacy_combinator_verdicts_stay_unchanged():
    tool = Tool(name="test", input_schema={"anyOf": "legacy-shortcut"})
    for rule in (ToolsInputSchemaValidRule(), ToolsOutputSchemaValidRule()):
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed
        assert "suggested_fix" not in result.to_dict()


@pytest.mark.asyncio
async def test_rejected_catalog_preserves_location_and_omits_raw_input(caplog):
    with pytest.raises(ValidationError) as caught:
        ListToolsResult.model_validate(
            {
                "tools": [
                    {
                        "name": ["SECRET"],
                        "inputSchema": {"type": "object"},
                        "outputSchema": {"type": "object", "required": "SECRET"},
                    }
                ]
            }
        )
    client = MCPClient()
    client.session = MagicMock()
    client.session.list_tools = AsyncMock(side_effect=caught.value)
    assert await client.list_tools() is None
    error = client.listing_errors["tools"]
    assert error["outcome"] == "invalid_response"
    assert error["issues"][0]["path"] == "/tools/0/name"
    result = CapabilityToolsPresentRule().check(
        AuditData(
            capabilities=ServerCapabilities(tools=ToolsCapability()),
            listings_attempted=frozenset({"tools"}),
            listing_errors=client.listing_errors,
        )
    )
    assert not result.passed
    assert "invalid catalog response" in result.message
    assert "did not answer" not in result.message
    assert result.suggested_fix
    assert "SECRET" not in json.dumps(result.to_dict()) + caplog.text
    assert "Traceback" not in caplog.text
    # Reused clients must clear stale diagnostics after a successful listing.
    client.session.list_tools = AsyncMock(return_value=ListToolsResult(tools=[]))
    assert await client.list_tools() == []
    assert "tools" not in client.listing_errors


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exc", "outcome"),
    [
        (TimeoutError(), "timeout"),
        (MCPError(REQUEST_TIMEOUT, "secret"), "timeout"),
        (MCPError(-32601, "secret"), "rpc_error"),
        (RuntimeError("secret"), "collection_error"),
    ],
)
async def test_collection_causes_remain_distinct(exc, outcome, caplog):
    client = MCPClient()
    client.session = MagicMock()
    client.session.list_tools = AsyncMock(side_effect=exc)
    assert await client.list_tools() is None
    assert client.listing_errors["tools"]["outcome"] == outcome
    result = CapabilityToolsPresentRule().check(
        AuditData(capabilities=ServerCapabilities(tools=ToolsCapability()), listing_errors=client.listing_errors)
    )
    assert not result.passed
    assert result.suggested_fix
    assert "secret" not in json.dumps(result.to_dict()) + caplog.text


@pytest.mark.parametrize("length", [255, 256])
@pytest.mark.asyncio
async def test_collection_pointer_boundary_omits_instead_of_truncating(length):
    error = ValidationError.from_exception_data(
        "Catalog", [{"type": "string_type", "loc": ("x" * (length - 1),), "input": ["SECRET"]}]
    )
    client = MCPClient()
    client.session = MagicMock()
    client.session.list_tools = AsyncMock(side_effect=error)
    await client.list_tools()
    issue = client.listing_errors["tools"]["issues"][0]
    if length == 255:
        assert issue["path"] == "/" + "x" * 254
    else:
        assert "path" not in issue
        assert issue["path_omitted"] is True


@pytest.mark.asyncio
async def test_auditor_captures_prints_and_detaches_collection_diagnostics(caplog):
    from mcpscore.mcp_auditor import MCPAuditor

    error = {
        "outcome": "invalid_response",
        "page_index": 0,
        "issues": [{"path": "/tools/0/name", "expected": "a string"}],
    }
    client = MCPClient()
    client.session = MagicMock()
    client.listing_errors["tools"] = error
    client.incomplete_listings.add("tools")
    client.list_tools = AsyncMock(return_value=None)
    auditor = MCPAuditor()
    auditor.mcp_client = client
    auditor.rules = [CapabilityToolsPresentRule()]
    auditor.audit_data.capabilities = ServerCapabilities(tools=ToolsCapability())
    await auditor._collect_tools()
    # Captured diagnostics must not change with a reused client's later state.
    error["issues"][0]["expected"] = "changed by client"
    with caplog.at_level("INFO", logger="mcpscore"):
        auditor._run_all_rules()
    assert "Fix:" in caplog.text
    assert "Response /tools/0/name · expected a string" in caplog.text
    report = auditor.get_audit_report()
    assert report["listing_errors"]["tools"]["outcome"] == "invalid_response"
    assert report["incomplete_listings"] == ["tools"]
    report["listing_errors"]["tools"]["issues"][0]["expected"] = "changed by caller"
    assert auditor.get_audit_report()["listing_errors"]["tools"]["issues"][0]["expected"] == "a string"


@pytest.mark.parametrize("mode", ["schema", "long_path", "pass", "no_hint"])
def test_auditor_logs_guidance_only_for_authored_failures(mode, caplog, monkeypatch):
    from mcpscore.mcp_auditor import MCPAuditor

    auditor = MCPAuditor()
    if mode == "no_hint":
        from mcpscore.rules.tools import ToolsNamePresentRule

        auditor.rules = [ToolsNamePresentRule()]
        auditor.audit_data.tools = [Tool(name="", input_schema={"type": "object"})]
        # Model an older or third-party result explicitly: built-in tool-name
        # failures now have authored guidance and must no longer stand in for it.
        monkeypatch.setattr(
            auditor.rules[0],
            "check",
            lambda _: RuleResult("Legacy finding", RuleSeverity.CRITICAL, passed=False, message="Missing name."),
        )
    else:
        auditor.rules = [ToolsInputSchemaValidRule()]
        schema = (
            {"type": "object"}
            if mode == "pass"
            else {"type": "object", "properties": {"x" * 300 if mode == "long_path" else "email": {"type": "bad"}}}
        )
        auditor.audit_data.tools = [Tool(name="test", input_schema=schema)]
    with caplog.at_level("INFO", logger="mcpscore"):
        auditor._run_all_rules()
    if mode in ("pass", "no_hint"):
        assert "Fix:" not in caplog.text
    else:
        assert "Fix:" in caplog.text
        assert "Tool index 0" in caplog.text
        assert ("path omitted" if mode == "long_path" else "/inputSchema/properties/email/type") in caplog.text


def test_modern_catalog_validation_is_sanitized_and_indexed(caplog):
    from mcpscore.mcp_auditor import MCPAuditor
    from mcpscore.probes import PROBE_STATELESS_LIST, ProbeOutcome, ProbeResult

    auditor = MCPAuditor()
    auditor.rules = [CapabilityToolsPresentRule()]
    auditor.audit_data.capabilities = ServerCapabilities(tools=ToolsCapability())
    auditor.audit_data.probes = {
        PROBE_STATELESS_LIST: ProbeResult(
            PROBE_STATELESS_LIST,
            ProbeOutcome.SUPPORTED,
            payload={
                "tools": [
                    {"name": "valid", "inputSchema": {"type": "object"}},
                    {"name": ["SECRET"], "inputSchema": {"type": "object"}},
                ]
            },
        )
    }
    with caplog.at_level("INFO", logger="mcpscore"):
        auditor._populate_from_probe_payloads()
        auditor._run_all_rules()
    assert auditor.audit_data.tools is None  # no partial catalog from an invalid page
    report = auditor.get_audit_report()
    assert report["listing_errors"]["tools"]["issues"][0]["path"] == "/tools/1/name"
    assert not report["results"][0]["passed"]
    assert "invalid catalog response" in report["results"][0]["message"]
    assert "SECRET" not in caplog.text + json.dumps(report)


def test_passing_declaration_keeps_partial_provenance_out_of_result():
    data = AuditData(
        capabilities=ServerCapabilities(tools=ToolsCapability()),
        tools=[],
        listing_errors={"tools": {"outcome": "timeout", "page_index": 1}},
    )
    result = CapabilityToolsPresentRule().check(data)
    assert result.passed
    assert "collection_error" not in result.details
    assert result.suggested_fix is None


def test_modern_discovery_validation_does_not_log_raw_values(caplog):
    from mcpscore.mcp_auditor import MCPAuditor
    from mcpscore.probes import PROBE_DISCOVER, ProbeOutcome, ProbeResult

    auditor = MCPAuditor()
    auditor.audit_data.probes = {
        PROBE_DISCOVER: ProbeResult(
            PROBE_DISCOVER,
            ProbeOutcome.SUPPORTED,
            payload={"serverInfo": {"name": ["SECRET"], "version": "1"}, "capabilities": {"tools": "SECRET"}},
        )
    }
    with caplog.at_level("INFO", logger="mcpscore"):
        auditor._populate_from_probe_payloads()
    assert auditor.audit_data.server_info is None
    assert auditor.audit_data.capabilities is None
    assert "invalid response" in caplog.text
    assert "SECRET" not in caplog.text


def test_shared_validation_evidence_limits_and_escapes_locations():
    from mcpscore.diagnostics import validation_diagnostics

    error = ValidationError.from_exception_data(
        "Catalog", [{"type": "string_type", "loc": ("a/b~c\n", i), "input": ["SECRET"]} for i in range(25)]
    )
    evidence = validation_diagnostics(error)
    assert evidence["issues_total"] == 25
    assert evidence["issues_omitted"] == 5
    assert len(evidence["issues"]) == 20
    assert evidence["issues"][0]["path"] == "/a~1b~0c\n/0"
    assert "SECRET" not in json.dumps(evidence)


@pytest.mark.parametrize("kind", ["schema", "catalog"])
@pytest.mark.parametrize("key", ["line\nbreak", 'quote"and\\backslash', "slash/~tilde"])
def test_report_paths_resolve_after_json_round_trip_and_cli_is_escaped(kind, key, caplog):
    from mcpscore.diagnostics import validation_diagnostics
    from mcpscore.mcp_auditor import MCPAuditor

    if kind == "schema":
        document = {"inputSchema": {"type": "object", "properties": {key: {"type": "bad"}}}}
        result = ToolsInputSchemaValidRule().check(
            AuditData(tools=[Tool(name="tool", input_schema=document["inputSchema"])])
        )
        path = json.loads(json.dumps(result.to_dict()))["details"]["issues"][0]["path"]
    else:
        document = {key: "bad"}
        error = ValidationError.from_exception_data(
            "Catalog", [{"type": "string_type", "loc": (key,), "input": ["SECRET"]}]
        )
        evidence = validation_diagnostics(error)
        result = CapabilityToolsPresentRule().check(
            AuditData(capabilities=ServerCapabilities(tools=ToolsCapability()), listing_errors={"tools": evidence})
        )
        path = json.loads(json.dumps(result.to_dict()))["details"]["collection_error"]["issues"][0]["path"]
    # Resolve the pointer against the original document, not a display-escaped copy.
    resolved = document
    for segment in path.split("/")[1:]:
        resolved = resolved[segment.replace("~1", "/").replace("~0", "~")]
    assert resolved == "bad"
    with caplog.at_level("INFO", logger="mcpscore"):
        MCPAuditor._log_guidance(result)
    assert json.dumps(path)[1:-1] in caplog.text
    if "\n" in key:
        assert key not in caplog.text


def test_root_validation_pointer_addresses_the_document():
    from mcpscore.diagnostics import validation_diagnostics

    error = ValidationError.from_exception_data("Catalog", [{"type": "dict_type", "loc": (), "input": ["SECRET"]}])
    assert validation_diagnostics(error)["issues"][0]["path"] == ""


def test_nested_result_and_readiness_details_are_detached_on_export():
    from mcpscore.mcp_auditor import MCPAuditor

    auditor = MCPAuditor()
    error = {"outcome": "invalid_response", "issues": [{"path": "/tools/0/name"}]}
    auditor.audit_data.listing_errors = {"tools": error}
    result = CapabilityToolsPresentRule().check(
        AuditData(capabilities=ServerCapabilities(tools=ToolsCapability()), listing_errors={"tools": error})
    )
    auditor.results = [result]
    auditor.readiness_results = [result]
    first = auditor.get_audit_report()
    first["results"][0]["details"]["collection_error"]["issues"][0]["path"] = "changed"
    first["readiness"]["results"][0]["details"]["collection_error"]["issues"].clear()
    second = auditor.get_audit_report()
    assert second["results"][0]["details"]["collection_error"]["issues"][0]["path"] == "/tools/0/name"
    assert second["readiness"]["results"][0]["details"]["collection_error"]["issues"][0]["path"] == "/tools/0/name"
    assert error["issues"] == [{"path": "/tools/0/name"}]


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", [{}, {"tools": "SECRET"}, {"tools": None}])
async def test_modern_malformed_catalog_shape_reaches_diagnostics_without_changing_outcome(payload):
    import httpx2

    from mcpscore.mcp_auditor import MCPAuditor
    from mcpscore.probes import PROBE_STATELESS_LIST, ProbeOutcome, _HttpTarget, _probe_stateless_list

    def handler(request):
        return httpx2.Response(200, json={"jsonrpc": "2.0", "id": 2, "result": payload})

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        probe = await _probe_stateless_list(_HttpTarget(client, "https://example.com/mcp"))
    assert probe.outcome is ProbeOutcome.UNSUPPORTED
    assert "SECRET" not in json.dumps(probe.to_dict())
    auditor = MCPAuditor()
    auditor.rules = [CapabilityToolsPresentRule()]
    auditor.audit_data.capabilities = ServerCapabilities(tools=ToolsCapability())
    auditor.audit_data.probes = {PROBE_STATELESS_LIST: probe}
    auditor._populate_from_probe_payloads()
    auditor._run_all_rules()
    report = auditor.get_audit_report()
    assert not report["results"][0]["passed"]
    issue = report["listing_errors"]["tools"]["issues"][0]
    assert issue["path"] == "/tools"
    assert issue["reason"] == ("missing" if "tools" not in payload else "list_type")
    assert "SECRET" not in json.dumps(report)
