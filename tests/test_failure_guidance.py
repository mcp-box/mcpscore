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


def test_schema_evidence_is_bounded_and_control_characters_escaped():
    tools = [Tool(name="", input_schema={"type": "object", "properties": {"x\n": {"type": "bad"}}})] * 25
    result = ToolsInputSchemaValidRule().check(AuditData(tools=tools))
    assert len(result.details["issues"]) == 20
    assert result.details["issues_total"] == 25
    assert result.details["issues_omitted"] == 5
    assert "\n" not in result.details["issues"][0]["path"]
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
