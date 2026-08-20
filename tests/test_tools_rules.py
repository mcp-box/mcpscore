"""Comprehensive tests for tools rules.

This module tests all tool-related audit rules including:
- ToolsBaseRule
- ToolsAtLeastOneRule
- ToolsNamePresentRule
- ToolsNamesUniqueRule
- ToolsNamesValidFormatRule
- ToolsTitlePresentRule
- ToolsDescriptionPresentRule
- ToolsInputSchemaValidRule
- ToolsOutputSchemaValidRule

And the is_valid_schema() helper function.
"""

from typing import Any

from mcp_types import Tool, ToolAnnotations, ToolExecution
import pytest

from mcpscore.rules import AuditData, RuleSeverity
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE
from mcpscore.rules.registry import create_all_rules
from mcpscore.rules.tools import (
    ToolsAnnotationsPresentRule,
    ToolsAtLeastOneRule,
    ToolsBaseRule,
    ToolsDescriptionPresentRule,
    ToolsExecutionConsistentRule,
    ToolsInputPropertiesDocumentedRule,
    ToolsInputSchemaValidRule,
    ToolsMcpHeadersPrimitiveTypesRule,
    ToolsMcpHeadersStaticallyReachableRule,
    ToolsMcpHeadersUniqueRule,
    ToolsMcpHeadersValidNamesRule,
    ToolsNamePresentRule,
    ToolsNamesUniqueRule,
    ToolsNamesValidFormatRule,
    ToolsOutputSchemaRootObjectRule,
    ToolsOutputSchemaValidRule,
    ToolsTitlePresentRule,
    is_valid_output_schema,
    is_valid_schema,
)

# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def valid_schema() -> dict[str, Any]:
    """Return a valid JSON schema for tool input/output."""
    return {
        "type": "object",
        "title": "Valid Schema",
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"},
            "active": {"type": "boolean"},
        },
        "required": ["name"],
    }


@pytest.fixture
def valid_tool() -> Tool:
    """Return a fully valid tool with all required fields."""
    return Tool(
        name="test_tool",
        title="Test Tool",
        description="A test tool for validation",
        input_schema={
            "type": "object",
            "title": "Input Schema",
            "properties": {
                "param1": {"type": "string"},
            },
            "required": ["param1"],
        },
        output_schema={
            "type": "object",
            "title": "Output Schema",
            "properties": {
                "result": {"type": "string"},
            },
            "required": ["result"],
        },
    )


@pytest.fixture
def tool_with_empty_name() -> Tool:
    """Tool with empty name."""
    return Tool(
        name="",
        title="Empty Name Tool",
        description="Tool with empty name",
        input_schema={
            "type": "object",
            "title": "Input",
            "properties": {},
            "required": [],
        },
    )


@pytest.fixture
def tool_with_invalid_name() -> Tool:
    """Tool with name containing invalid characters."""
    return Tool(
        name="invalid@name#with$special%chars",
        title="Invalid Name Tool",
        description="Tool with invalid name format",
        input_schema={
            "type": "object",
            "title": "Input",
            "properties": {},
            "required": [],
        },
    )


@pytest.fixture
def tool_with_long_name() -> Tool:
    """Tool with name exceeding 128 characters."""
    return Tool(
        name="a" * 129,  # 129 characters
        title="Long Name Tool",
        description="Tool with too long name",
        input_schema={
            "type": "object",
            "title": "Input",
            "properties": {},
            "required": [],
        },
    )


@pytest.fixture
def tool_with_empty_title() -> Tool:
    """Tool with empty title."""
    return Tool(
        name="valid_name",
        title="",
        description="Tool with empty title",
        input_schema={
            "type": "object",
            "title": "Input",
            "properties": {},
            "required": [],
        },
    )


@pytest.fixture
def tool_with_empty_description() -> Tool:
    """Tool with empty description."""
    return Tool(
        name="valid_name",
        title="Valid Title",
        description="",
        input_schema={
            "type": "object",
            "title": "Input",
            "properties": {},
            "required": [],
        },
    )


@pytest.fixture
def tool_with_invalid_input_schema() -> Tool:
    """Tool with invalid input schema."""
    return Tool(
        name="valid_name",
        title="Valid Title",
        description="Valid Description",
        input_schema={
            "type": "string",  # Wrong type - should be "object"
            "title": "Invalid",
            "properties": {},
            "required": [],
        },
    )


@pytest.fixture
def tool_with_invalid_output_schema() -> Tool:
    """Tool with invalid output schema."""
    return Tool(
        name="valid_name",
        title="Valid Title",
        description="Valid Description",
        input_schema={
            "type": "object",
            "title": "Valid Input",
            "properties": {},
            "required": [],
        },
        output_schema={
            # An array root is VALID for output schemas since the 2026-08 split
            # (the version question is tools_output_schema_root_object's job) —
            # a malformed properties mapping is what invalidity means here.
            "type": "object",
            "properties": "not-a-mapping",
            "title": "Invalid Output",
        },
    )


# ============================================================================
# is_valid_schema() Tests
# ============================================================================


class TestIsValidSchema:
    """Test the is_valid_schema() helper function."""

    def test_valid_schema_with_all_fields(self, valid_schema: dict[str, Any]) -> None:
        """Valid schema with all required fields returns True."""
        assert is_valid_schema(valid_schema) is True

    def test_none_schema(self) -> None:
        """None schema returns False."""
        assert is_valid_schema(None) is False

    def test_missing_type_field(self) -> None:
        """Schema missing 'type' field returns False."""
        schema = {
            "title": "Test",
            "properties": {"name": {"type": "string"}},
            "required": [],
        }
        assert is_valid_schema(schema) is False

    def test_wrong_type_not_object(self) -> None:
        """Schema with type != 'object' returns False."""
        schema = {
            "type": "string",  # Wrong type
            "title": "Test",
            "properties": {"name": {"type": "string"}},
            "required": [],
        }
        assert is_valid_schema(schema) is False

    def test_missing_properties_field_is_valid(self) -> None:
        """Schema without 'properties' is valid (zero-argument tool)."""
        schema = {
            "type": "object",
            "title": "Test",
            "required": [],
        }
        assert is_valid_schema(schema) is True

    def test_missing_required_field_is_valid(self) -> None:
        """Schema without 'required' is valid (all parameters optional)."""
        schema = {
            "type": "object",
            "title": "Test",
            "properties": {"name": {"type": "string"}},
        }
        assert is_valid_schema(schema) is True

    def test_missing_title_field_is_valid(self) -> None:
        """Schema without 'title' is valid (title is not required by JSON Schema)."""
        schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": [],
        }
        assert is_valid_schema(schema) is True

    def test_top_level_combinators_are_valid(self) -> None:
        """Schemas using anyOf/oneOf/allOf/$ref at the top level are valid."""
        assert is_valid_schema({"anyOf": [{"type": "object"}, {"type": "null"}]}) is True
        assert is_valid_schema({"oneOf": [{"type": "object"}]}) is True
        assert is_valid_schema({"allOf": [{"type": "object"}]}) is True
        assert is_valid_schema({"$ref": "#/definitions/params"}) is True

    def test_properties_not_dict(self) -> None:
        """Schema with 'properties' not a dict returns False."""
        schema = {
            "type": "object",
            "title": "Test",
            "properties": "not a dict",
            "required": [],
        }
        assert is_valid_schema(schema) is False

    def test_required_not_list(self) -> None:
        """Schema with 'required' not a list returns False."""
        schema = {
            "type": "object",
            "title": "Test",
            "properties": {"name": {"type": "string"}},
            "required": "not a list",
        }
        assert is_valid_schema(schema) is False

    def test_empty_title_is_valid(self) -> None:
        """Schema with empty title is valid (title content is not enforced)."""
        schema = {
            "type": "object",
            "title": "",
            "properties": {"name": {"type": "string"}},
            "required": [],
        }
        assert is_valid_schema(schema) is True

    def test_non_string_title_is_invalid(self) -> None:
        """Schema with a non-string title returns False."""
        schema = {
            "type": "object",
            "title": 42,
            "properties": {"name": {"type": "string"}},
            "required": [],
        }
        assert is_valid_schema(schema) is False

    def test_required_property_not_in_properties(self) -> None:
        """Schema with required property not in properties returns False."""
        schema = {
            "type": "object",
            "title": "Test",
            "properties": {"name": {"type": "string"}},
            "required": ["age"],  # 'age' not in properties
        }
        assert is_valid_schema(schema) is False

    def test_property_without_type_is_valid(self) -> None:
        """Properties without 'type' are valid (enum/anyOf/$ref properties)."""
        schema = {
            "type": "object",
            "title": "Test",
            "properties": {
                "name": {"description": "Name field"},
                "mode": {"enum": ["fast", "slow"]},
            },
            "required": [],
        }
        assert is_valid_schema(schema) is True

    def test_property_with_invalid_type(self) -> None:
        """Schema with property having invalid type returns False."""
        schema = {
            "type": "object",
            "title": "Test",
            "properties": {
                "name": {"type": "invalid_type"},
            },
            "required": [],
        }
        assert is_valid_schema(schema) is False

    def test_property_not_dict(self) -> None:
        """Schema with property that's not a dict returns False."""
        schema = {
            "type": "object",
            "title": "Test",
            "properties": {
                "name": "not a dict",
            },
            "required": [],
        }
        assert is_valid_schema(schema) is False

    def test_valid_schema_with_all_json_types(self) -> None:
        """Valid schema with all valid JSON types returns True."""
        schema = {
            "type": "object",
            "title": "Test All Types",
            "properties": {
                "str_field": {"type": "string"},
                "num_field": {"type": "number"},
                "int_field": {"type": "integer"},
                "bool_field": {"type": "boolean"},
                "array_field": {"type": "array"},
                "obj_field": {"type": "object"},
                "null_field": {"type": "null"},
            },
            "required": ["str_field"],
        }
        assert is_valid_schema(schema) is True

    def test_empty_properties_dict(self) -> None:
        """Schema with empty properties dict is valid."""
        schema = {
            "type": "object",
            "title": "Test",
            "properties": {},
            "required": [],
        }
        assert is_valid_schema(schema) is True


# ============================================================================
# ToolsBaseRule Tests
# ============================================================================


class TestToolsBaseRule:
    """Test ToolsBaseRule behavior."""

    def test_base_rule_cannot_be_instantiated_directly(self) -> None:
        """ToolsBaseRule is abstract and cannot be instantiated."""
        # This should work - we can create an instance but _check_tools must be implemented
        with pytest.raises(TypeError):
            ToolsBaseRule()  # type: ignore[abstract]

    def test_declared_but_unavailable_tools_skip_every_catalog_rule(self, capabilities_full) -> None:
        """One failed tools/list must not fan out into failures across the tools rule pack."""
        data = AuditData(tools=None, capabilities=capabilities_full)
        rules = [rule for rule in create_all_rules() if isinstance(rule, ToolsBaseRule)]

        assert rules
        assert {rule.skip_reason(data) for rule in rules} == {SKIP_REASON_INSUFFICIENT_DATA}

    def test_absent_optional_tools_catalog_does_not_claim_collection_failed(self, capabilities_missing) -> None:
        """No declaration is distinct from a declared catalog that failed to load."""
        data = AuditData(tools=None, capabilities=capabilities_missing)
        assert ToolsAtLeastOneRule().skip_reason(data) is None

    def test_empty_complete_catalog_skips_every_quality_rule(self) -> None:
        data = AuditData(tools=[])
        quality_rules = [
            rule
            for rule in create_all_rules()
            if isinstance(rule, ToolsBaseRule) and not isinstance(rule, ToolsAtLeastOneRule)
        ]

        assert quality_rules
        assert {rule.skip_reason(data) for rule in quality_rules} == {SKIP_REASON_NOT_APPLICABLE}


# ============================================================================
# ToolsAtLeastOneRule Tests
# ============================================================================


class TestToolsAtLeastOneRule:
    """Test ToolsAtLeastOneRule."""

    def test_rule_properties(self) -> None:
        """Test rule metadata properties."""
        rule = ToolsAtLeastOneRule()
        assert rule.rule_id == "tools_at_least_one"
        assert rule.rule_order == 1
        assert rule.severity == RuleSeverity.CRITICAL

    def test_empty_incomplete_listing_skips(self) -> None:
        """An empty partial listing cannot prove the server has no tools."""
        rule = ToolsAtLeastOneRule()
        data = AuditData(tools=[], incomplete_listings=frozenset({"tools"}))
        assert rule.skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_nonempty_incomplete_listing_still_judges(self, valid_tool: Tool) -> None:
        """A non-empty partial listing proves presence — judge it, don't skip."""
        rule = ToolsAtLeastOneRule()
        data = AuditData(tools=[valid_tool], incomplete_listings=frozenset({"tools"}))
        assert rule.skip_reason(data) is None
        assert rule.check(data).passed is True

    def test_empty_complete_listing_still_fails(self) -> None:
        """A complete empty listing is a genuine failure, not insufficient data."""
        rule = ToolsAtLeastOneRule()
        data = AuditData(tools=[])
        assert rule.skip_reason(data) is None
        assert rule.check(data).passed is False
        assert "at least one tool" in rule.rule_name.lower()

    def test_with_one_tool(self, valid_tool: Tool) -> None:
        """Pass: Server provides at least one tool."""
        rule = ToolsAtLeastOneRule()
        result = rule.check(AuditData(tools=[valid_tool]))
        assert result.passed is True
        assert result.details is not None
        assert result.details["tools_count"] == 1

    def test_with_multiple_tools(self, valid_tool: Tool) -> None:
        """Pass: Server provides multiple tools."""
        rule = ToolsAtLeastOneRule()
        result = rule.check(AuditData(tools=[valid_tool, valid_tool]))
        assert result.passed is True
        assert result.details is not None
        assert result.details["tools_count"] == 2

    def test_with_empty_list(self) -> None:
        """Fail: Server provides no tools."""
        rule = ToolsAtLeastOneRule()
        result = rule.check(AuditData(tools=[]))
        assert result.passed is False
        assert result.details is not None
        assert result.details["tools_count"] == 0


# ============================================================================
# ToolsNamePresentRule Tests
# ============================================================================


class TestToolsNamePresentRule:
    """Test ToolsNamePresentRule."""

    def test_rule_properties(self) -> None:
        """Test rule metadata properties."""
        rule = ToolsNamePresentRule()
        assert rule.rule_id == "tools_name_present_in_all"
        assert rule.rule_order == 2
        assert rule.severity == RuleSeverity.CRITICAL
        assert "name" in rule.rule_name.lower()

    def test_with_all_valid_names(self, valid_tool: Tool) -> None:
        """Pass: All tools have names."""
        rule = ToolsNamePresentRule()
        result = rule.check(AuditData(tools=[valid_tool]))
        assert result.passed is True
        assert result.details is not None
        assert result.details["tools_with_empty_names"] == 0

    def test_with_empty_name(self, tool_with_empty_name: Tool) -> None:
        """Fail: Tool has empty name."""
        rule = ToolsNamePresentRule()
        result = rule.check(AuditData(tools=[tool_with_empty_name]))
        assert result.passed is False
        assert result.details is not None
        assert result.details["tools_with_empty_names"] == 1

    def test_with_mixed_names(self, valid_tool: Tool, tool_with_empty_name: Tool) -> None:
        """Fail: Some tools have empty names."""
        rule = ToolsNamePresentRule()
        result = rule.check(AuditData(tools=[valid_tool, tool_with_empty_name, tool_with_empty_name]))
        assert result.passed is False
        assert result.details is not None
        assert result.details["tools_with_empty_names"] == 2


# ============================================================================
# ToolsNamesUniqueRule Tests
# ============================================================================


class TestToolsNamesUniqueRule:
    """Test ToolsNamesUniqueRule."""

    def test_rule_properties(self) -> None:
        """Test rule metadata properties."""
        rule = ToolsNamesUniqueRule()
        assert rule.rule_id == "tools_names_unique"
        assert rule.rule_order == 3
        assert rule.severity == RuleSeverity.CRITICAL
        assert "unique" in rule.rule_name.lower()

    def test_incomplete_listing_skips(self, valid_tool: Tool) -> None:
        """A partial tool list cannot prove uniqueness — the duplicate may be on an unfetched page."""
        rule = ToolsNamesUniqueRule()
        data = AuditData(tools=[valid_tool], incomplete_listings=frozenset({"tools"}))
        assert rule.skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA
        assert rule.skip_reason(AuditData(tools=[valid_tool])) is None

    def test_with_unique_names(self, valid_tool: Tool) -> None:
        """Pass: All tool names are unique."""
        rule = ToolsNamesUniqueRule()
        tool1 = Tool(name="tool1", input_schema={"type": "object", "title": "T", "properties": {}, "required": []})
        tool2 = Tool(name="tool2", input_schema={"type": "object", "title": "T", "properties": {}, "required": []})
        result = rule.check(AuditData(tools=[tool1, tool2]))
        assert result.passed is True
        assert result.details is not None
        assert result.details["duplicate_names"] == []

    def test_with_duplicate_names(self, valid_tool: Tool) -> None:
        """Fail: Tools have duplicate names."""
        rule = ToolsNamesUniqueRule()
        tool1 = Tool(name="duplicate", input_schema={"type": "object", "title": "T", "properties": {}, "required": []})
        tool2 = Tool(name="duplicate", input_schema={"type": "object", "title": "T", "properties": {}, "required": []})
        result = rule.check(AuditData(tools=[tool1, tool2]))
        assert result.passed is False
        assert result.details is not None
        assert "duplicate" in result.details["duplicate_names"]
        assert result.details["name_counts"]["duplicate"] == 2

    def test_with_multiple_duplicates(self) -> None:
        """Fail: Multiple sets of duplicate names."""
        rule = ToolsNamesUniqueRule()
        tools = [
            Tool(name="dup1", input_schema={"type": "object", "title": "T", "properties": {}, "required": []}),
            Tool(name="dup1", input_schema={"type": "object", "title": "T", "properties": {}, "required": []}),
            Tool(name="dup2", input_schema={"type": "object", "title": "T", "properties": {}, "required": []}),
            Tool(name="dup2", input_schema={"type": "object", "title": "T", "properties": {}, "required": []}),
            Tool(name="unique", input_schema={"type": "object", "title": "T", "properties": {}, "required": []}),
        ]
        result = rule.check(AuditData(tools=tools))
        assert result.passed is False
        assert result.details is not None
        assert "dup1" in result.details["duplicate_names"]
        assert "dup2" in result.details["duplicate_names"]
        assert "unique" not in result.details["duplicate_names"]


# ============================================================================
# ToolsNamesValidFormatRule Tests
# ============================================================================


class TestToolsNamesValidFormatRule:
    """Test ToolsNamesValidFormatRule."""

    def test_rule_properties(self) -> None:
        """Test rule metadata properties."""
        rule = ToolsNamesValidFormatRule()
        assert rule.rule_id == "tools_names_valid_format"
        assert rule.rule_order == 4
        assert rule.severity == RuleSeverity.HIGH
        assert "format" in rule.rule_name.lower()

    def test_with_valid_format(self, valid_tool: Tool) -> None:
        """Pass: Tool names follow valid format."""
        rule = ToolsNamesValidFormatRule()
        result = rule.check(AuditData(tools=[valid_tool]))
        assert result.passed is True
        assert result.details is not None
        assert result.details["tools_with_invalid_names"] == 0

    def test_with_alphanumeric_name(self) -> None:
        """Pass: Tool name with alphanumeric characters."""
        rule = ToolsNamesValidFormatRule()
        tool = Tool(name="tool123", input_schema={"type": "object", "title": "T", "properties": {}, "required": []})
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is True

    def test_with_underscore_name(self) -> None:
        """Pass: Tool name with underscores."""
        rule = ToolsNamesValidFormatRule()
        tool = Tool(
            name="my_tool_name", input_schema={"type": "object", "title": "T", "properties": {}, "required": []}
        )
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is True

    def test_with_dash_name(self) -> None:
        """Pass: Tool name with dashes."""
        rule = ToolsNamesValidFormatRule()
        tool = Tool(
            name="my-tool-name", input_schema={"type": "object", "title": "T", "properties": {}, "required": []}
        )
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is True

    def test_with_dot_name(self) -> None:
        """Pass: Tool name with dots."""
        rule = ToolsNamesValidFormatRule()
        tool = Tool(
            name="my.tool.name", input_schema={"type": "object", "title": "T", "properties": {}, "required": []}
        )
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is True

    def test_with_max_length_name(self) -> None:
        """Pass: Tool name with 128 characters (max allowed)."""
        rule = ToolsNamesValidFormatRule()
        tool = Tool(name="a" * 128, input_schema={"type": "object", "title": "T", "properties": {}, "required": []})
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is True

    def test_with_invalid_special_chars(self, tool_with_invalid_name: Tool) -> None:
        """Fail: Tool name with invalid special characters."""
        rule = ToolsNamesValidFormatRule()
        result = rule.check(AuditData(tools=[tool_with_invalid_name]))
        assert result.passed is False
        assert result.details is not None
        assert result.details["tools_with_invalid_names"] == 1

    def test_with_too_long_name(self, tool_with_long_name: Tool) -> None:
        """Fail: Tool name exceeds 128 characters."""
        rule = ToolsNamesValidFormatRule()
        result = rule.check(AuditData(tools=[tool_with_long_name]))
        assert result.passed is False
        assert result.details is not None
        assert result.details["tools_with_invalid_names"] == 1

    def test_with_space_in_name(self) -> None:
        """Fail: Tool name contains spaces."""
        rule = ToolsNamesValidFormatRule()
        tool = Tool(
            name="my tool name", input_schema={"type": "object", "title": "T", "properties": {}, "required": []}
        )
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is False
        assert result.details is not None
        assert result.details["tools_with_invalid_names"] == 1


# ============================================================================
# ToolsTitlePresentRule Tests
# ============================================================================


class TestToolsTitlePresentRule:
    """Test ToolsTitlePresentRule."""

    def test_rule_properties(self) -> None:
        """Test rule metadata properties."""
        rule = ToolsTitlePresentRule()
        assert rule.rule_id == "tools_title_present_in_all"
        assert rule.rule_order == 5
        assert rule.severity == RuleSeverity.LOW
        assert "title" in rule.rule_name.lower()

    def test_scoped_to_revisions_that_have_title(self) -> None:
        """`title` first appeared in 2025-06-18 — earlier servers cannot declare one."""
        rule = ToolsTitlePresentRule()
        assert rule.min_spec_version == "2025-06-18"
        assert not rule.applies_to("2025-03-26")
        assert rule.applies_to("2025-06-18")

    def test_with_valid_title(self, valid_tool: Tool) -> None:
        """Pass: All tools have titles."""
        rule = ToolsTitlePresentRule()
        result = rule.check(AuditData(tools=[valid_tool]))
        assert result.passed is True
        assert result.details is not None
        assert result.details["tools_without_title"] == []

    @pytest.mark.parametrize("title", ["", "   ", None])
    def test_missing_blank_and_whitespace_titles_fail(self, valid_schema: dict[str, Any], title: str | None) -> None:
        """A missing title is just as absent as an empty one (PR #64 Bugbot finding)."""
        tool = Tool(name="untitled", title=title, input_schema=valid_schema)
        rule = ToolsTitlePresentRule()
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is False
        assert result.details is not None
        assert result.details["tools_without_title"] == ["untitled"]

    def test_with_mixed_titles(self, valid_tool: Tool, tool_with_empty_title: Tool) -> None:
        """Fail: Some tools have empty titles."""
        rule = ToolsTitlePresentRule()
        result = rule.check(AuditData(tools=[valid_tool, tool_with_empty_title]))
        assert result.passed is False
        assert result.details is not None
        assert len(result.details["tools_without_title"]) == 1


# ============================================================================
# ToolsDescriptionPresentRule Tests
# ============================================================================


class TestToolsDescriptionPresentRule:
    """Test ToolsDescriptionPresentRule."""

    def test_rule_properties(self) -> None:
        """Test rule metadata properties."""
        rule = ToolsDescriptionPresentRule()
        assert rule.rule_id == "tools_description_present_in_all"
        assert rule.rule_order == 6
        assert rule.severity == RuleSeverity.HIGH
        assert "description" in rule.rule_name.lower()

    def test_with_valid_description(self, valid_tool: Tool) -> None:
        """Pass: All tools have descriptions."""
        rule = ToolsDescriptionPresentRule()
        result = rule.check(AuditData(tools=[valid_tool]))
        assert result.passed is True
        assert result.details is not None
        assert result.details["tools_with_empty_descriptions"] == []

    def test_with_empty_description(self, tool_with_empty_description: Tool) -> None:
        """Fail: Tool has empty description."""
        rule = ToolsDescriptionPresentRule()
        result = rule.check(AuditData(tools=[tool_with_empty_description]))
        assert result.passed is False
        assert result.details is not None
        assert "valid_name" in result.details["tools_with_empty_descriptions"]

    def test_with_mixed_descriptions(self, valid_tool: Tool, tool_with_empty_description: Tool) -> None:
        """Fail: Some tools have empty descriptions."""
        rule = ToolsDescriptionPresentRule()
        result = rule.check(AuditData(tools=[valid_tool, tool_with_empty_description]))
        assert result.passed is False
        assert result.details is not None
        assert len(result.details["tools_with_empty_descriptions"]) == 1


class TestToolsAnnotationsPresentRule:
    """Test ToolsAnnotationsPresentRule."""

    def _tool(self, name: str, annotations: ToolAnnotations | None) -> Tool:
        return Tool(name=name, input_schema={"type": "object"}, annotations=annotations)

    def test_rule_properties(self) -> None:
        """Test rule metadata properties."""
        rule = ToolsAnnotationsPresentRule()
        assert rule.rule_id == "tools_annotations_present"
        assert rule.rule_order == 9
        assert rule.severity == RuleSeverity.MEDIUM
        assert "annotation" in rule.rule_name.lower()

    def test_with_behavior_annotation_passes(self) -> None:
        """Pass: tool declares a behavior hint."""
        tool = self._tool("reader", ToolAnnotations(readOnlyHint=True))
        result = ToolsAnnotationsPresentRule().check(AuditData(tools=[tool]))
        assert result.passed is True
        assert result.details is not None
        assert result.details["tools_without_annotations"] == []

    def test_without_annotations_fails(self) -> None:
        """Fail: tool has no annotations at all."""
        tool = self._tool("bare", None)
        result = ToolsAnnotationsPresentRule().check(AuditData(tools=[tool]))
        assert result.passed is False
        assert result.details is not None
        assert "bare" in result.details["tools_without_annotations"]

    def test_empty_annotations_object_fails(self) -> None:
        """Fail: annotations present but no behavior hint set."""
        tool = self._tool("empty", ToolAnnotations())
        result = ToolsAnnotationsPresentRule().check(AuditData(tools=[tool]))
        assert result.passed is False

    def test_title_only_annotation_fails(self) -> None:
        """Fail: only the display-only title hint is set (no behavior semantics)."""
        tool = self._tool("titled", ToolAnnotations(title="Pretty Name"))
        result = ToolsAnnotationsPresentRule().check(AuditData(tools=[tool]))
        assert result.passed is False
        assert result.details is not None
        assert "titled" in result.details["tools_without_annotations"]

    def test_mixed_tools_fail(self) -> None:
        """Fail: some tools annotated, some not."""
        annotated = self._tool("good", ToolAnnotations(destructiveHint=True))
        bare = self._tool("bad", None)
        result = ToolsAnnotationsPresentRule().check(AuditData(tools=[annotated, bare]))
        assert result.passed is False
        assert result.details is not None
        assert result.details["tools_without_annotations"] == ["bad"]

    def test_declared_tools_unavailable_skips(self, capabilities_full) -> None:
        """A failed tools/list provides no annotations to judge."""
        data = AuditData(tools=None, capabilities=capabilities_full)
        assert ToolsAnnotationsPresentRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA


# ============================================================================
# ToolsInputSchemaValidRule Tests
# ============================================================================


class TestToolsInputSchemaValidRule:
    """Test ToolsInputSchemaValidRule."""

    def test_rule_properties(self) -> None:
        """Test rule metadata properties."""
        rule = ToolsInputSchemaValidRule()
        assert rule.rule_id == "tools_input_schema_valid"
        assert rule.rule_order == 7
        assert rule.severity == RuleSeverity.HIGH
        assert "input schema" in rule.rule_name.lower()

    def test_with_valid_input_schema(self, valid_tool: Tool) -> None:
        """Pass: All tools have valid input schemas."""
        rule = ToolsInputSchemaValidRule()
        result = rule.check(AuditData(tools=[valid_tool]))
        assert result.passed is True
        assert result.details is not None
        assert result.details["tools_with_invalid_input_schema"] == []

    def test_with_invalid_input_schema(self, tool_with_invalid_input_schema: Tool) -> None:
        """Fail: Tool has invalid input schema."""
        rule = ToolsInputSchemaValidRule()
        result = rule.check(AuditData(tools=[tool_with_invalid_input_schema]))
        assert result.passed is False
        assert result.details is not None
        assert "valid_name" in result.details["tools_with_invalid_input_schema"]

    def test_with_invalid_input_schema_shape(self) -> None:
        """Fail: Tool has a structurally invalid input schema."""
        rule = ToolsInputSchemaValidRule()
        tool = Tool(
            name="test",
            input_schema={
                "type": "object",
                "properties": {"name": "not-a-mapping"},  # property def must be a dict
            },
        )
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is False

    def test_zero_argument_tool_passes(self) -> None:
        """Pass: a zero-argument tool with a minimal schema is valid."""
        rule = ToolsInputSchemaValidRule()
        tool = Tool(name="test", input_schema={"type": "object", "properties": {}})
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is True


class TestToolsInputPropertiesDocumentedRule:
    """Test documentation of statically reachable input properties."""

    def test_schema_without_properties_and_non_dict_property_pass(self) -> None:
        """Nothing to document: no properties key, and a boolean property schema is skipped."""
        tools = [
            Tool(name="bare", input_schema={"type": "object"}),
            Tool(name="boolean-schema", input_schema={"type": "object", "properties": {"x": True}}),
        ]
        result = ToolsInputPropertiesDocumentedRule().check(AuditData(tools=tools))
        assert result.passed is True
        assert result.details == {"undocumented_properties": []}

    def test_documented_nested_properties_pass(self) -> None:
        tool = Tool(
            name="search",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search terms"},
                    "options": {
                        "type": "object",
                        "description": "Search options",
                        "properties": {
                            "limit": {"type": "integer", "description": "Maximum results"},
                        },
                    },
                },
            },
        )
        result = ToolsInputPropertiesDocumentedRule().check(AuditData(tools=[tool]))
        assert result.passed is True
        assert result.details == {"undocumented_properties": []}

    def test_missing_and_blank_descriptions_report_exact_paths(self) -> None:
        tool = Tool(
            name="search",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "options": {
                        "type": "object",
                        "description": " ",
                        "properties": {"limit": {"type": "integer"}},
                    },
                },
            },
        )
        result = ToolsInputPropertiesDocumentedRule().check(AuditData(tools=[tool]))
        assert result.passed is False
        assert result.details == {
            "undocumented_properties": [
                {"tool": "search", "path": "$.properties.query"},
                {"tool": "search", "path": "$.properties.options"},
                {"tool": "search", "path": "$.properties.options.properties.limit"},
            ]
        }

    def test_unresolved_schema_branches_are_not_judged(self) -> None:
        tool = Tool(
            name="search",
            input_schema={
                "type": "object",
                "$defs": {"query": {"type": "string"}},
                "anyOf": [{"type": "object", "properties": {"query": {"type": "string"}}}],
            },
        )
        result = ToolsInputPropertiesDocumentedRule().check(AuditData(tools=[tool]))
        assert result.passed is True
        assert result.details == {"undocumented_properties": []}


# ============================================================================
# ToolsOutputSchemaValidRule Tests
# ============================================================================


class TestToolsOutputSchemaValidRule:
    """Test ToolsOutputSchemaValidRule."""

    def test_rule_properties(self) -> None:
        """Test rule metadata properties."""
        rule = ToolsOutputSchemaValidRule()
        assert rule.rule_id == "tools_output_schema_valid"
        assert rule.rule_order == 8
        assert rule.severity == RuleSeverity.HIGH
        assert "output schema" in rule.rule_name.lower()

    def test_with_valid_output_schema(self, valid_tool: Tool) -> None:
        """Pass: All tools have valid output schemas."""
        rule = ToolsOutputSchemaValidRule()
        result = rule.check(AuditData(tools=[valid_tool]))
        assert result.passed is True
        assert result.details is not None
        assert result.details["tools_with_invalid_output_schema"] == []

    def test_with_invalid_output_schema(self, tool_with_invalid_output_schema: Tool) -> None:
        """Fail: Tool has invalid output schema."""
        rule = ToolsOutputSchemaValidRule()
        result = rule.check(AuditData(tools=[tool_with_invalid_output_schema]))
        assert result.passed is False
        assert result.details is not None
        assert "valid_name" in result.details["tools_with_invalid_output_schema"]

    def test_with_none_output_schema_is_valid(self) -> None:
        """Pass: outputSchema is optional in the MCP spec; None is valid."""
        rule = ToolsOutputSchemaValidRule()
        tool = Tool(
            name="test",
            input_schema={
                "type": "object",
                "title": "Input",
                "properties": {},
                "required": [],
            },
            output_schema=None,
        )
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is True
        assert result.details is not None
        assert result.details["tools_with_invalid_output_schema"] == []

    def test_with_mixed_output_schemas(self, valid_tool: Tool, tool_with_invalid_output_schema: Tool) -> None:
        """Fail: Some tools have invalid output schemas."""
        rule = ToolsOutputSchemaValidRule()
        result = rule.check(AuditData(tools=[valid_tool, tool_with_invalid_output_schema]))
        assert result.passed is False
        assert result.details is not None
        assert len(result.details["tools_with_invalid_output_schema"]) == 1


def _header_tool(name: str, input_schema: dict[str, Any]) -> Tool:
    return Tool(name=name, input_schema=input_schema)


class TestToolsMcpHeadersValidNamesRule:
    def test_valid_and_absent_annotations_pass(self) -> None:
        tools = [
            _header_tool(
                "valid",
                {
                    "type": "object",
                    "properties": {
                        "region": {"type": "string", "x-mcp-header": "Region"},
                        "plain": {"type": "string"},
                    },
                },
            ),
            _header_tool("absent", {"type": "object", "properties": {}}),
        ]
        result = ToolsMcpHeadersValidNamesRule().check(AuditData(tools=tools))
        assert result.passed is True
        assert result.details == {"invalid_headers": []}

    @pytest.mark.parametrize("header", ["", "not a token", "line\nbreak", 42])
    def test_invalid_header_name_fails(self, header: object) -> None:
        tool = _header_tool(
            "bad",
            {
                "type": "object",
                "properties": {"value": {"type": "string", "x-mcp-header": header}},
            },
        )
        result = ToolsMcpHeadersValidNamesRule().check(AuditData(tools=[tool]))
        assert result.passed is False
        assert result.details is not None
        assert result.details["invalid_headers"][0]["path"] == "$.properties.value"


class TestToolsMcpHeadersUniqueRule:
    def test_names_are_case_insensitively_unique_within_a_tool(self) -> None:
        tool = _header_tool(
            "duplicate",
            {
                "type": "object",
                "properties": {
                    "first": {"type": "string", "x-mcp-header": "Region"},
                    "second": {"type": "string", "x-mcp-header": "region"},
                },
            },
        )
        result = ToolsMcpHeadersUniqueRule().check(AuditData(tools=[tool]))
        assert result.passed is False
        assert result.details is not None
        assert len(result.details["duplicate_headers"]) == 2

    def test_same_header_name_in_different_tools_passes(self) -> None:
        schema = {
            "type": "object",
            "properties": {"region": {"type": "string", "x-mcp-header": "Region"}},
        }
        result = ToolsMcpHeadersUniqueRule().check(
            AuditData(tools=[_header_tool("first", schema), _header_tool("second", schema)])
        )
        assert result.passed is True


class TestToolsMcpHeadersPrimitiveTypesRule:
    @pytest.mark.parametrize("parameter_type", ["string", "boolean", "integer"])
    def test_allowed_primitive_type_passes(self, parameter_type: str) -> None:
        tool = _header_tool(
            "valid",
            {
                "type": "object",
                "properties": {"value": {"type": parameter_type, "x-mcp-header": "Value"}},
            },
        )
        assert ToolsMcpHeadersPrimitiveTypesRule().check(AuditData(tools=[tool])).passed

    @pytest.mark.parametrize("parameter_type", ["number", "object", "array", None])
    def test_unsupported_or_missing_type_fails(self, parameter_type: str | None) -> None:
        property_schema: dict[str, Any] = {"x-mcp-header": "Value"}
        if parameter_type is not None:
            property_schema["type"] = parameter_type
        tool = _header_tool(
            "invalid",
            {"type": "object", "properties": {"value": property_schema}},
        )
        result = ToolsMcpHeadersPrimitiveTypesRule().check(AuditData(tools=[tool]))
        assert result.passed is False
        assert result.details is not None
        assert result.details["headers_with_invalid_types"][0]["type"] == parameter_type


class TestToolsMcpHeadersStaticallyReachableRule:
    def test_nested_properties_chain_passes(self) -> None:
        tool = _header_tool(
            "nested",
            {
                "type": "object",
                "properties": {
                    "location": {
                        "type": "object",
                        "properties": {
                            "region": {"type": "string", "x-mcp-header": "Region"},
                        },
                    }
                },
            },
        )
        assert ToolsMcpHeadersStaticallyReachableRule().check(AuditData(tools=[tool])).passed

    @pytest.mark.parametrize(
        ("schema", "expected_path"),
        [
            (
                {"type": "object", "x-mcp-header": "Root", "properties": {}},
                "$",
            ),
            (
                {
                    "type": "object",
                    "properties": {
                        "values": {
                            "type": "array",
                            "items": {"type": "string", "x-mcp-header": "Item"},
                        }
                    },
                },
                "$.properties.values.items",
            ),
            (
                {
                    "type": "object",
                    "properties": {
                        "value": {
                            "oneOf": [
                                {"type": "string", "x-mcp-header": "Variant"},
                            ]
                        }
                    },
                },
                "$.properties.value.oneOf[0]",
            ),
        ],
    )
    def test_annotations_outside_properties_chain_fail(
        self,
        schema: dict[str, Any],
        expected_path: str,
    ) -> None:
        result = ToolsMcpHeadersStaticallyReachableRule().check(AuditData(tools=[_header_tool("invalid", schema)]))
        assert result.passed is False
        assert result.details is not None
        assert result.details["unreachable_headers"][0]["path"] == expected_path


class TestToolsExecutionConsistentRule:
    def _tool(self, name: str, task_support: str | None) -> Tool:
        execution = ToolExecution(task_support=task_support) if task_support is not None else None
        return Tool(name=name, input_schema={"type": "object"}, execution=execution)

    def test_no_task_tools_passes(self):
        rule = ToolsExecutionConsistentRule()
        tools = [self._tool("plain", None), self._tool("forbidden", "forbidden")]
        result = rule.check(AuditData(tools=tools))
        assert result.passed is True

    def test_task_tools_with_tasks_capability_pass(self, capabilities_full):
        from dataclasses import replace

        rule = ToolsExecutionConsistentRule()
        tools = [self._tool("runner", "optional"), self._tool("batch", "required")]
        caps = replace(capabilities_full, tasks=object())
        result = rule.check(AuditData(tools=tools, capabilities=caps))
        assert result.passed is True

    def test_task_tools_without_tasks_capability_fail(self, capabilities_full):
        rule = ToolsExecutionConsistentRule()
        tools = [self._tool("runner", "optional")]
        result = rule.check(AuditData(tools=tools, capabilities=capabilities_full))
        assert result.passed is False
        assert result.details is not None
        assert result.details["task_tools"] == ["runner"]

    def test_no_tools_at_all_skips(self):
        """No tools means task-execution consistency has no subject to judge."""
        rule = ToolsExecutionConsistentRule()
        assert rule.skip_reason(AuditData()) == SKIP_REASON_NOT_APPLICABLE

    def test_skips_when_tools_unavailable_despite_capability(self, capabilities_full):
        """A failed tools/list (tools None, capability declared) skips rather than false-passing."""
        rule = ToolsExecutionConsistentRule()
        data = AuditData(tools=None, capabilities=capabilities_full)
        assert rule.skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA


class TestToolsOutputSchemaRootObjectRule:
    """Version-scoped root-type restriction (2025-06-18 .. 2025-11-25)."""

    def _tool(self, output_schema):
        return Tool(name="t", input_schema={"type": "object"}, output_schema=output_schema)

    def test_scoped_to_the_restriction_window(self):
        rule = ToolsOutputSchemaRootObjectRule()
        assert not rule.applies_to("2025-03-26")  # outputSchema does not exist yet
        assert rule.applies_to("2025-06-18")
        assert rule.applies_to("2025-11-25")
        assert not rule.applies_to("2026-07-28")  # any root became legal

    def test_object_rooted_and_absent_schemas_pass(self):
        tools = [
            self._tool({"type": "object", "properties": {}}),
            Tool(name="none", input_schema={"type": "object"}),  # no outputSchema at all
        ]
        result = ToolsOutputSchemaRootObjectRule().check(AuditData(tools=tools))
        assert result.passed
        assert result.details == {"tools_with_non_object_root": {}}

    def test_non_object_roots_fail_with_root_named(self):
        tools = [
            Tool(name="arr", input_schema={"type": "object"}, output_schema={"type": "array", "items": {}}),
            Tool(name="untyped", input_schema={"type": "object"}, output_schema={"properties": {}}),
            Tool(name="ok", input_schema={"type": "object"}, output_schema={"type": "object"}),
        ]
        result = ToolsOutputSchemaRootObjectRule().check(AuditData(tools=tools))
        assert not result.passed
        assert result.details["tools_with_non_object_root"] == {"arr": "array", "untyped": "<absent>"}
        assert "2" in result.message


class TestIsValidOutputSchema:
    """Root-agnostic output-schema validity.

    The root-vs-revision question belongs to
    ``tools_output_schema_root_object``, not to this helper.
    """

    def test_array_root_is_valid(self):
        assert is_valid_output_schema({"type": "array", "items": {"type": "object"}})

    def test_scalar_and_untyped_roots_are_valid(self):
        assert is_valid_output_schema({"type": "string"})
        assert is_valid_output_schema({"description": "anything"})  # no type at root

    def test_object_root_keeps_full_shape_checks(self):
        assert is_valid_output_schema({"type": "object", "properties": {}})
        assert not is_valid_output_schema({"type": "object", "properties": "nope"})
        assert not is_valid_output_schema({"type": "object", "required": ["x"], "properties": {}})

    def test_invalid_root_type_and_none_fail(self):
        assert not is_valid_output_schema({"type": "tuple"})
        assert not is_valid_output_schema(None)

    def test_output_rule_accepts_array_root(self):
        tool = Tool(name="t", input_schema={"type": "object"}, output_schema={"type": "array", "items": {}})
        result = ToolsOutputSchemaValidRule().check(AuditData(tools=[tool]))
        assert result.passed

    def test_input_rule_still_requires_object_root(self):
        tool = Tool(name="t", input_schema={"type": "array"}, output_schema=None)
        result = ToolsInputSchemaValidRule().check(AuditData(tools=[tool]))
        assert not result.passed
