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

from mcp.types import Tool
import pytest

from mcpaudit.rules import AuditData, RuleSeverity
from mcpaudit.rules.tools import (
    ToolsAtLeastOneRule,
    ToolsBaseRule,
    ToolsDescriptionPresentRule,
    ToolsInputSchemaValidRule,
    ToolsNamePresentRule,
    ToolsNamesUniqueRule,
    ToolsNamesValidFormatRule,
    ToolsOutputSchemaValidRule,
    ToolsTitlePresentRule,
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
        inputSchema={
            "type": "object",
            "title": "Input Schema",
            "properties": {
                "param1": {"type": "string"},
            },
            "required": ["param1"],
        },
        outputSchema={
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
        inputSchema={
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
        inputSchema={
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
        inputSchema={
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
        inputSchema={
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
        inputSchema={
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
        inputSchema={
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
        inputSchema={
            "type": "object",
            "title": "Valid Input",
            "properties": {},
            "required": [],
        },
        outputSchema={
            "type": "array",  # Wrong type
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

    def test_missing_properties_field(self) -> None:
        """Schema missing 'properties' field returns False."""
        schema = {
            "type": "object",
            "title": "Test",
            "required": [],
        }
        assert is_valid_schema(schema) is False

    def test_missing_required_field(self) -> None:
        """Schema missing 'required' field returns False."""
        schema = {
            "type": "object",
            "title": "Test",
            "properties": {"name": {"type": "string"}},
        }
        assert is_valid_schema(schema) is False

    def test_missing_title_field(self) -> None:
        """Schema missing 'title' field returns False."""
        schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": [],
        }
        assert is_valid_schema(schema) is False

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

    def test_empty_title(self) -> None:
        """Schema with empty title returns False."""
        schema = {
            "type": "object",
            "title": "",
            "properties": {"name": {"type": "string"}},
            "required": [],
        }
        assert is_valid_schema(schema) is False

    def test_whitespace_only_title(self) -> None:
        """Schema with whitespace-only title returns False."""
        schema = {
            "type": "object",
            "title": "   ",
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

    def test_property_missing_type_field(self) -> None:
        """Schema with property missing 'type' field returns False."""
        schema = {
            "type": "object",
            "title": "Test",
            "properties": {
                "name": {"description": "Name field"},  # Missing 'type'
            },
            "required": [],
        }
        assert is_valid_schema(schema) is False

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

    def test_check_with_none_tools(self, valid_tool: Tool) -> None:
        """Check method with None tools returns failed result."""
        # Use a concrete implementation to test base behavior
        rule = ToolsAtLeastOneRule()
        result = rule.check(AuditData(tools=None))
        assert result.passed is False
        assert "not available" in result.message
        assert result.details["tools"] is None


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
        assert "at least one tool" in rule.rule_name.lower()

    def test_with_one_tool(self, valid_tool: Tool) -> None:
        """Pass: Server provides at least one tool."""
        rule = ToolsAtLeastOneRule()
        result = rule.check(AuditData(tools=[valid_tool]))
        assert result.passed is True
        assert result.details["tools_count"] == 1

    def test_with_multiple_tools(self, valid_tool: Tool) -> None:
        """Pass: Server provides multiple tools."""
        rule = ToolsAtLeastOneRule()
        result = rule.check(AuditData(tools=[valid_tool, valid_tool]))
        assert result.passed is True
        assert result.details["tools_count"] == 2

    def test_with_empty_list(self) -> None:
        """Fail: Server provides no tools."""
        rule = ToolsAtLeastOneRule()
        result = rule.check(AuditData(tools=[]))
        assert result.passed is False
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
        assert result.details["tools_with_empty_names"] == 0

    def test_with_empty_name(self, tool_with_empty_name: Tool) -> None:
        """Fail: Tool has empty name."""
        rule = ToolsNamePresentRule()
        result = rule.check(AuditData(tools=[tool_with_empty_name]))
        assert result.passed is False
        assert result.details["tools_with_empty_names"] == 1

    def test_with_mixed_names(self, valid_tool: Tool, tool_with_empty_name: Tool) -> None:
        """Fail: Some tools have empty names."""
        rule = ToolsNamePresentRule()
        result = rule.check(AuditData(tools=[valid_tool, tool_with_empty_name, tool_with_empty_name]))
        assert result.passed is False
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

    def test_with_unique_names(self, valid_tool: Tool) -> None:
        """Pass: All tool names are unique."""
        rule = ToolsNamesUniqueRule()
        tool1 = Tool(name="tool1", inputSchema={"type": "object", "title": "T", "properties": {}, "required": []})
        tool2 = Tool(name="tool2", inputSchema={"type": "object", "title": "T", "properties": {}, "required": []})
        result = rule.check(AuditData(tools=[tool1, tool2]))
        assert result.passed is True
        assert result.details["duplicate_names"] == []

    def test_with_duplicate_names(self, valid_tool: Tool) -> None:
        """Fail: Tools have duplicate names."""
        rule = ToolsNamesUniqueRule()
        tool1 = Tool(name="duplicate", inputSchema={"type": "object", "title": "T", "properties": {}, "required": []})
        tool2 = Tool(name="duplicate", inputSchema={"type": "object", "title": "T", "properties": {}, "required": []})
        result = rule.check(AuditData(tools=[tool1, tool2]))
        assert result.passed is False
        assert "duplicate" in result.details["duplicate_names"]
        assert result.details["name_counts"]["duplicate"] == 2

    def test_with_multiple_duplicates(self) -> None:
        """Fail: Multiple sets of duplicate names."""
        rule = ToolsNamesUniqueRule()
        tools = [
            Tool(name="dup1", inputSchema={"type": "object", "title": "T", "properties": {}, "required": []}),
            Tool(name="dup1", inputSchema={"type": "object", "title": "T", "properties": {}, "required": []}),
            Tool(name="dup2", inputSchema={"type": "object", "title": "T", "properties": {}, "required": []}),
            Tool(name="dup2", inputSchema={"type": "object", "title": "T", "properties": {}, "required": []}),
            Tool(name="unique", inputSchema={"type": "object", "title": "T", "properties": {}, "required": []}),
        ]
        result = rule.check(AuditData(tools=tools))
        assert result.passed is False
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
        assert result.details["tools_with_invalid_names"] == 0

    def test_with_alphanumeric_name(self) -> None:
        """Pass: Tool name with alphanumeric characters."""
        rule = ToolsNamesValidFormatRule()
        tool = Tool(name="tool123", inputSchema={"type": "object", "title": "T", "properties": {}, "required": []})
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is True

    def test_with_underscore_name(self) -> None:
        """Pass: Tool name with underscores."""
        rule = ToolsNamesValidFormatRule()
        tool = Tool(name="my_tool_name", inputSchema={"type": "object", "title": "T", "properties": {}, "required": []})
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is True

    def test_with_dash_name(self) -> None:
        """Pass: Tool name with dashes."""
        rule = ToolsNamesValidFormatRule()
        tool = Tool(name="my-tool-name", inputSchema={"type": "object", "title": "T", "properties": {}, "required": []})
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is True

    def test_with_dot_name(self) -> None:
        """Pass: Tool name with dots."""
        rule = ToolsNamesValidFormatRule()
        tool = Tool(name="my.tool.name", inputSchema={"type": "object", "title": "T", "properties": {}, "required": []})
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is True

    def test_with_max_length_name(self) -> None:
        """Pass: Tool name with 128 characters (max allowed)."""
        rule = ToolsNamesValidFormatRule()
        tool = Tool(name="a" * 128, inputSchema={"type": "object", "title": "T", "properties": {}, "required": []})
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is True

    def test_with_invalid_special_chars(self, tool_with_invalid_name: Tool) -> None:
        """Fail: Tool name with invalid special characters."""
        rule = ToolsNamesValidFormatRule()
        result = rule.check(AuditData(tools=[tool_with_invalid_name]))
        assert result.passed is False
        assert result.details["tools_with_invalid_names"] == 1

    def test_with_too_long_name(self, tool_with_long_name: Tool) -> None:
        """Fail: Tool name exceeds 128 characters."""
        rule = ToolsNamesValidFormatRule()
        result = rule.check(AuditData(tools=[tool_with_long_name]))
        assert result.passed is False
        assert result.details["tools_with_invalid_names"] == 1

    def test_with_space_in_name(self) -> None:
        """Fail: Tool name contains spaces."""
        rule = ToolsNamesValidFormatRule()
        tool = Tool(name="my tool name", inputSchema={"type": "object", "title": "T", "properties": {}, "required": []})
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is False
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
        assert rule.severity == RuleSeverity.HIGH
        assert "title" in rule.rule_name.lower()

    def test_with_valid_title(self, valid_tool: Tool) -> None:
        """Pass: All tools have titles."""
        rule = ToolsTitlePresentRule()
        result = rule.check(AuditData(tools=[valid_tool]))
        assert result.passed is True
        assert result.details["tools_with_empty_titles"] == []

    def test_with_empty_title(self, tool_with_empty_title: Tool) -> None:
        """Fail: Tool has empty title."""
        rule = ToolsTitlePresentRule()
        result = rule.check(AuditData(tools=[tool_with_empty_title]))
        assert result.passed is False
        assert "valid_name" in result.details["tools_with_empty_titles"]

    def test_with_mixed_titles(self, valid_tool: Tool, tool_with_empty_title: Tool) -> None:
        """Fail: Some tools have empty titles."""
        rule = ToolsTitlePresentRule()
        result = rule.check(AuditData(tools=[valid_tool, tool_with_empty_title]))
        assert result.passed is False
        assert len(result.details["tools_with_empty_titles"]) == 1


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
        assert result.details["tools_with_empty_descriptions"] == []

    def test_with_empty_description(self, tool_with_empty_description: Tool) -> None:
        """Fail: Tool has empty description."""
        rule = ToolsDescriptionPresentRule()
        result = rule.check(AuditData(tools=[tool_with_empty_description]))
        assert result.passed is False
        assert "valid_name" in result.details["tools_with_empty_descriptions"]

    def test_with_mixed_descriptions(self, valid_tool: Tool, tool_with_empty_description: Tool) -> None:
        """Fail: Some tools have empty descriptions."""
        rule = ToolsDescriptionPresentRule()
        result = rule.check(AuditData(tools=[valid_tool, tool_with_empty_description]))
        assert result.passed is False
        assert len(result.details["tools_with_empty_descriptions"]) == 1


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
        assert result.details["tools_with_invalid_input_schema"] == []

    def test_with_invalid_input_schema(self, tool_with_invalid_input_schema: Tool) -> None:
        """Fail: Tool has invalid input schema."""
        rule = ToolsInputSchemaValidRule()
        result = rule.check(AuditData(tools=[tool_with_invalid_input_schema]))
        assert result.passed is False
        assert "valid_name" in result.details["tools_with_invalid_input_schema"]

    def test_with_none_input_schema(self) -> None:
        """Fail: Tool has None input schema."""
        rule = ToolsInputSchemaValidRule()
        # Note: Tool requires inputSchema, so this test verifies behavior
        # when the schema exists but is invalid
        tool = Tool(
            name="test",
            inputSchema={
                "type": "object",
                "title": "",  # Empty title makes it invalid
                "properties": {},
                "required": [],
            },
        )
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is False


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
        assert result.details["tools_with_invalid_output_schema"] == []

    def test_with_invalid_output_schema(self, tool_with_invalid_output_schema: Tool) -> None:
        """Fail: Tool has invalid output schema."""
        rule = ToolsOutputSchemaValidRule()
        result = rule.check(AuditData(tools=[tool_with_invalid_output_schema]))
        assert result.passed is False
        assert "valid_name" in result.details["tools_with_invalid_output_schema"]

    def test_with_none_output_schema(self) -> None:
        """Fail: Tool has None output schema."""
        rule = ToolsOutputSchemaValidRule()
        tool = Tool(
            name="test",
            inputSchema={
                "type": "object",
                "title": "Input",
                "properties": {},
                "required": [],
            },
            outputSchema=None,
        )
        result = rule.check(AuditData(tools=[tool]))
        assert result.passed is False
        assert "test" in result.details["tools_with_invalid_output_schema"]

    def test_with_mixed_output_schemas(self, valid_tool: Tool, tool_with_invalid_output_schema: Tool) -> None:
        """Fail: Some tools have invalid output schemas."""
        rule = ToolsOutputSchemaValidRule()
        result = rule.check(AuditData(tools=[valid_tool, tool_with_invalid_output_schema]))
        assert result.passed is False
        assert len(result.details["tools_with_invalid_output_schema"]) == 1
