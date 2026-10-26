"""Comprehensive tests for tools rules.

This module tests all tool-related audit rules including:
- ToolsBaseRule
- ToolsNamePresentRule
- ToolsNamesUniqueRule
- ToolsNamesValidFormatRule
- ToolsTitlePresentRule
- ToolsDescriptionPresentRule
- ToolsDescriptionsUniqueRule
- ToolsInputSchemaValidRule
- ToolsOutputSchemaValidRule

And the is_valid_schema() helper function.
"""

import json
import tracemalloc
from typing import Any

from mcp_types import Tool, ToolAnnotations, ToolExecution
import pytest

from mcpscore.rules import AuditData, RuleSeverity
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE
from mcpscore.rules.registry import create_all_rules
from mcpscore.rules.tools import (
    ToolsAnnotationsPresentRule,
    ToolsBaseRule,
    ToolsDescriptionPresentRule,
    ToolsDescriptionsInformativeRule,
    ToolsDescriptionsUniqueRule,
    ToolsExecutionConsistentRule,
    ToolsInputDefaultsMatchTypeRule,
    ToolsInputPropertiesDocumentedRule,
    ToolsInputSchemaValidRule,
    ToolsMcpHeadersNotSensitiveRule,
    ToolsMcpHeadersPrimitiveTypesRule,
    ToolsMcpHeadersStaticallyReachableRule,
    ToolsMcpHeadersUniqueRule,
    ToolsMcpHeadersValidNamesRule,
    ToolsNamePresentRule,
    ToolsNamesUniqueRule,
    ToolsNamesValidFormatRule,
    ToolsOutputPropertiesDocumentedRule,
    ToolsOutputSchemaRootObjectRule,
    ToolsOutputSchemaValidRule,
    ToolsTitlePresentRule,
    is_valid_output_schema,
    is_valid_schema,
    normalized_description,
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

    def test_empty_complete_catalog_skips_every_quality_rule(self) -> None:
        data = AuditData(tools=[])
        quality_rules = [rule for rule in create_all_rules() if isinstance(rule, ToolsBaseRule)]

        assert quality_rules
        assert {rule.skip_reason(data) for rule in quality_rules} == {SKIP_REASON_NOT_APPLICABLE}


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

    def test_absent_description_fails(self) -> None:
        """Fail: a tool with NO description at all is the rule's core case.

        Regression: the old `== ""` predicate passed description=None — the
        most common real-world defect earned the HIGH points. Proven to fail
        against the old implementation.
        """
        rule = ToolsDescriptionPresentRule()
        tool = Tool(name="no_description", input_schema={"type": "object"})

        result = rule.check(AuditData(tools=[tool]))

        assert result.passed is False
        assert result.details is not None
        assert "no_description" in result.details["tools_with_empty_descriptions"]

    def test_whitespace_description_fails(self) -> None:
        """Fail: whitespace-only is missing, same predicate as the siblings."""
        rule = ToolsDescriptionPresentRule()
        tool = Tool(name="blank_description", input_schema={"type": "object"}, description="   ")

        result = rule.check(AuditData(tools=[tool]))

        assert result.passed is False


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
# ToolsDescriptionsUniqueRule Tests
# ============================================================================


def described(name: str, description: str | None) -> Tool:
    """Build a minimal tool with the given description."""
    return Tool(name=name, description=description, input_schema={"type": "object"})


class TestToolsDescriptionsUniqueRule:
    """Test ToolsDescriptionsUniqueRule."""

    def test_rule_properties(self) -> None:
        """The rule is a LOW tools rule citing the spec's interaction model."""
        rule = ToolsDescriptionsUniqueRule()
        assert rule.rule_id == "tools_descriptions_unique"
        assert rule.severity == RuleSeverity.LOW
        assert rule.basis is not None
        assert "User Interaction Model" in rule.basis

    def test_distinct_descriptions_pass(self) -> None:
        """Pass: every described tool has its own description."""
        tools = [described("get_user", "Get one user by ID."), described("list_users", "List users.")]
        result = ToolsDescriptionsUniqueRule().check(AuditData(tools=tools))
        assert result.passed is True
        assert result.details is not None
        assert result.details["duplicate_description_groups"] == []

    def test_two_tools_sharing_a_description_fail(self) -> None:
        """Fail: two tools carry the same description, and the text is not echoed."""
        tools = [
            described("appstore_apps", "Query the App Store."),
            described("appstore_apps_appId", "Query the App Store."),
            described("other", "Something else."),
        ]
        result = ToolsDescriptionsUniqueRule().check(AuditData(tools=tools))
        assert result.passed is False
        assert result.details is not None
        assert result.details["duplicate_description_groups"] == [["appstore_apps", "appstore_apps_appId"]]
        assert '"appstore_apps", "appstore_apps_appId"' in result.message
        assert "1 group)" in result.message
        assert "App Store" not in result.message
        assert "App Store" not in str(result.details)
        assert [issue["entity_index"] for issue in result.details["issues"]] == [0, 1]
        assert {issue["path"] for issue in result.details["issues"]} == {"/description"}

    def test_several_groups_are_summarized(self) -> None:
        """Fail: each group is named, a few tools and groups at a time."""
        tools = [described(f"tpl_{i}", "List predefined templates") for i in range(6)]
        for group in range(4):
            tools += [described(f"g{group}_a", f"Alias {group}"), described(f"g{group}_b", f"alias {group}")]
        result = ToolsDescriptionsUniqueRule().check(AuditData(tools=tools))
        assert result.passed is False
        assert result.details is not None
        assert len(result.details["duplicate_description_groups"]) == 5
        assert "(5 groups)" in result.message
        assert '"tpl_0", "tpl_1", "tpl_2" and 3 more' in result.message
        assert "tpl_3" not in result.message
        assert "2 more groups" in result.message
        assert "g3_a" not in result.message

    @pytest.mark.parametrize(
        "variant",
        ["Search the docs.", "search the docs", "  Search   the\tdocs  ", "SEARCH THE DOCS.", "Search the docs .\n"],
    )
    def test_case_whitespace_and_period_variants_match(self, variant: str) -> None:
        """Fail: descriptions that differ only by case, whitespace or a trailing period match."""
        tools = [described("a", "Search the docs"), described("b", variant)]
        assert ToolsDescriptionsUniqueRule().check(AuditData(tools=tools)).passed is False

    def test_only_one_trailing_period_is_dropped(self) -> None:
        """Pass: an ellipsis is not the same text as no period."""
        assert normalized_description("Wait..") == "wait."
        tools = [described("a", "Wait"), described("b", "Wait..")]
        assert ToolsDescriptionsUniqueRule().check(AuditData(tools=tools)).passed is True

    def test_blank_descriptions_are_ignored(self) -> None:
        """Pass: missing and blank descriptions are another rule's concern."""
        tools = [
            described("a", None),
            described("b", ""),
            described("c", " . "),
            described("d", "One"),
            described("e", "Two"),
        ]
        rule = ToolsDescriptionsUniqueRule()
        data = AuditData(tools=tools)
        assert rule.skip_reason(data) is None
        assert rule.check(data).passed is True

    def test_fewer_than_two_described_tools_is_not_applicable(self) -> None:
        """Skip: nothing to compare with one described tool."""
        rule = ToolsDescriptionsUniqueRule()
        assert rule.skip_reason(AuditData(tools=[described("a", "One"), described("b", "  ")])) == (
            SKIP_REASON_NOT_APPLICABLE
        )
        assert rule.skip_reason(AuditData(tools=[])) == SKIP_REASON_NOT_APPLICABLE

    def test_incomplete_listing_is_insufficient_data(self) -> None:
        """Skip: the duplicate may be on a page that was never fetched."""
        tools = [described("a", "One"), described("b", "Two")]
        data = AuditData(tools=tools, incomplete_listings=frozenset({"tools"}))
        assert ToolsDescriptionsUniqueRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA


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
        assert result.details["undocumented_properties"] == [
            {"tool": "search", "path": "$.properties.query"},
            {"tool": "search", "path": "$.properties.options"},
            {"tool": "search", "path": "$.properties.options.properties.limit"},
        ]

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


class TestToolsOutputPropertiesDocumentedRule:
    """Test documentation of statically reachable output properties."""

    rule = ToolsOutputPropertiesDocumentedRule()

    @staticmethod
    def _tool(output_schema: dict | None, name: str = "search") -> Tool:
        return Tool(
            name=name,
            input_schema={"type": "object", "properties": {"q": {"type": "string"}}},
            output_schema=output_schema,
        )

    def test_rule_properties(self) -> None:
        assert self.rule.rule_id == "tools_output_properties_documented"
        assert self.rule.severity is RuleSeverity.LOW
        assert self.rule.applies_to("2025-03-26") is False
        assert self.rule.applies_to("2025-06-18") is True

    def test_not_applicable_without_any_output_schema(self) -> None:
        data = AuditData(tools=[self._tool(None)])
        assert self.rule.skip_reason(data) == SKIP_REASON_NOT_APPLICABLE

    def test_applies_when_one_tool_declares_an_output_schema(self) -> None:
        data = AuditData(tools=[self._tool(None, "plain"), self._tool({"type": "object"})])
        assert self.rule.skip_reason(data) is None

    def test_documented_nested_properties_pass(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "total": {"type": "integer", "description": "Number of matches"},
                "meta": {
                    "type": "object",
                    "description": "Paging details",
                    "properties": {"page": {"type": "integer", "description": "Current page"}},
                },
            },
        }
        result = self.rule.check(AuditData(tools=[self._tool(schema)]))
        assert result.passed is True
        assert result.details == {"undocumented_properties": []}
        assert result.suggested_fix is None

    def test_undocumented_nested_properties_report_output_paths(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "total": {"type": "integer"},
                "meta": {"type": "object", "description": " ", "properties": {"page": {"type": "integer"}}},
            },
        }
        tools = [self._tool(None, "plain"), self._tool(schema)]
        result = self.rule.check(AuditData(tools=tools))
        assert result.passed is False
        assert result.severity is RuleSeverity.LOW
        assert "output properties: 3" in result.message
        assert result.details["undocumented_properties"] == [
            {"tool": "search", "path": "$.properties.total"},
            {"tool": "search", "path": "$.properties.meta"},
            {"tool": "search", "path": "$.properties.meta.properties.page"},
        ]
        assert [(issue["entity_index"], issue["path"]) for issue in result.details["issues"]] == [
            (1, "/outputSchema/properties/total/description"),
            (1, "/outputSchema/properties/meta/description"),
            (1, "/outputSchema/properties/meta/properties/page/description"),
        ]
        assert result.suggested_fix is not None
        assert "not a sample value" in result.suggested_fix

    def test_undocumented_inputs_do_not_count(self) -> None:
        tool = Tool(
            name="search",
            input_schema={"type": "object", "properties": {"q": {"type": "string"}}},
            output_schema={"type": "object", "properties": {"n": {"type": "integer", "description": "Count"}}},
        )
        assert self.rule.check(AuditData(tools=[tool])).passed is True


class TestToolsDescriptionsInformativeRule:
    """Test that tool descriptions say more than the tool's name."""

    rule = ToolsDescriptionsInformativeRule()

    @staticmethod
    def _tool(name: str, description: str | None, title: str | None = None) -> Tool:
        return Tool(name=name, title=title, description=description, input_schema={"type": "object"})

    def _flagged(self, *tools: Tool) -> list[dict[str, str]]:
        return self.rule.check(AuditData(tools=list(tools))).details["uninformative_descriptions"]

    def test_rule_properties(self) -> None:
        assert self.rule.rule_id == "tools_descriptions_informative"
        assert self.rule.severity is RuleSeverity.LOW
        assert self.rule.applies_to("2024-11-05") is True

    @pytest.mark.parametrize("description", [None, "", "   "])
    def test_not_applicable_without_any_description(self, description: str | None) -> None:
        data = AuditData(tools=[self._tool("search", description)])
        assert self.rule.skip_reason(data) == SKIP_REASON_NOT_APPLICABLE

    @pytest.mark.parametrize(
        ("name", "description", "title"),
        [
            ("get_user", "Get user.", None),
            ("getUser", "get user", None),
            ("get-user", "GET USER", None),
            ("users.get", "Users get", None),
            ("HTTPRequest", "HTTP request", None),
            ("search", "Search", None),
            ("s", "Search docs", "Search docs"),
            ("指南", "指南", None),
            ("getUser", "GETUSER", None),
            ("getUser", "getuser", None),
            ("get_user", "GetUser", None),
            ("_", "_", None),
            ("search", "🔍", "🔍"),
        ],
    )
    def test_descriptions_that_echo_the_name_fail(self, name: str, description: str, title: str | None) -> None:
        assert self._flagged(self._tool(name, description, title)) == [{"tool": name, "reason": "echoes_name"}]

    @pytest.mark.parametrize(
        "description",
        ["TODO", "tbd", "FIXME.", "Description here", "Tool description", "Lorem ipsum", "TODO: describe this"],
    )
    def test_placeholder_descriptions_fail(self, description: str) -> None:
        assert self._flagged(self._tool("lookup", description)) == [{"tool": "lookup", "reason": "placeholder"}]

    @pytest.mark.parametrize(
        ("name", "description"),
        [
            ("get_user", "Get a user by ID and return their profile."),
            ("todo_list", "Todo list manager"),
            ("search", "Search the docs"),
            ("fetch", "Fetch a URL and return its text"),
            ("_", "🔍"),
            ("describe", "Describe"[:0] + "Describe a dataset's columns"),
        ],
    )
    def test_informative_descriptions_pass(self, name: str, description: str) -> None:
        result = self.rule.check(AuditData(tools=[self._tool(name, description)]))
        assert result.passed is True
        assert result.details == {"uninformative_descriptions": []}
        assert result.suggested_fix is None

    def test_failure_reports_names_and_reasons_only(self) -> None:
        tools = [self._tool("fetch", "Fetch a URL"), self._tool("get_user", "Get user"), self._tool("x", "TODO")]
        result = self.rule.check(AuditData(tools=tools))
        assert result.passed is False
        assert result.severity is RuleSeverity.LOW
        assert "beyond the name: 2" in result.message
        assert result.details["uninformative_descriptions"] == [
            {"tool": "get_user", "reason": "echoes_name"},
            {"tool": "x", "reason": "placeholder"},
        ]
        assert [(issue["entity_index"], issue["path"]) for issue in result.details["issues"]] == [
            (1, "/description"),
            (2, "/description"),
        ]
        assert "Get user" not in json.dumps(result.details)
        assert result.suggested_fix is not None
        assert "when to use it" in result.suggested_fix

    def test_missing_descriptions_are_left_to_the_presence_rule(self) -> None:
        tools = (self._tool("a", None), self._tool("c", "  "), self._tool("b", "Does b things"))
        assert self._flagged(*tools) == []
        assert self.rule.skip_reason(AuditData(tools=list(tools))) is None

    def test_empty_catalog_is_not_applicable(self) -> None:
        assert self.rule.skip_reason(AuditData(tools=[])) == SKIP_REASON_NOT_APPLICABLE

    def test_long_descriptions_are_not_examined(self) -> None:
        name = "k" * 600
        assert self._flagged(self._tool(name[:128], " ".join(["k" * 128]) + " " * 600)) == []

    def test_details_are_bounded(self) -> None:
        tools = [self._tool(f"t{index}", "TODO") for index in range(25)]
        result = self.rule.check(AuditData(tools=tools))
        assert len(result.details["uninformative_descriptions"]) == 20
        assert result.details["issues_total"] == 25


class TestToolsInputDefaultsMatchTypeRule:
    """Test that input defaults match the type, enum or const declared beside them."""

    rule = ToolsInputDefaultsMatchTypeRule()

    @staticmethod
    def _tool(properties: dict[str, Any], name: str = "search", **extra: Any) -> Tool:
        return Tool(name=name, input_schema={"type": "object", "properties": properties, **extra})

    def _paths(self, *tools: Tool) -> list[str]:
        return [
            failure["path"] for failure in self.rule.check(AuditData(tools=list(tools))).details["mismatched_defaults"]
        ]

    def test_rule_properties(self) -> None:
        assert self.rule.rule_id == "tools_input_defaults_match_type"
        assert self.rule.severity is RuleSeverity.MEDIUM
        assert self.rule.applies_to("2024-11-05") is True

    def test_not_applicable_without_any_default(self) -> None:
        data = AuditData(tools=[self._tool({"q": {"type": "string"}})])
        assert self.rule.skip_reason(data) == SKIP_REASON_NOT_APPLICABLE

    def test_applies_when_a_nested_default_exists(self) -> None:
        nested = {"type": "array", "items": {"type": "object", "properties": {"n": {"default": 1}}}}
        data = AuditData(tools=[self._tool({"q": {"type": "string"}}), self._tool({"rows": nested})])
        assert self.rule.skip_reason(data) is None

    @pytest.mark.parametrize(
        "schema",
        [
            {"type": "integer", "default": 10},
            {"type": "integer", "default": 2.0},
            {"type": "number", "default": 3},
            {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": None},
            {"type": ["integer", "null"], "default": None},
            {"type": "string", "enum": ["asc", "desc"], "default": "asc"},
            {"enum": [1.0, "x"], "default": 1},
            {"const": {"a": [1, True]}, "default": {"a": [1.0, True]}},
            {"type": "string", "minLength": 5, "format": "date", "default": "x"},
            {"type": "custom", "default": 1},
        ],
        ids=[
            "typed",
            "integral-float",
            "integer-as-number",
            "nullable-anyof",
            "nullable-type-list",
            "enum",
            "enum-numeric-equality",
            "const-nested",
            "other-assertions-not-checked",
            "unknown-type-name",
        ],
    )
    def test_matching_defaults_pass(self, schema: dict[str, Any]) -> None:
        result = self.rule.check(AuditData(tools=[self._tool({"limit": schema})]))
        assert result.passed is True
        assert result.details == {"mismatched_defaults": []}
        assert result.suggested_fix is None

    def test_null_default_on_integer_fails_with_locations(self) -> None:
        tools = [
            self._tool({"q": {"type": "string"}}, "plain"),
            self._tool({"q": {"type": "string"}, "limit": {"type": "integer", "default": None, "title": "Limit"}}),
        ]
        result = self.rule.check(AuditData(tools=tools))
        assert result.passed is False
        assert result.severity is RuleSeverity.MEDIUM
        assert "contradict their declared type: 1" in result.message
        assert result.details["mismatched_defaults"] == [
            {
                "tool": "search",
                "path": "/properties/limit",
                "default_type": "null",
                "mismatch": "type",
                "declared_type": "integer",
            }
        ]
        assert [(issue["entity_index"], issue["path"]) for issue in result.details["issues"]] == [
            (1, "/inputSchema/properties/limit/default")
        ]
        assert result.suggested_fix is not None
        assert "T | None" in result.suggested_fix

    @pytest.mark.parametrize(
        ("schema", "mismatch"),
        [
            ({"type": "integer", "default": True}, "type"),
            ({"type": "integer", "default": 1.5}, "type"),
            ({"type": ["string", "null"], "default": 0}, "type"),
            ({"enum": [1, 2], "default": True}, "enum"),
            ({"enum": ["asc", "desc"], "default": "up"}, "enum"),
            ({"const": [1, 2], "default": [1]}, "const"),
            ({"const": {"a": 1}, "default": {"b": 1}}, "const"),
        ],
    )
    def test_mismatches_are_named(self, schema: dict[str, Any], mismatch: str) -> None:
        result = self.rule.check(AuditData(tools=[self._tool({"x": schema})]))
        assert [failure["mismatch"] for failure in result.details["mismatched_defaults"]] == [mismatch]

    def test_nested_and_combinator_defaults_are_checked(self) -> None:
        properties = {
            "rows": {
                "type": "array",
                "items": {"type": "object", "properties": {"n": {"type": "integer", "default": "x"}}},
            },
            "mode": {"anyOf": [{"type": "string", "default": 1}, {"type": "null"}]},
        }
        assert self._paths(self._tool(properties)) == [
            "/properties/rows/items/properties/n",
            "/properties/mode/anyOf/0",
        ]

    def test_refs_are_not_followed(self) -> None:
        tool = self._tool(
            {"order": {"$ref": "#/$defs/Order", "default": "up"}}, **{"$defs": {"Order": {"enum": ["asc"]}}}
        )
        assert self._paths(tool) == []

    def test_exponential_ref_graph_is_not_expanded(self) -> None:
        defs: dict[str, Any] = {"n0": {"type": "integer"}}
        for level in range(1, 41):
            defs[f"n{level}"] = {"allOf": [{"$ref": f"#/$defs/n{level - 1}"}, {"$ref": f"#/$defs/n{level - 1}"}]}
        tool = self._tool({"x": {"$ref": "#/$defs/n40", "default": 1}}, **{"$defs": defs})
        assert self.rule.check(AuditData(tools=[tool])).passed is True

    def test_schema_regexes_are_never_run(self) -> None:
        # Exponential under Python's re, and an overflowing quantifier: neither is compiled or matched.
        tool = self._tool(
            {
                "x": {"type": "string", "pattern": "^(a+)+$", "default": "a" * 64 + "!"},
                "y": {"type": "integer", "pattern": "a{4294967296}", "default": "ten"},
            },
            **{"$schema": "http://json-schema.org/draft-07/schema#"},
        )
        assert self._paths(tool) == ["/properties/y"]

    def test_property_named_pattern_does_not_hide_findings(self) -> None:
        tool = self._tool({"pattern": {"type": "string"}, "limit": {"type": "integer", "default": "ten"}})
        assert self._paths(tool) == ["/properties/limit"]

    def test_draft_07_tuple_items_and_dependencies_are_walked(self) -> None:
        tool = self._tool(
            {"pair": {"type": "array", "items": [{"type": "string", "default": 1}]}, "a": {"type": "string"}},
            dependencies={"a": {"properties": {"b": {"type": "integer", "default": "x"}}}},
            **{"$schema": "http://json-schema.org/draft-07/schema#"},
        )
        assert self._paths(tool) == ["/properties/pair/items/0", "/dependencies/a/properties/b"]

    def test_draft_07_prefix_items_are_data(self) -> None:
        tool = self._tool(
            {"pair": {"type": "array", "prefixItems": [{"type": "string", "default": 1}]}},
            **{"$schema": "http://json-schema.org/draft-07/schema#"},
        )
        assert self.rule.check(AuditData(tools=[tool])).passed is True

    def test_draft_07_ref_siblings_are_ignored(self) -> None:
        tool = self._tool(
            {"x": {"$ref": "#/definitions/X", "type": "integer", "default": "s"}},
            definitions={"X": {"type": "string"}},
            **{"$schema": "http://json-schema.org/draft-07/schema#"},
        )
        assert self.rule.skip_reason(AuditData(tools=[tool])) is None
        assert self._paths(tool) == []

    def test_draft_07_ref_siblings_are_not_walked(self) -> None:
        tool = self._tool(
            {"s": {"$ref": "#/definitions/S", "properties": {"n": {"type": "integer", "default": "bad"}}}},
            definitions={"S": {"type": "object"}},
            **{"$schema": "http://json-schema.org/draft-07/schema#"},
        )
        assert self._paths(tool) == []

    def test_2020_12_ref_siblings_are_walked(self) -> None:
        tool = self._tool(
            {"s": {"$ref": "#/$defs/S", "properties": {"n": {"type": "integer", "default": "bad"}}}},
            **{"$defs": {"S": {"type": "object"}}},
        )
        assert self._paths(tool) == ["/properties/s/properties/n"]

    def test_data_keywords_are_not_walked(self) -> None:
        tool = self._tool({"q": {"type": "object", "examples": [{"default": None, "type": "integer"}]}})
        assert self.rule.skip_reason(AuditData(tools=[tool])) == SKIP_REASON_NOT_APPLICABLE

    @pytest.mark.parametrize(
        "extra",
        [{"$schema": "https://example.com/custom-dialect"}, {"$schema": 5}, {"$defs": "not a map"}],
        ids=["unknown-dialect", "non-string-dialect", "malformed"],
    )
    def test_schemas_that_cannot_be_read_are_insufficient_data(self, extra: dict[str, Any]) -> None:
        tool = self._tool({"limit": {"type": "integer", "default": None}}, **extra)
        assert self.rule.skip_reason(AuditData(tools=[tool])) == SKIP_REASON_INSUFFICIENT_DATA
        assert self.rule.check(AuditData(tools=[tool])).passed is True

    def test_findings_from_readable_tools_survive_an_unreadable_one(self) -> None:
        unreadable = self._tool({"limit": {"type": "integer", "default": None}}, "custom", **{"$schema": 5})
        readable = self._tool({"limit": {"type": "integer", "default": None}})
        data = AuditData(tools=[unreadable, readable])
        assert self.rule.skip_reason(data) is None
        assert [f["tool"] for f in self.rule.check(data).details["mismatched_defaults"]] == ["search"]

    def test_too_deep_schema_with_defaults_is_insufficient_data(self) -> None:
        schema: dict[str, Any] = {"type": "string", "default": 1}
        for _ in range(100):
            schema = {"type": "object", "properties": {"n": schema}}
        tool = self._tool({"root": schema})
        assert self.rule.skip_reason(AuditData(tools=[tool])) == SKIP_REASON_INSUFFICIENT_DATA
        assert self.rule.check(AuditData(tools=[tool])).passed is True

    def test_boolean_subschemas_are_skipped(self) -> None:
        properties = {"any": True, "mode": {"anyOf": [False, {"type": "string", "default": 0}]}}
        assert self._paths(self._tool(properties)) == ["/properties/mode/anyOf/1"]

    def test_paths_over_the_limit_are_omitted(self) -> None:
        result = self.rule.check(AuditData(tools=[self._tool({"k" * 300: {"type": "integer", "default": None}})]))
        [failure] = result.details["mismatched_defaults"]
        assert failure["path_omitted"] is True
        assert "path" not in failure
        [issue] = result.details["issues"]
        assert issue["path_omitted"] is True
        assert "path" not in issue

    def test_oversized_ancestor_names_are_not_escaped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        escaped: list[int] = []

        def counting_pointer_token(value: str) -> str:
            escaped.append(len(value))
            return value

        monkeypatch.setattr("mcpscore.rules.tools.pointer_token", counting_pointer_token)
        children = {f"p{index}": {"type": "integer", "default": None} for index in range(200)}
        tool = self._tool({"k" * 100_000: {"type": "object", "properties": children}})
        result = self.rule.check(AuditData(tools=[tool]))
        assert result.details["issues_total"] == 200
        assert all(issue["path_omitted"] for issue in result.details["issues"])
        assert max(escaped, default=0) < 100_000

    def test_paths_that_outgrow_the_limit_when_escaped_are_omitted(self) -> None:
        result = self.rule.check(AuditData(tools=[self._tool({"/" * 130: {"type": "integer", "default": None}})]))
        assert result.details["mismatched_defaults"][0]["path_omitted"] is True

    def test_details_are_bounded(self) -> None:
        tool = self._tool({f"p{index}": {"type": "integer", "default": None} for index in range(25)})
        result = self.rule.check(AuditData(tools=[tool]))
        assert len(result.details["mismatched_defaults"]) == 20
        assert result.details["issues_total"] == 25
        assert "25" in result.message

    def test_large_data_does_not_build_paths(self) -> None:
        name = "k" * 16384
        tool = self._tool({name: {"type": "array", "default": [[0]] * 2048, "examples": [[[0]] * 2048]}})
        tracemalloc.start()
        try:
            self.rule.check(AuditData(tools=[tool]))
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        assert peak < 8 * 1024 * 1024

    def test_embedded_dialect_switch_is_unjudged(self) -> None:
        tool = self._tool(
            {
                "pair": {
                    "$schema": "http://json-schema.org/draft-07/schema#",
                    "prefixItems": [],
                    "default": 1,
                    "type": "string",
                }
            }
        )
        assert self.rule.skip_reason(AuditData(tools=[tool])) == SKIP_REASON_INSUFFICIENT_DATA

    def test_integral_floats_are_not_integers_before_draft_06(self) -> None:
        draft_04 = {"$schema": "http://json-schema.org/draft-04/schema#"}
        tool = self._tool(
            {"x": {"type": "integer", "default": 2.0}, "y": {"type": "number", "default": 2.0}}, **draft_04
        )
        assert self._paths(tool) == ["/properties/x"]

    def test_const_is_ignored_before_draft_06(self) -> None:
        tool = self._tool(
            {"x": {"type": "integer", "const": 0, "default": 1}},
            **{"$schema": "http://json-schema.org/draft-04/schema#"},
        )
        assert self._paths(tool) == []

    def test_pointer_tokens_are_escaped(self) -> None:
        result = self.rule.check(AuditData(tools=[self._tool({"a/b~c": {"type": "string", "default": 3}})]))
        assert result.details["mismatched_defaults"][0]["path"] == "/properties/a~1b~0c"
        assert result.details["mismatched_defaults"][0]["default_type"] == "integer"

    @pytest.mark.parametrize(
        ("default", "expected"),
        [(True, "boolean"), (1.5, "number"), ([1], "array"), ({"a": 1}, "object")],
    )
    def test_default_types_are_named(self, default: Any, expected: str) -> None:
        result = self.rule.check(AuditData(tools=[self._tool({"q": {"type": "string", "default": default}})]))
        assert result.details["mismatched_defaults"][0]["default_type"] == expected


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


class TestToolsMcpHeadersNotSensitiveRule:
    @pytest.mark.parametrize(
        ("parameter_name", "category"),
        [
            ("password", "password"),
            ("apiKey", "API key"),
            ("APIKey", "API key"),
            ("api_token", "API token"),
            ("refresh-token", "refresh token"),
            ("client_secret", "client secret"),
            ("social_security_number", "social security number"),
            ("email_address", "email address"),
            ("pii", "personally identifiable information"),
            ("session_token", "token"),
            ("securityToken", "token"),
            ("user_email", "email address"),
            ("contact_email", "email address"),
            ("customer_phone", "phone number"),
            ("apiKeys", "API key"),
            ("apiTokens", "API token"),
            ("passwords", "password"),
            ("clientSecrets", "client secret"),
        ],
    )
    def test_sensitive_parameter_names_fail(self, parameter_name: str, category: str) -> None:
        tool = _header_tool(
            "unsafe",
            {
                "type": "object",
                "properties": {
                    parameter_name: {"type": "string", "x-mcp-header": "Routing-Value"},
                },
            },
        )

        result = ToolsMcpHeadersNotSensitiveRule().check(AuditData(tools=[tool]))

        assert result.passed is False
        assert result.details is not None
        assert result.details["sensitive_headers"] == [
            {
                "tool": "unsafe",
                "path": f"$.properties.{parameter_name}",
                "header": "Routing-Value",
                "matched_on": "parameter",
                "sensitive_category": category,
            }
        ]

    def test_description_or_header_can_supply_sensitive_evidence(self) -> None:
        tools = [
            _header_tool(
                "description",
                {
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "description": "Bearer token used to access the upstream API",
                            "x-mcp-header": "Upstream-Value",
                        }
                    },
                },
            ),
            _header_tool(
                "header",
                {
                    "type": "object",
                    "properties": {
                        "value": {"type": "string", "x-mcp-header": "Client-Secret"},
                    },
                },
            ),
        ]

        result = ToolsMcpHeadersNotSensitiveRule().check(AuditData(tools=tools))

        assert result.passed is False
        assert result.details is not None
        assert [failure["matched_on"] for failure in result.details["sensitive_headers"]] == [
            "description",
            "header",
        ]

    @pytest.mark.parametrize(
        "parameter_name",
        [
            "region",
            "tenant_id",
            "page_token",
            "continuationToken",
            "token_count",
            "max_tokens",
            "email_notifications",
            "phone_support_enabled",
        ],
    )
    def test_common_non_sensitive_routing_parameters_pass(self, parameter_name: str) -> None:
        tool = _header_tool(
            "safe",
            {
                "type": "object",
                "properties": {
                    parameter_name: {"type": "string", "x-mcp-header": "Routing-Value"},
                },
            },
        )

        result = ToolsMcpHeadersNotSensitiveRule().check(AuditData(tools=[tool]))

        assert result.passed is True
        assert result.details == {"sensitive_headers": []}

    @pytest.mark.parametrize(
        "description",
        [
            "Maximum number of tokens to generate",
            "Send email notifications when the job completes",
            "Enable phone support for this account",
            "The secret of good UX is clarity",
            "HTTP authorization is handled by the gateway",
            "Store routing credentials separately from this header",
        ],
    )
    def test_ambiguous_words_in_free_text_do_not_fail(self, description: str) -> None:
        tool = _header_tool(
            "safe",
            {
                "type": "object",
                "properties": {
                    "setting": {
                        "type": "string",
                        "description": description,
                        "x-mcp-header": "Routing-Setting",
                    },
                },
            },
        )

        result = ToolsMcpHeadersNotSensitiveRule().check(AuditData(tools=[tool]))

        assert result.passed is True
        assert result.details == {"sensitive_headers": []}

    @pytest.mark.parametrize(
        ("field", "value", "category"),
        [
            ("description", "User email address", "email address"),
            ("description", "Customer phone number", "phone number"),
            ("description", "API access token", "access token"),
            ("description", "API token for the upstream service", "API token"),
            ("description", "OAuth client secret", "client secret"),
            ("title", "Email", "email address"),
            ("title", "Token", "token"),
            ("title", "Secret", "secret"),
        ],
    )
    def test_sensitive_context_in_free_text_still_fails(self, field: str, value: str, category: str) -> None:
        tool = _header_tool(
            "unsafe",
            {
                "type": "object",
                "properties": {
                    "value": {
                        "type": "string",
                        field: value,
                        "x-mcp-header": "Routing-Value",
                    },
                },
            },
        )

        result = ToolsMcpHeadersNotSensitiveRule().check(AuditData(tools=[tool]))

        assert result.passed is False
        assert result.details is not None
        assert result.details["sensitive_headers"][0]["matched_on"] == field
        assert result.details["sensitive_headers"][0]["sensitive_category"] == category

    def test_sensitive_unannotated_parameter_passes(self) -> None:
        tool = _header_tool(
            "safe",
            {
                "type": "object",
                "properties": {"password": {"type": "string"}},
            },
        )

        assert ToolsMcpHeadersNotSensitiveRule().check(AuditData(tools=[tool])).passed

    def test_malformed_sibling_schema_does_not_hide_sensitive_parameter(self) -> None:
        tool = _header_tool(
            "mixed",
            {
                "type": "object",
                "properties": {
                    "malformed": "not-a-schema",
                    "password": {"type": "string", "x-mcp-header": "Password"},
                },
            },
        )

        result = ToolsMcpHeadersNotSensitiveRule().check(AuditData(tools=[tool]))

        assert result.passed is False
        assert result.details is not None
        assert result.details["sensitive_headers"][0]["path"] == "$.properties.password"


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
