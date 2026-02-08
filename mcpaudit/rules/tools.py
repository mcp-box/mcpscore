from abc import abstractmethod
import re
from collections import Counter
from typing import Any

from mcp.types import Tool

from .base import BaseRule, RuleResult, RuleSeverity, requires_tools
from .registry import register_rule


class ToolsBaseRule(BaseRule):
    """Base class for all tool-related audit rules.

    This abstract base class provides common functionality for rules that
    validate MCP server tools compliance.
    """

    group_name = "tools"
    group_order = 4

    @requires_tools
    def check(self, tools: list[Tool] | None) -> RuleResult:
        """Execute the tools rule check.

        Args:
            tools: The tools to validate

        Returns:
            RuleResult indicating whether the tools check passed

        """
        if tools is None:
            return RuleResult(
                rule_name=self.rule_name,
                severity=self.severity,
                passed=False,
                message="❌ Tools object is not available",
                details={"tools": None},
            )

        return self._check_tools(tools)

    @abstractmethod
    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Perform the actual tools' validation.

        Args:
            tools: The tools to validate

        Returns:
            RuleResult with the validation outcome

        Note:
            This method must be implemented by subclasses to define
            the specific validation logic for each rule type.

        """
        ...


@register_rule
class ToolsAtLeastOneRule(ToolsBaseRule):
    """Critical check: Verify the MCP server provides at least one tool."""

    rule_id = "tools_at_least_one"
    rule_order = 1

    @property
    def rule_name(self) -> str:
        return "Tools - At least one tool must exist"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Critical check: Verify the MCP server provides at least one tool.

        Args:
            tools: The tools to validate
        Returns:
            RuleResult with the check outcome

        """
        passed = len(tools) > 0

        message = "✅ MCP Server provides at least one tool" if passed else "❌ MCP Server does not provide any tools"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"tools_count": len(tools)},
        )


@register_rule
class ToolsNamePresentRule(ToolsBaseRule):
    """Critical check: Verify that all tools have a name."""

    rule_id = "tools_name_present_in_all"
    rule_order = 2

    @property
    def rule_name(self) -> str:
        return "Tools - All tools must have a Name"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Critical check: Verify that all tools have a name.

        Args:
            tools: The tools to validate
        Returns:
            RuleResult with the check outcome

        """
        tools_with_empty_names = 0
        for tool in tools:
            if tool.name == "":
                tools_with_empty_names += 1

        passed = tools_with_empty_names == 0

        message = (
            "✅ All Tools have a Name property specified"
            if passed
            else f"❌ Number of tools with empty names: {tools_with_empty_names}"
        )

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"tools_with_empty_names": tools_with_empty_names},
        )


@register_rule
class ToolsNamesUniqueRule(ToolsBaseRule):
    """Critical check: Verify that all tool names are unique."""

    rule_id = "tools_names_unique"
    rule_order = 3

    @property
    def rule_name(self) -> str:
        return "Tools - All tool names must be unique"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Critical check: Verify that all tools names are unique.

        Args:
            tools: The tools to validate
        Returns:
            RuleResult with the check outcome

        """
        tool_names: list[str] = [tool.name for tool in tools]
        name_counts = Counter(tool_names)
        duplicates = [name for name, count in name_counts.items() if count > 1]

        passed = len(duplicates) == 0
        message = (
            "✅ All Tools have unique names"
            if passed
            else f"❌ Duplicate tool names found: {', '.join(duplicates)}"
        )

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"duplicate_names": duplicates, "name_counts": dict(name_counts)},
        )


@register_rule
class ToolsNamesValidFormatRule(ToolsBaseRule):
    """High check: Verify that all tool names follow the format."""

    rule_id = "tools_names_valid_format"
    rule_order = 4

    @property
    def rule_name(self) -> str:
        return "Tools - All tool names must follow the format"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """High check: Verify that all tools names follow the format.

        Args:
            tools: The tools to validate
        Returns:
            RuleResult with the check outcome

        """
        tools_with_invalid_names = 0
        for tool in tools:
            if bool(re.match(r"^[A-Za-z0-9_.-]{1,128}$", tool.name)):
                # Valid name
                continue

            tools_with_invalid_names += 1

        passed = tools_with_invalid_names == 0

        message = (
            "✅ All Tools have a valid Name property"
            if passed
            else f"❌ Number of tools with invalid names: {tools_with_invalid_names}"
        )

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"tools_with_invalid_names": tools_with_invalid_names},
        )


@register_rule
class ToolsTitlePresentRule(ToolsBaseRule):
    """High check: Verify that all tools have a title."""

    rule_id = "tools_title_present_in_all"
    rule_order = 5

    @property
    def rule_name(self) -> str:
        return "Tools - All tools must have a Title"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """High check: Verify that all tools have a title.

        Args:
            tools: The tools to validate
        Returns:
            RuleResult with the check outcome

        """
        tools_with_empty_titles: list[str] = [tool.name for tool in tools if tool.title == ""]

        passed = len(tools_with_empty_titles) == 0

        message = (
            "✅ All Tools have a Title property specified"
            if passed
            else f"❌ Number of tools with empty Titles: {len(tools_with_empty_titles)}"
        )

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"tools_with_empty_titles": tools_with_empty_titles},
        )


@register_rule
class ToolsDescriptionPresentRule(ToolsBaseRule):
    """High check: Verify that all tools have a description."""

    rule_id = "tools_description_present_in_all"
    rule_order = 6

    @property
    def rule_name(self) -> str:
        return "Tools - All tools must have a Description"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """High check: Verify that all tools have a Description.

        Args:
            tools: The tools to validate
        Returns:
            RuleResult with the check outcome

        """
        tools_with_empty_descriptions: list[str] = [tool.name for tool in tools if tool.description == ""]

        passed = len(tools_with_empty_descriptions) == 0

        message = (
            "✅ All Tools have a Description property specified"
            if passed
            else f"❌ Number of tools with empty descriptions: {len(tools_with_empty_descriptions)}"
        )

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"tools_with_empty_descriptions": tools_with_empty_descriptions},
        )


def is_valid_schema(schema: dict[str, Any] | None) -> bool:
    """Validate that a schema has a proper structure and required fields.

    A valid schema should have:
    - type: "object"
    - properties: dict with property definitions
    - required: list of required property names
    - title: string title for the schema

    Args:
        schema: The schema dictionary to validate

    Returns:
        bool: True if a schema is valid, False otherwise

    """
    if schema is None:
        return False

    # Check basic type
    if schema.get("type") != "object":
        return False

    # Check for required fields
    required_fields = ["properties", "required", "title"]
    if not all(field in schema for field in required_fields):
        return False

    # Validate properties is a dict
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return False

    # Validate required is a list
    required = schema.get("required")
    if not isinstance(required, list):
        return False

    # Validate title is a non-empty string
    title = schema.get("title")
    if not isinstance(title, str) or title.strip() == "":
        return False

    # Validate that all required properties exist in properties
    for prop_name in required:
        if prop_name not in properties:
            return False

    # Validate that each property has a proper structure
    for _prop_def in properties.values():
        if not isinstance(_prop_def, dict):
            return False

        # Each property should have at least a type
        if "type" not in _prop_def:
            return False

        # Property type should be a valid JSON Schema type
        valid_types = {"string", "number", "integer", "boolean", "array", "object", "null"}
        if _prop_def.get("type") not in valid_types:
            return False

    return True


@register_rule
class ToolsInputSchemaValidRule(ToolsBaseRule):
    """High check: Verify that each tool has a valid input schema."""

    rule_id = "tools_input_schema_valid"
    rule_order = 7

    @property
    def rule_name(self) -> str:
        return "Tools - All tools must have a valid input schema"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """High check: Verify that each tool has a valid input schema

        Args:
            tools: The tools to validate
        Returns:
            RuleResult with the check outcome

        """
        tools_with_invalid_input_schema: list[str] = [
            tool.name for tool in tools if not is_valid_schema(tool.inputSchema)
        ]

        passed = len(tools_with_invalid_input_schema) == 0

        message = (
            "✅ All Tools have a valid Input Schema"
            if passed
            else f"❌ Number of tools with invalid Input Schema: {len(tools_with_invalid_input_schema)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"tools_with_invalid_input_schema": tools_with_invalid_input_schema},
        )


@register_rule
class ToolsOutputSchemaValidRule(ToolsBaseRule):
    """High check: Verify that each tool has a valid output schema."""

    rule_id = "tools_output_schema_valid"
    rule_order = 8

    @property
    def rule_name(self) -> str:
        return "Tools - All tools must have a valid output schema"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """High check: Verify that each tool has a valid output schema

        Args:
            tools: The tools to validate
        Returns:
            RuleResult with the check outcome

        """
        tools_with_invalid_output_schema: list[str] = [
            tool.name for tool in tools if not is_valid_schema(tool.outputSchema)
        ]

        passed = len(tools_with_invalid_output_schema) == 0

        message = (
            "✅ All Tools have a valid Output Schema"
            if passed
            else f"❌ Number of tools with invalid Output Schema: {len(tools_with_invalid_output_schema)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"tools_with_invalid_output_schema": tools_with_invalid_output_schema},
        )
