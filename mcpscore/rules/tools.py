from abc import abstractmethod
from collections import Counter
import re
from typing import Any

from mcp_types import Tool

from .base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
    requires_fields,
    requires_tools,
)
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
    basis = "MCP 2025-11-25 Tools §Listing Tools (tools/list)"
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
    basis = "MCP 2025-11-25 Tools §Tool (name: unique identifier)"
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
    basis = "MCP 2025-11-25 Tools §Tool Names (SHOULD be unique within a server)"
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
            "✅ All Tools have unique names" if passed else f"❌ Duplicate tool names found: {', '.join(duplicates)}"
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
    basis = "MCP 2025-11-25 Tools §Tool Names (allowed charset, 1-128 length)"
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
    basis = "MCP 2025-11-25 Tools §Tool (title: display name)"
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
    basis = "MCP 2025-11-25 Tools §Tool (description)"
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


_VALID_JSON_TYPES = {"string", "number", "integer", "boolean", "array", "object", "null"}


def is_valid_schema(schema: dict[str, Any] | None) -> bool:
    """Validate that a schema is a structurally valid JSON Schema object.

    MCP tool schemas are JSON Schema, which permits far more than a fixed
    field set; only structural validity is checked here:

    - the top level must be an object schema, or use a combinator/reference
      (``anyOf``/``oneOf``/``allOf``/``$ref``)
    - ``properties``, ``required``, and ``title`` are optional but must have
      the correct shape when present — zero-argument tools with empty or
      omitted ``properties`` are valid
    - every name listed in ``required`` must exist in ``properties``
    - each property definition must be a mapping; a plain-string ``type``
      must be a valid JSON Schema type

    Args:
        schema: The schema dictionary to validate

    Returns:
        bool: True if a schema is valid, False otherwise

    """
    if schema is None:
        return False

    # Combinators and references are valid top-level schema forms
    if any(key in schema for key in ("anyOf", "oneOf", "allOf", "$ref")):
        return True

    if schema.get("type") != "object":
        return False

    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return False

    required = schema.get("required", [])
    if not isinstance(required, list):
        return False

    if "title" in schema and not isinstance(schema["title"], str):
        return False

    # Every required property must be defined in properties
    for prop_name in required:
        if prop_name not in properties:
            return False

    for prop_def in properties.values():
        if not isinstance(prop_def, dict):
            return False

        # "type" is optional (enum/anyOf/$ref properties are valid), but a
        # plain-string type must be a real JSON Schema type
        prop_type = prop_def.get("type")
        if isinstance(prop_type, str) and prop_type not in _VALID_JSON_TYPES:
            return False

    return True


@register_rule
class ToolsInputSchemaValidRule(ToolsBaseRule):
    """High check: Verify that each tool has a valid input schema."""

    rule_id = "tools_input_schema_valid"
    basis = "MCP 2025-11-25 Tools §Tool (inputSchema MUST be a valid JSON Schema object; 2020-12 default)"
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
            tool.name for tool in tools if not is_valid_schema(tool.input_schema)
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
    """High check: Verify that each declared output schema is valid.

    The MCP specification makes ``outputSchema`` optional — tools returning
    unstructured content simply omit it. Only tools that declare one are
    validated.
    """

    rule_id = "tools_output_schema_valid"
    basis = "MCP 2025-11-25 Tools §Tool (outputSchema; JSON Schema usage guidelines)"
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
            tool.name for tool in tools if tool.output_schema is not None and not is_valid_schema(tool.output_schema)
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


# The behavior-describing hints from the MCP tool `annotations` object. The
# display-only `title` hint is excluded: it conveys no execution semantics, so
# it does not count as "annotated" for this rule.
_TOOL_BEHAVIOR_HINTS = ("read_only_hint", "destructive_hint", "idempotent_hint", "open_world_hint")


def _has_behavior_annotation(tool: Tool) -> bool:
    """Return True if the tool declares at least one behavior hint."""
    annotations = tool.annotations
    if annotations is None:
        return False
    return any(getattr(annotations, hint, None) is not None for hint in _TOOL_BEHAVIOR_HINTS)


@register_rule
class ToolsAnnotationsPresentRule(ToolsBaseRule):
    """Medium check: tools should declare behavior annotations.

    MCP tool `annotations` (readOnlyHint, destructiveHint, idempotentHint,
    openWorldHint) let clients reason about a tool's effects — e.g. warn before
    a destructive call or skip confirmation for a read-only one. Declaring them
    is a spec best-practice that improves how safely clients can use the server.
    """

    rule_id = "tools_annotations_present"
    basis = "MCP 2025-11-25 Tools §Tool (annotations)"
    rule_order = 9

    @property
    def rule_name(self) -> str:
        return "Tools - All tools should declare behavior annotations"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Medium check: Verify that every tool declares behavior annotations.

        Args:
            tools: The tools to validate
        Returns:
            RuleResult with the check outcome

        """
        tools_without_annotations: list[str] = [tool.name for tool in tools if not _has_behavior_annotation(tool)]

        passed = len(tools_without_annotations) == 0

        message = (
            "✅ All Tools declare behavior annotations"
            if passed
            else f"❌ Number of tools without behavior annotations: {len(tools_without_annotations)}"
        )

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"tools_without_annotations": tools_without_annotations},
        )


@register_rule
class ToolsExecutionConsistentRule(BaseRule):
    """Medium check: task-augmented tools require the ``tasks`` capability.

    A tool whose ``execution.taskSupport`` is ``optional`` or ``required``
    (2025-11-25 experimental tasks) promises task-augmented execution — a
    server making that promise without declaring the ``tasks`` capability
    gives clients contradictory metadata.
    """

    group_name = "tools"
    group_order = 4
    rule_id = "tools_execution_consistent"
    basis = "MCP 2025-11-25 Tools §Tool (execution.taskSupport); Lifecycle §Capability Negotiation (tasks)"
    rule_order = 10
    min_spec_version = "2025-11-25"

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when the tools list is unavailable despite a declared tools capability.

        A failed ``tools/list`` (tools is None while the server declared the
        tools capability) means this rule cannot judge consistency — the peer
        tools rules already report the missing list, so re-passing here on an
        empty fallback would be a false green.
        """
        declares_tools = getattr(audit_data.capabilities, "tools", None) is not None
        if declares_tools and audit_data.tools is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    @property
    def rule_name(self) -> str:
        return "Tools - Task Execution Backed by Tasks Capability"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    @requires_fields("tools", "capabilities")
    def check(self, tools: list[Tool] | None, capabilities: Any | None) -> RuleResult:  # type: ignore[override]
        """Medium check: tools declaring task execution align with capabilities.

        Args:
            tools: The server's declared tools
            capabilities: The server's declared capabilities

        Returns:
            RuleResult with the check outcome

        """
        task_tools = [
            tool.name
            for tool in (tools or [])
            if tool.execution is not None and tool.execution.task_support in ("optional", "required")
        ]
        has_tasks_capability = getattr(capabilities, "tasks", None) is not None

        if not task_tools:
            passed = True
            message = "✅ No tools declare task-augmented execution"
        elif has_tasks_capability:
            passed = True
            message = f"✅ All {len(task_tools)} task-augmented tool(s) are backed by the tasks capability"
        else:
            passed = False
            message = f"❌ Number of tools declaring task execution without a tasks capability: {len(task_tools)}"

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"task_tools": task_tools, "tasks_capability": has_tasks_capability},
        )
