from abc import abstractmethod
from collections import Counter
import re
from typing import Any, ClassVar

from mcp_types import Tool

from .base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_NOT_APPLICABLE,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
    requires_fields,
    requires_tools,
)
from .icon_validation import find_invalid_icons
from .registry import register_rule


class ToolsBaseRule(BaseRule):
    """Base class for all tool-related audit rules.

    This abstract base class provides common functionality for rules that
    validate MCP server tools compliance.
    """

    group_name = "tools"
    group_order = 4
    judge_empty_catalog: ClassVar[bool] = False
    """Whether this rule's subject is the absence of tools itself."""

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when the tools catalog is unavailable or has no tools to judge."""
        listing = "tools"
        declares_tools = getattr(audit_data.capabilities, "tools", None) is not None
        unavailable = audit_data.tools is None and (declares_tools or listing in audit_data.listings_attempted)
        empty_partial = not audit_data.tools and listing in audit_data.incomplete_listings
        if unavailable or empty_partial:
            return SKIP_REASON_INSUFFICIENT_DATA
        if not audit_data.tools and not self.judge_empty_catalog:
            return SKIP_REASON_NOT_APPLICABLE
        return None

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
        assert tools or self.judge_empty_catalog  # noqa: S101 — skip_reason gates empty quality catalogs
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
    judge_empty_catalog = True

    @property
    def rule_name(self) -> str:
        return "Tools - At least one tool must exist"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.CRITICAL

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when an incomplete listing collected zero tools.

        An empty partial listing cannot prove the server has no tools — the
        tools may live on a page that was never fetched. A non-empty partial
        listing proves presence, so the rule still judges (and passes) it.
        """
        listing = "tools"
        declares_tools = getattr(audit_data.capabilities, "tools", None) is not None
        unavailable = audit_data.tools is None and (declares_tools or listing in audit_data.listings_attempted)
        if unavailable or (listing in audit_data.incomplete_listings and not audit_data.tools):
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

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

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when pagination did not produce the complete tool list.

        Uniqueness judged on a partial listing can produce a false pass —
        the duplicate may live on a page that was never fetched.
        """
        if reason := super().skip_reason(audit_data):
            return reason
        return SKIP_REASON_INSUFFICIENT_DATA if "tools" in audit_data.incomplete_listings else None

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
    """Low check: Encourage human-readable display titles for tools."""

    rule_id = "tools_title_present_in_all"
    basis = "MCP 2025-11-25 Tools §Tool (title: display name)"
    # `title` was introduced in the 2025-06-18 revision — earlier servers
    # cannot declare one and must not be penalized for its absence. (The
    # basis cites the revision the rule was verified against, per repo
    # policy — intentionally not the introduction revision.)
    min_spec_version = "2025-06-18"
    rule_order = 5

    @property
    def rule_name(self) -> str:
        return "Tools - All tools should have a display title"

    @property
    def severity(self) -> RuleSeverity:
        # LOW since the 2026-07 rebalance (was HIGH): title is optional with a
        # spec-defined fallback to `name`, and the registry sweep showed half
        # the ecosystem omits it — matching the resource/prompt title rules.
        return RuleSeverity.LOW

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Find tools without a non-blank display title.

        Args:
            tools: The tools to validate
        Returns:
            RuleResult with the check outcome

        """
        tools_without_title: list[str] = [tool.name for tool in tools if not (tool.title and tool.title.strip())]

        passed = len(tools_without_title) == 0

        message = (
            "✅ All tools have a display title"
            if passed
            else f"❌ Number of tools without a display title: {len(tools_without_title)}"
        )

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"tools_without_title": tools_without_title},
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
_HTTP_FIELD_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
# Deliberately strict: a JSON Schema type array (e.g. ["string", "null"]) also
# fails, even though the transport spec's client-behavior table contemplates
# null parameter values. The spec's constraint text names only the three bare
# primitives, so clients reading it literally will reject annotated union
# types too — flagging them matches the strictest conforming client.
_MCP_HEADER_PRIMITIVE_TYPES = {"integer", "string", "boolean"}
_SENSITIVE_HEADER_TERMS: dict[str, str] = {
    "api_key": "API key",
    "access_token": "access token",
    "auth_token": "authentication token",
    "authentication_token": "authentication token",
    "authorization": "authorization credential",
    "bearer_token": "bearer token",
    "client_secret": "client secret",
    "credential": "credential",
    "credentials": "credential",
    "password": "password",
    "passwd": "password",
    "passphrase": "passphrase",
    "private_key": "private key",
    "refresh_token": "refresh token",
    "secret": "secret",
    "token": "token",
    # High-confidence personal and financial identifiers. Generic identifiers,
    # names, tenant IDs, and account IDs are deliberately excluded: treating
    # every identifier as PII would make this heuristic unusably noisy.
    "card_number": "payment card number",
    "credit_card": "payment card number",
    "cvc": "card verification code",
    "cvv": "card verification code",
    "date_of_birth": "date of birth",
    "dob": "date of birth",
    "driver_license": "driver license number",
    "email": "email address",
    "email_address": "email address",
    "national_id": "national identifier",
    "passport_number": "passport number",
    "phone": "phone number",
    "phone_number": "phone number",
    "social_security_number": "social security number",
    "ssn": "social security number",
}
_NON_SECRET_TOKEN_TERMS = {
    "continuation_token",
    "cursor_token",
    "max_token",
    "max_tokens",
    "page_token",
    "pagination_token",
    "token_count",
    "token_limit",
}


def _mcp_header_annotations(schema: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect every x-mcp-header annotation and its static reachability."""
    annotations: list[dict[str, Any]] = []

    def walk(node: Any, path: str, *, reachable: bool, properties_allowed: bool) -> None:
        if isinstance(node, dict):
            if "x-mcp-header" in node:
                annotations.append(
                    {
                        "header": node["x-mcp-header"],
                        "path": path,
                        "type": node.get("type"),
                        "reachable": reachable,
                    }
                )

            for key, value in node.items():
                if key == "properties" and isinstance(value, dict):
                    for property_name, property_schema in value.items():
                        property_path = f"{path}.properties.{property_name}"
                        walk(
                            property_schema,
                            property_path,
                            reachable=properties_allowed,
                            properties_allowed=properties_allowed,
                        )
                elif isinstance(value, (dict, list)):
                    walk(value, f"{path}.{key}", reachable=False, properties_allowed=False)
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, f"{path}[{index}]", reachable=False, properties_allowed=False)

    walk(schema, "$", reachable=False, properties_allowed=True)
    return annotations


def _tool_mcp_header_annotations(tools: list[Tool]) -> list[dict[str, Any]]:
    """Collect x-mcp-header annotations with their tool names."""
    return [
        {"tool": tool.name, **annotation} for tool in tools for annotation in _mcp_header_annotations(tool.input_schema)
    ]


def _normalized_sensitive_terms(value: str) -> set[str]:
    """Return normalized words and phrases used by the sensitive-name matcher."""
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    words = re.findall(r"[A-Za-z0-9]+", snake.casefold())
    terms = set(words)
    terms.update(
        "_".join(words[start:end])
        for start in range(len(words))
        for end in range(start + 2, min(start + 3, len(words)) + 1)
    )
    if terms & _NON_SECRET_TOKEN_TERMS:
        terms.discard("token")
        terms.discard("tokens")
    return terms - _NON_SECRET_TOKEN_TERMS


def _sensitive_mcp_header_parameters(tool: Tool) -> list[dict[str, str]]:
    """Find annotated parameters whose declared metadata strongly implies sensitive data."""
    failures: list[dict[str, str]] = []

    def walk(schema: dict[str, Any], path: str) -> None:
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            return
        for parameter_name, property_schema in properties.items():
            property_path = f"{path}.properties.{parameter_name}"
            if not isinstance(property_schema, dict):
                continue
            if "x-mcp-header" in property_schema:
                candidates = {
                    "parameter": parameter_name,
                    "header": property_schema.get("x-mcp-header"),
                    "title": property_schema.get("title"),
                    "description": property_schema.get("description"),
                }
                matched: tuple[str, str] | None = None
                for source, candidate in candidates.items():
                    if not isinstance(candidate, str):
                        continue
                    terms = _normalized_sensitive_terms(candidate)
                    sensitive = next((term for term in _SENSITIVE_HEADER_TERMS if term in terms), None)
                    if sensitive is not None:
                        matched = (source, _SENSITIVE_HEADER_TERMS[sensitive])
                        break
                if matched is not None:
                    source, category = matched
                    failures.append(
                        {
                            "tool": tool.name,
                            "path": property_path,
                            "header": str(property_schema.get("x-mcp-header")),
                            "matched_on": source,
                            "sensitive_category": category,
                        }
                    )
            walk(property_schema, property_path)

    walk(tool.input_schema, "$")
    return failures


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


def is_valid_output_schema(schema: dict[str, Any] | None) -> bool:
    """Validate an ``outputSchema`` without requiring an object root.

    From 2026-07-28 an output schema "can be any valid JSON Schema 2020-12",
    so unlike ``is_valid_schema`` (input schemas keep their object-root
    requirement in every revision) this accepts any root:

    - combinators/references are valid top-level forms;
    - an object-rooted schema gets the full object shape checks;
    - any other root is accepted when its plain-string ``type`` (if present)
      is a real JSON Schema type.

    Whether a non-object root is *allowed on the negotiated revision* is a
    separate, version-scoped question — ``tools_output_schema_root_object``
    judges that for 2025-06-18..2025-11-25, so the two rules never
    double-penalize one condition.

    Args:
        schema: The schema dictionary to validate

    Returns:
        bool: True if a schema is valid, False otherwise

    """
    if schema is None:
        return False
    if any(key in schema for key in ("anyOf", "oneOf", "allOf", "$ref")):
        return True
    if schema.get("type") == "object":
        return is_valid_schema(schema)
    root_type = schema.get("type")
    return not isinstance(root_type, str) or root_type in _VALID_JSON_TYPES


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
    validated. Validity here is root-agnostic (2026-07-28 allows any valid
    JSON Schema root); the object-root restriction of earlier revisions is
    the version-scoped ``tools_output_schema_root_object`` rule's job.
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
            tool.name
            for tool in tools
            if tool.output_schema is not None and not is_valid_output_schema(tool.output_schema)
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


@register_rule
class ToolsOutputSchemaRootObjectRule(ToolsBaseRule):
    """High check: output schemas must be object-rooted where the revision requires it.

    Through 2025-11-25 the schema literal restricts ``outputSchema`` to
    ``type: "object"`` at the root ("Currently restricted to type: 'object'
    at the root level"); any-root schemas became legal in 2026-07-28. A
    server negotiating an older revision while declaring a non-object root
    breaks clients that compile declared schemas relying on that guarantee
    (e.g. the Go and Rust quickstart clients).
    """

    rule_id = "tools_output_schema_root_object"
    basis = 'MCP 2025-11-25 Schema Reference §Tool (outputSchema "restricted to type: object at the root level")'
    # outputSchema itself was introduced in 2025-06-18; the root restriction
    # was lifted in 2026-07-28 — the rule applies only inside that window.
    min_spec_version = "2025-06-18"
    max_spec_version = "2025-11-25"
    rule_order = 17

    @property
    def rule_name(self) -> str:
        return "Tools - Output schemas must be object-rooted on this revision"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        offending = {
            tool.name: tool.output_schema.get("type", "<absent>")
            for tool in tools
            if tool.output_schema is not None and tool.output_schema.get("type") != "object"
        }
        passed = not offending
        message = (
            "✅ All declared output schemas are object-rooted"
            if passed
            else f"❌ Number of tools with a non-object output schema root: {len(offending)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"tools_with_non_object_root": offending},
        )


class ToolsMcpHeadersBaseRule(ToolsBaseRule):
    """Base class for 2026 x-mcp-header definition rules."""

    min_spec_version = "2026-07-28"


@register_rule
class ToolsMcpHeadersValidNamesRule(ToolsMcpHeadersBaseRule):
    """High check: Verify x-mcp-header values use HTTP field-name syntax."""

    rule_id = "tools_mcp_headers_valid_names"
    basis = "MCP 2026-07-28 Tools §Tool Definitions (x-mcp-header constraints)"
    rule_order = 11

    @property
    def rule_name(self) -> str:
        return "Tools - MCP header names must be valid"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Find empty, non-string, or syntactically invalid header names."""
        invalid_headers = [
            annotation
            for annotation in _tool_mcp_header_annotations(tools)
            if not isinstance(annotation["header"], str) or _HTTP_FIELD_NAME_RE.fullmatch(annotation["header"]) is None
        ]
        return _mcp_header_result(
            self,
            invalid_headers,
            "invalid_headers",
            "All MCP header names are valid",
            "MCP headers with invalid names",
        )


@register_rule
class ToolsMcpHeadersUniqueRule(ToolsMcpHeadersBaseRule):
    """High check: Verify x-mcp-header values are case-insensitively unique."""

    rule_id = "tools_mcp_headers_unique"
    basis = "MCP 2026-07-28 Tools §Tool Definitions (x-mcp-header constraints)"
    rule_order = 12

    @property
    def rule_name(self) -> str:
        return "Tools - MCP header names must be unique"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Find duplicate header names within each tool input schema."""
        annotations = _tool_mcp_header_annotations(tools)
        counts = Counter(
            (annotation["tool"], annotation["header"].casefold())
            for annotation in annotations
            if isinstance(annotation["header"], str)
        )
        duplicate_headers = [
            annotation
            for annotation in annotations
            if isinstance(annotation["header"], str)
            and counts[(annotation["tool"], annotation["header"].casefold())] > 1
        ]
        return _mcp_header_result(
            self,
            duplicate_headers,
            "duplicate_headers",
            "All MCP header names are unique",
            "duplicate MCP header annotations",
        )


@register_rule
class ToolsMcpHeadersPrimitiveTypesRule(ToolsMcpHeadersBaseRule):
    """High check: Verify x-mcp-header appears only on allowed primitives."""

    rule_id = "tools_mcp_headers_primitive_types"
    basis = "MCP 2026-07-28 Tools §Tool Definitions (x-mcp-header primitive types)"
    rule_order = 13

    @property
    def rule_name(self) -> str:
        return "Tools - MCP headers must annotate supported primitive types"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Find annotations on number, object, array, or untyped schemas."""
        invalid_types = [
            annotation
            for annotation in _tool_mcp_header_annotations(tools)
            if annotation["type"] not in _MCP_HEADER_PRIMITIVE_TYPES
        ]
        return _mcp_header_result(
            self,
            invalid_types,
            "headers_with_invalid_types",
            "All MCP headers annotate supported primitive types",
            "MCP headers on unsupported types",
        )


@register_rule
class ToolsMcpHeadersStaticallyReachableRule(ToolsMcpHeadersBaseRule):
    """High check: Verify annotated properties are statically reachable."""

    rule_id = "tools_mcp_headers_statically_reachable"
    basis = "MCP 2026-07-28 Tools §Tool Definitions (x-mcp-header static reachability)"
    rule_order = 14

    @property
    def rule_name(self) -> str:
        return "Tools - MCP header parameters must be statically reachable"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Find annotations reached through anything except properties chains."""
        unreachable_headers = [
            annotation for annotation in _tool_mcp_header_annotations(tools) if not annotation["reachable"]
        ]
        return _mcp_header_result(
            self,
            unreachable_headers,
            "unreachable_headers",
            "All MCP header parameters are statically reachable",
            "statically unreachable MCP header parameters",
        )


@register_rule
class ToolsMcpHeadersNotSensitiveRule(ToolsMcpHeadersBaseRule):
    """High check: Reject x-mcp-header annotations on visibly sensitive inputs."""

    rule_id = "tools_mcp_headers_not_sensitive"
    basis = "MCP 2026-07-28 Tools §x-mcp-header (sensitive parameters SHOULD NOT be mirrored into headers)"
    rule_order = 15

    @property
    def rule_name(self) -> str:
        return "Tools - MCP headers should not expose sensitive parameters"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Find high-confidence credential and PII terms on annotated inputs."""
        sensitive_headers = [failure for tool in tools for failure in _sensitive_mcp_header_parameters(tool)]
        return _mcp_header_result(
            self,
            sensitive_headers,
            "sensitive_headers",
            "MCP headers avoid visibly sensitive parameters",
            "MCP headers exposing visibly sensitive parameters",
        )


def _undocumented_input_properties(tool: Tool) -> list[dict[str, str]]:
    """Find undocumented properties reachable through direct properties chains."""
    failures: list[dict[str, str]] = []

    # walk is entered only with dicts: the model validates input_schema, and
    # recursion below descends only into property schemas that are dicts.
    def walk(schema: dict[str, Any], path: str) -> None:
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            return
        for property_name, property_schema in properties.items():
            property_path = f"{path}.properties.{property_name}"
            if not isinstance(property_schema, dict):
                continue
            description = property_schema.get("description")
            if not isinstance(description, str) or not description.strip():
                failures.append({"tool": tool.name, "path": property_path})
            walk(property_schema, property_path)

    walk(tool.input_schema, "$")
    return failures


@register_rule
class ToolsInputPropertiesDocumentedRule(ToolsBaseRule):
    """Medium check: Encourage descriptions for statically reachable inputs."""

    rule_id = "tools_input_properties_documented"
    # Quality recommendation, not a spec mandate: the spec's §Tool examples
    # document every property, but no normative text requires it. Undocumented
    # parameters directly degrade LLM tool selection and argument filling.
    basis = "MCP 2026-07-28 Tools §Tool (inputSchema; property descriptions per the spec's examples)"
    rule_order = 16

    @property
    def rule_name(self) -> str:
        return "Tools - Input properties should be documented"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Find statically reachable input properties without descriptions."""
        undocumented_properties = [failure for tool in tools for failure in _undocumented_input_properties(tool)]
        passed = not undocumented_properties
        message = (
            "✅ All statically reachable tool inputs are documented"
            if passed
            else f"❌ Number of undocumented tool input properties: {len(undocumented_properties)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"undocumented_properties": undocumented_properties},
        )


def _mcp_header_result(
    rule: BaseRule,
    failures: list[dict[str, Any]],
    details_key: str,
    pass_message: str,
    failure_label: str,
) -> RuleResult:
    """Build a consistent result for an x-mcp-header rule."""
    passed = not failures
    message = f"✅ {pass_message}" if passed else f"❌ Number of {failure_label}: {len(failures)}"
    return RuleResult(
        rule_name=rule.rule_name,
        severity=rule.severity,
        passed=passed,
        message=message,
        details={details_key: failures},
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
class ToolsIconsValidRule(ToolsBaseRule):
    """Low check: validate every declared tool icon."""

    rule_id = "tools_icons_valid"
    basis = "MCP 2026-07-28 Schema Reference §Common Types (Icon); Tools §Tool (icons)"
    min_spec_version = "2025-11-25"
    rule_order = 16

    @property
    def rule_name(self) -> str:
        return "Tools - Declared icons must be valid"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        invalid_icons = find_invalid_icons([(tool.name, tool) for tool in tools])
        passed = not invalid_icons
        message = (
            "✅ All declared tool icons are valid"
            if passed
            else f"❌ Number of invalid tool icons: {len(invalid_icons)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"invalid_icons": invalid_icons},
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
        """Skip when the tools catalog is unavailable or has no tools to judge.

        A declared-but-unobserved catalog or an empty partial listing lacks
        enough evidence to judge consistency. A complete empty catalog has no
        tool whose execution metadata this rule can assess.
        """
        listing = "tools"
        declares_tools = getattr(audit_data.capabilities, "tools", None) is not None
        unavailable = audit_data.tools is None and (declares_tools or listing in audit_data.listings_attempted)
        empty_partial = not audit_data.tools and listing in audit_data.incomplete_listings
        if unavailable or empty_partial:
            return SKIP_REASON_INSUFFICIENT_DATA
        if not audit_data.tools:
            return SKIP_REASON_NOT_APPLICABLE
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
