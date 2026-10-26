from abc import abstractmethod
from collections import Counter
from collections.abc import Iterator
import re
from typing import Any, cast

from jsonschema.exceptions import SchemaError
from jsonschema.validators import Draft202012Validator, validator_for
from mcp_types import Tool
from referencing import Registry
from referencing.exceptions import Unresolvable

from mcpscore.diagnostics import quoted_preview

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
from .catalog_diagnostics import catalog_result, field_issue, fields, pointer_token
from .icon_validation import find_invalid_icons, icon_issues
from .registry import register_rule
from .tool_intent import ToolIntent, tool_intent


class ToolsBaseRule(BaseRule):
    """Base class for all tool-related audit rules.

    This abstract base class provides common functionality for rules that
    validate MCP server tools compliance.
    """

    group_name = "tools"
    group_order = 4

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when the tools catalog is unavailable or has no tools to judge."""
        listing = "tools"
        declares_tools = getattr(audit_data.capabilities, "tools", None) is not None
        unavailable = audit_data.tools is None and (declares_tools or listing in audit_data.listings_attempted)
        empty_partial = not audit_data.tools and listing in audit_data.incomplete_listings
        if unavailable or empty_partial:
            return SKIP_REASON_INSUFFICIENT_DATA
        if not audit_data.tools:
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
                suggested_fix=(
                    "Check catalog collection and the tools/list response before changing tool "
                    "definitions. Retry the audit once the catalog is available."
                ),
            )
        assert tools  # noqa: S101 — skip_reason gates empty catalogs
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
            "✅ All tools have a non-empty name"
            if passed
            else f"❌ Number of tools with empty names: {tools_with_empty_names}"
        )

        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"tools_with_empty_names": tools_with_empty_names},
            suggested_fix=(
                "Set name to a non-empty identifier on each reported tool. Use the catalog index to "
                "locate unnamed entries."
            ),
            issues=fields(tools, "tool", "/name", "empty_name", "a non-empty identifier", lambda tool: tool.name == ""),
            recommendation=False,
        )


@register_rule
class ToolsNamesUniqueRule(ToolsBaseRule):
    """Critical check: Verify that all tool names are unique."""

    rule_id = "tools_names_unique"
    basis = "MCP 2025-11-25 Tools §Tool Names (SHOULD be unique within a server)"
    rule_order = 3

    @property
    def rule_name(self) -> str:
        return "Tools - All tool names should be unique"

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
            "✅ All tools have unique names"
            if passed
            else (
                f"❌ Duplicate tool names ({len(duplicates)} distinct): "
                + ", ".join(quoted_preview(name) for name in duplicates[:3])
                + (f"; {len(duplicates) - 3} more" if len(duplicates) > 3 else "")
            )
        )

        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"duplicate_names": duplicates, "name_counts": dict(name_counts)},
            suggested_fix=(
                "Give each tool a distinct name and update clients or documentation that reference renamed tools."
            ),
            issues=fields(
                tools,
                "tool",
                "/name",
                "duplicate_name",
                "a name unique within the tool catalog",
                lambda tool: name_counts[tool.name] > 1,
            ),
            recommendation=False,
        )


@register_rule
class ToolsNamesValidFormatRule(ToolsBaseRule):
    """High check: Verify that all tool names follow the format."""

    rule_id = "tools_names_valid_format"
    basis = "MCP 2025-11-25 Tools §Tool Names (allowed charset, 1-128 length)"
    rule_order = 4

    @property
    def rule_name(self) -> str:
        return "Tools - All tool names should follow the recommended format"

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
            "✅ All tools have names matching the checked format"
            if passed
            else f"❌ Number of tools with invalid names: {tools_with_invalid_names}"
        )

        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"tools_with_invalid_names": tools_with_invalid_names},
            suggested_fix=(
                "Use 1-128 ASCII letters, digits, underscores, hyphens or dots in each tool name; for "
                "example, search_customers. Update references to renamed tools."
            ),
            issues=fields(
                tools,
                "tool",
                "/name",
                "invalid_name_format",
                "1-128 ASCII letters, digits, underscores, hyphens or dots",
                lambda tool: not re.match(r"^[A-Za-z0-9_.-]{1,128}$", tool.name),
            ),
            recommendation=False,
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

        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"tools_without_title": tools_without_title},
            suggested_fix="Add a short human-readable title to each reported tool for display in clients.",
            issues=fields(
                tools,
                "tool",
                "/title",
                "missing_title",
                "a nonblank display title",
                lambda tool: not (tool.title and tool.title.strip()),
            ),
            recommendation=True,
        )


@register_rule
class ToolsDescriptionPresentRule(ToolsBaseRule):
    """High check: Verify that all tools have a description."""

    rule_id = "tools_description_present_in_all"
    basis = "MCP 2025-11-25 Tools §Tool (description)"
    rule_order = 6

    @property
    def rule_name(self) -> str:
        return "Tools - All tools should have a description"

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
        # Absent (None) and whitespace-only count as missing, same predicate
        # as the prompt/resource siblings — the old `== ""` let a tool with
        # NO description at all pass the rule that exists to catch it.
        tools_with_empty_descriptions: list[str] = [
            tool.name for tool in tools if not (tool.description and tool.description.strip())
        ]

        passed = len(tools_with_empty_descriptions) == 0

        message = (
            "✅ All tools have a nonblank description"
            if passed
            else f"❌ Number of tools with missing or empty descriptions: {len(tools_with_empty_descriptions)}"
        )

        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"tools_with_empty_descriptions": tools_with_empty_descriptions},
            suggested_fix=(
                "Describe what each reported tool does, when to use it and its important limits in "
                "the description field."
            ),
            issues=fields(
                tools,
                "tool",
                "/description",
                "missing_description",
                "a nonblank description",
                lambda tool: not (tool.description and tool.description.strip()),
            ),
            recommendation=True,
        )


def normalized_description(description: str | None) -> str | None:
    """Return the comparable form of a description, or None when it is missing or blank.

    Trims, case-folds, collapses whitespace and drops one trailing period, so
    descriptions that differ only in those ways compare equal.
    """
    if description is None:
        return None
    text = " ".join(description.split()).casefold().removesuffix(".").rstrip()
    return text or None


@register_rule
class ToolsDescriptionsUniqueRule(ToolsBaseRule):
    """Low check: Verify that no two tools share a description."""

    rule_id = "tools_descriptions_unique"
    basis = "MCP 2025-11-25 Tools §User Interaction Model (model-controlled: the model picks tools by description)"
    rule_order = 21

    @property
    def rule_name(self) -> str:
        return "Tools - Each tool should have its own description"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip a partial listing, and a catalog with fewer than two described tools."""
        if reason := super().skip_reason(audit_data):
            return reason
        if "tools" in audit_data.incomplete_listings:
            return SKIP_REASON_INSUFFICIENT_DATA
        described = [tool for tool in audit_data.tools or [] if normalized_description(tool.description)]
        return SKIP_REASON_NOT_APPLICABLE if len(described) < 2 else None

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Low check: Group tools whose normalized descriptions are identical.

        Args:
            tools: The tools to validate
        Returns:
            RuleResult with the check outcome

        """
        groups: dict[str, list[str]] = {}
        for tool in tools:
            if key := normalized_description(tool.description):
                groups.setdefault(key, []).append(tool.name)
        shared = [names for names in groups.values() if len(names) > 1]
        duplicated = {key for key, names in groups.items() if len(names) > 1}

        passed = not shared
        # Tool names only: the description text is publisher-controlled and never echoed.
        summaries = [
            ", ".join(quoted_preview(name) for name in names[:3])
            + (f" and {len(names) - 3} more" if len(names) > 3 else "")
            for names in shared[:3]
        ]
        message = (
            "✅ Every described tool has its own description"
            if passed
            else (
                f"❌ Tools sharing one description ({len(shared)} group{'s' if len(shared) != 1 else ''}): "
                + "; ".join(summaries)
                + (f"; {len(shared) - 3} more groups" if len(shared) > 3 else "")
            )
        )

        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"duplicate_description_groups": shared},
            suggested_fix=(
                "Say in each reported tool's description when to use it instead of the others. "
                "If two tools are aliases of one operation, remove the alias."
            ),
            issues=fields(
                tools,
                "tool",
                "/description",
                "duplicate_description",
                "a description that tells this tool apart from the others",
                lambda tool: normalized_description(tool.description) in duplicated,
            ),
            recommendation=True,
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
    "api_token": "API token",
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
    "pii": "personally identifiable information",
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
_STRUCTURED_SUFFIX_SENSITIVE_TERMS = {"email", "phone"}
_SENSITIVE_PLURAL_WORDS: dict[str, str] = {
    "credentials": "credential",
    "keys": "key",
    "passphrases": "passphrase",
    "passwords": "password",
    "secrets": "secret",
    "tokens": "token",
}
_FREE_TEXT_EXACT_SENSITIVE_TERMS = {
    "authorization",
    "credential",
    "credentials",
    "email",
    "phone",
    "secret",
    "token",
}
_FREE_TEXT_CONTEXT_SENSITIVE_TERMS = {
    term: category for term, category in _SENSITIVE_HEADER_TERMS.items() if term not in _FREE_TEXT_EXACT_SENSITIVE_TERMS
}


def _mcp_header_annotations(schema: dict[str, Any]) -> list[dict[str, Any]]:
    """Collect every x-mcp-header annotation and its static reachability."""
    annotations: list[dict[str, Any]] = []

    def walk(node: Any, path: str, pointer: str, *, reachable: bool, properties_allowed: bool) -> None:
        if isinstance(node, dict):
            if "x-mcp-header" in node:
                annotations.append(
                    {
                        "header": node["x-mcp-header"],
                        "path": path,
                        "_pointer": pointer,
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
                            f"{pointer}/properties/{pointer_token(property_name)}",
                            reachable=properties_allowed,
                            properties_allowed=properties_allowed,
                        )
                elif isinstance(value, (dict, list)):
                    walk(
                        value,
                        f"{path}.{key}",
                        f"{pointer}/{pointer_token(key)}",
                        reachable=False,
                        properties_allowed=False,
                    )
        elif isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, f"{path}[{index}]", f"{pointer}/{index}", reachable=False, properties_allowed=False)

    walk(schema, "$", "/inputSchema", reachable=False, properties_allowed=True)
    return annotations


def _tool_mcp_header_annotations(tools: list[Tool]) -> list[dict[str, Any]]:
    """Collect x-mcp-header annotations with their tool names."""
    return [
        {"tool": tool.name, "_entity_index": index, **annotation}
        for index, tool in enumerate(tools)
        for annotation in _mcp_header_annotations(tool.input_schema)
    ]


def _normalized_sensitive_words(value: str) -> list[str]:
    """Split an identifier and canonicalize only known sensitive plurals."""
    snake = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", value)
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", snake)
    return [
        cast("str", _SENSITIVE_PLURAL_WORDS.get(word, word)) for word in re.findall(r"[A-Za-z0-9]+", snake.casefold())
    ]


def _normalized_sensitive_terms(value: str) -> set[str]:
    """Return normalized words and phrases used by the sensitive-name matcher."""
    words = _normalized_sensitive_words(value)
    terms = set(words)
    terms.update(
        "_".join(words[start:end])
        for start in range(len(words))
        for end in range(start + 2, min(start + 3, len(words)) + 1)
    )
    if terms & _NON_SECRET_TOKEN_TERMS:
        terms.discard("token")
    return terms - _NON_SECRET_TOKEN_TERMS


def _sensitive_category(value: str, source: str) -> str | None:
    """Classify strong sensitive-data evidence, accounting for metadata shape."""
    terms = _normalized_sensitive_terms(value)
    normalized_identifier = "_".join(_normalized_sensitive_words(value))

    if source in {"title", "description"}:
        contextual = next((term for term in _FREE_TEXT_CONTEXT_SENSITIVE_TERMS if term in terms), None)
        if contextual is not None:
            return _FREE_TEXT_CONTEXT_SENSITIVE_TERMS[contextual]
        if normalized_identifier in _FREE_TEXT_EXACT_SENSITIVE_TERMS:
            return _SENSITIVE_HEADER_TERMS[normalized_identifier]
        return None

    for sensitive, category in _SENSITIVE_HEADER_TERMS.items():
        if sensitive not in terms:
            continue
        if sensitive in _STRUCTURED_SUFFIX_SENSITIVE_TERMS and not (
            normalized_identifier == sensitive or normalized_identifier.endswith(f"_{sensitive}")
        ):
            continue
        return category
    return None


def _sensitive_mcp_header_parameters(tool: Tool) -> list[dict[str, Any]]:
    """Find annotated parameters whose declared metadata strongly implies sensitive data."""
    failures: list[dict[str, Any]] = []

    def walk(schema: dict[str, Any], path: str, pointer: str) -> None:
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            return
        for parameter_name, property_schema in properties.items():
            property_path = f"{path}.properties.{parameter_name}"
            property_pointer = f"{pointer}/properties/{pointer_token(parameter_name)}"
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
                    category = _sensitive_category(candidate, source)
                    if category is not None:
                        matched = (source, category)
                        break
                if matched is not None:
                    source, category = matched
                    failures.append(
                        {
                            "tool": tool.name,
                            "path": property_path,
                            "_pointer": property_pointer,
                            "header": str(property_schema.get("x-mcp-header")),
                            "matched_on": source,
                            "sensitive_category": category,
                        }
                    )
            walk(property_schema, property_path, property_pointer)

    walk(tool.input_schema, "$", "/inputSchema")
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
    return _schema_problem(schema) is None


def is_valid_output_schema(schema: dict[str, Any] | None) -> bool:
    """Validate output schemas without imposing a revision-specific root type.

    The 2026-07-28 revision permits non-object output schema roots. Earlier
    revisions' object-root restriction is checked separately by the scoped
    tools_output_schema_root_object rule, avoiding duplicate penalties here.
    Preserve the existing structural predicate until its separate correctness review.
    """
    return _schema_problem(schema, output=True) is None


def _pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _schema_problem(schema: dict[str, Any] | None, *, output: bool = False) -> tuple[str, str, str] | None:
    """Explain the first failing legacy predicate without broadening validation.

    This is deliberately not a new JSON Schema validator. Combinator shortcuts
    and required/properties behavior remain unchanged pending a separate review.
    No schema values are copied into diagnostic output.
    """
    if schema is None:
        return "", "missing_schema", "a JSON Schema object"
    if any(key in schema for key in ("anyOf", "oneOf", "allOf", "$ref")):
        return None
    if output and schema.get("type") != "object":
        root_type = schema.get("type")
        if isinstance(root_type, str) and root_type not in _VALID_JSON_TYPES:
            return "/type", "invalid_type", "string, number, integer, boolean, array, object, or null"
        return None
    if schema.get("type") != "object":
        return "/type", "object_root_expected", "object"
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return "/properties", "invalid_properties", "an object mapping property names to schemas"
    required = schema.get("required", [])
    if not isinstance(required, list):
        return "/required", "invalid_required", "an array of property names"
    if "title" in schema and not isinstance(schema["title"], str):
        return "/title", "invalid_title", "a string"
    for index, name in enumerate(required):
        if name not in properties:
            return f"/required/{index}", "undeclared_required_property", "a property declared in properties"
    for name, definition in properties.items():
        path = f"/properties/{_pointer(name)}"
        if not isinstance(definition, dict):
            return path, "invalid_property_schema", "a schema object"
        value = definition.get("type")
        if isinstance(value, str) and value not in _VALID_JSON_TYPES:
            return path + "/type", "invalid_type", "string, number, integer, boolean, array, object, or null"
    return None


def _schema_issues(tools: list[Tool], *, output: bool = False) -> dict[str, Any]:
    """Collect bounded indexed locations without copying arbitrary schema values."""
    issues: list[dict[str, Any]] = []
    total = 0
    field_name = "outputSchema" if output else "inputSchema"
    for index, tool in enumerate(tools):
        schema = tool.output_schema if output else tool.input_schema
        if output and schema is None:
            continue
        problem = _schema_problem(schema, output=output)
        if problem is None:
            continue
        total += 1
        if len(issues) < 20:
            path, reason, expected = problem
            # Store a resolvable pointer; terminal escaping belongs to the renderer.
            pointer = "/" + field_name + path
            issue = {"entity_kind": "tool", "entity_index": index, "reason": reason, "expected": expected}
            if len(pointer) <= 255:
                issue["path"] = pointer
            else:
                issue["path_omitted"] = True
            issues.append(issue)
    return {"issues": issues, "issues_total": total, "issues_omitted": total - len(issues)}


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
            "✅ All tools have a valid Input Schema"
            if passed
            else f"❌ {len(tools_with_invalid_input_schema)} tool(s) have an invalid input schema."
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "tools_with_invalid_input_schema": tools_with_invalid_input_schema,
                **(_schema_issues(tools, output=False) if not passed else {}),
            },
            suggested_fix=(
                "Correct each listed inputSchema path to match its expected constraint. "
                "For an invalid type, use string, number, integer, boolean, array, object, or null."
            )
            if not passed
            else None,
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
            "✅ All tools have a valid Output Schema"
            if passed
            else f"❌ {len(tools_with_invalid_output_schema)} tool(s) have an invalid output schema."
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={
                "tools_with_invalid_output_schema": tools_with_invalid_output_schema,
                **(_schema_issues(tools, output=True) if not passed else {}),
            },
            suggested_fix=(
                "Correct each listed outputSchema path to match its expected constraint. "
                "For an invalid type, use string, number, integer, boolean, array, object, or null."
            )
            if not passed
            else None,
        )


def non_object_output_roots(tools: list[Tool]) -> dict[str, Any]:
    """Return each tool whose declared output schema is not object-rooted, mapped to its root ``type``."""
    return {
        tool.name: tool.output_schema.get("type", "<absent>")
        for tool in tools
        if tool.output_schema is not None and tool.output_schema.get("type") != "object"
    }


def session_rejected_output_roots(audit_data: AuditData) -> list[int]:
    """Return the indexes of tools whose output schema root the session's first ``tools/list`` page failed at."""
    error = audit_data.listing_errors.get("tools", {})
    if error.get("outcome") != "invalid_response" or error.get("page_index") != 0:
        return []
    indexes = set()
    for issue in error.get("issues", []):
        # "/tools/0/outputSchema/type" -> ["tools", "0", "outputSchema", "type"]
        parts = str(issue.get("path", "")).split("/")[1:]
        if len(parts) == 4 and parts[0] == "tools" and parts[1].isdigit() and parts[2:] == ["outputSchema", "type"]:
            indexes.add(int(parts[1]))
    return sorted(indexes)


@register_rule
class ToolsOutputSchemaRootObjectRule(ToolsBaseRule):
    """High check: output schemas must be object-rooted where the revision requires it.

    Through 2025-11-25 the schema literal restricts ``outputSchema`` to
    ``type: "object"`` at the root ("Currently restricted to type: 'object'
    at the root level"); any-root schemas became legal in 2026-07-28. A
    server negotiating an older revision while declaring a non-object root
    breaks clients that compile declared schemas relying on that guarantee
    (e.g. the Go and Rust quickstart clients).

    When the session listing failed and the catalog was recovered from the
    stateless lifecycle, that catalog shows what the newer revision serves,
    not what the session did. The rule then judges the session's own
    evidence: it fails when the session's catalog was rejected at an output
    schema root, and is not applicable otherwise.
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

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip a recovered catalog unless the session rejected an output schema root.

        The session's rejection is judged whatever the recovered catalog holds, even nothing. ``check`` takes
        the whole audit data, so the auditor's partial-audit skip does not see that this rule needs the tools:
        a partial audit that collected none is insufficient data, as for every other tools rule.
        """
        if audit_data.partial and audit_data.tools is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        if "tools" in audit_data.catalog_versions:
            return None if session_rejected_output_roots(audit_data) else SKIP_REASON_NOT_APPLICABLE
        return super().skip_reason(audit_data)

    def check(self, audit_data: AuditData) -> RuleResult:
        """Judge the session's catalog, or the session's rejection of it when the catalog was recovered."""
        if "tools" not in audit_data.catalog_versions:
            return super().check(audit_data)
        rejected = session_rejected_output_roots(audit_data)
        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=False,
            message=(
                f"❌ The {audit_data.protocol_version} session could not list tools: the output schema root of "
                f"{len(rejected)} tool(s) is not an object"
            ),
            details={"session_rejected_tool_indexes": rejected},
            suggested_fix=self._SUGGESTED_FIX,
            issues=(
                field_issue(
                    "tool",
                    index,
                    "/outputSchema/type",
                    "non_object_root",
                    "object for revisions 2025-06-18 through 2025-11-25",
                )
                for index in rejected
            ),
        )

    _SUGGESTED_FIX = (
        "For the audited revision, wrap structured output in an object and update "
        "outputSchema and returned structuredContent together. Omit outputSchema only if "
        "structured output is not part of the contract."
    )

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        offending = non_object_output_roots(tools)
        passed = not offending
        message = (
            "✅ All declared output schemas are object-rooted"
            if passed
            else f"❌ Number of distinct tool names with a non-object output schema root: {len(offending)}"
        )
        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"tools_with_non_object_root": offending},
            suggested_fix=self._SUGGESTED_FIX,
            issues=fields(
                tools,
                "tool",
                "/outputSchema/type",
                "non_object_root",
                "object for revisions 2025-06-18 through 2025-11-25",
                lambda tool: tool.output_schema is not None and tool.output_schema.get("type") != "object",
            ),
            recommendation=False,
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
            suggested_fix=(
                "Use a non-empty HTTP field-name token for each x-mcp-header value, such as Region. "
                "Remove spaces, separators and control characters."
            ),
            expected="a non-empty HTTP field-name token",
            reason="invalid_header_name",
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
            suggested_fix=(
                "Use distinct x-mcp-header values within each tool, ignoring letter case. If the "
                "flagged parameters belong to separate tools with the same name, resolve the "
                "tool-name collision and audit again."
            ),
            expected="case-insensitively distinct header names (currently grouped by tool name)",
            reason="duplicate_header_name",
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
            suggested_fix=(
                "Keep x-mcp-header only on string, integer or boolean parameters. Remove the "
                "annotation from parameters whose actual type needs a different representation; do "
                "not change their type just to pass."
            ),
            expected="string, integer or boolean",
            reason="unsupported_header_type",
            field="type",
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
            suggested_fix=(
                "Keep x-mcp-header on parameters reached through direct properties chains from "
                "inputSchema. Remove it from conditional, referenced or array branches, or "
                "restructure the schema without changing input meaning."
            ),
            expected="a parameter reached through direct properties chains",
            reason="unreachable_header",
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
        sensitive_headers = [
            {**failure, "_entity_index": index}
            for index, tool in enumerate(tools)
            for failure in _sensitive_mcp_header_parameters(tool)
        ]
        return _mcp_header_result(
            self,
            sensitive_headers,
            "sensitive_headers",
            "MCP headers avoid visibly sensitive parameters",
            "MCP header annotations with potentially sensitive parameter metadata",
            suggested_fix=(
                "Remove x-mcp-header from inputs containing credentials or personal data. Use the "
                "appropriate authentication mechanism for credentials; renaming a sensitive field "
                "does not make it safe."
            ),
            expected="a parameter without metadata indicating credentials or personal data",
            reason="potentially_sensitive_header",
        )


def _undocumented_properties(tool: Tool, schema: dict[str, Any], root: str) -> list[dict[str, Any]]:
    """Find undocumented properties of *schema*, at JSON pointer *root*, reachable through direct properties chains."""
    failures: list[dict[str, Any]] = []

    # walk is entered only with dicts: the model validates both schemas, and
    # recursion below descends only into property schemas that are dicts.
    def walk(schema: dict[str, Any], path: str, pointer: str) -> None:
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            return
        for property_name, property_schema in properties.items():
            property_path = f"{path}.properties.{property_name}"
            property_pointer = f"{pointer}/properties/{pointer_token(property_name)}"
            if not isinstance(property_schema, dict):
                continue
            description = property_schema.get("description")
            if not isinstance(description, str) or not description.strip():
                failures.append({"tool": tool.name, "path": property_path, "_pointer": property_pointer})
            walk(property_schema, property_path, property_pointer)

    walk(schema, "$", root)
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
        undocumented_properties: list[dict[str, Any]] = [
            {**failure, "_entity_index": index}
            for index, tool in enumerate(tools)
            for failure in _undocumented_properties(tool, tool.input_schema, "/inputSchema")
        ]
        passed = not undocumented_properties
        message = (
            "✅ All statically reachable tool inputs are documented"
            if passed
            else f"❌ Number of undocumented tool input properties: {len(undocumented_properties)}"
        )
        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"undocumented_properties": _legacy_locations(undocumented_properties)},
            suggested_fix=(
                "Add a description to each reported input property explaining its purpose, expected "
                "format and important constraints. This check covers direct properties chains only."
            ),
            recommendation=True,
            issues=(
                field_issue(
                    "tool",
                    failure["_entity_index"],
                    failure["_pointer"] + "/description",
                    "missing_property_description",
                    "a nonblank property description",
                )
                for failure in undocumented_properties
            ),
        )


@register_rule
class ToolsOutputPropertiesDocumentedRule(ToolsBaseRule):
    """Low check: Encourage descriptions for statically reachable output properties."""

    rule_id = "tools_output_properties_documented"
    # Quality recommendation, not a spec mandate, like the input rule: an agent
    # reads an undocumented result field without an error and has to guess its meaning.
    basis = "MCP 2026-07-28 Tools §Tool (outputSchema; property descriptions per the spec's examples)"
    min_spec_version = "2025-06-18"
    rule_order = 22

    @property
    def rule_name(self) -> str:
        return "Tools - Output properties should be documented"

    @property
    def severity(self) -> RuleSeverity:
        # LOW: only servers that publish an outputSchema are judged, so a heavier
        # penalty would reward dropping the schema instead of describing it.
        return RuleSeverity.LOW

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip unless at least one tool declares an ``outputSchema``."""
        reason = super().skip_reason(audit_data)
        if reason is not None:
            return reason
        if not any(isinstance(tool.output_schema, dict) for tool in audit_data.tools or []):
            return SKIP_REASON_NOT_APPLICABLE
        return None

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Find statically reachable output properties without descriptions."""
        undocumented_properties: list[dict[str, Any]] = [
            {**failure, "_entity_index": index}
            for index, tool in enumerate(tools)
            if isinstance(tool.output_schema, dict)
            for failure in _undocumented_properties(tool, tool.output_schema, "/outputSchema")
        ]
        passed = not undocumented_properties
        message = (
            "✅ All statically reachable tool outputs are documented"
            if passed
            else f"❌ Number of undocumented tool output properties: {len(undocumented_properties)}"
        )
        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"undocumented_properties": _legacy_locations(undocumented_properties)},
            suggested_fix=(
                "Add a description to each reported output property saying what the field means, not a "
                "sample value. This check covers direct properties chains only."
            ),
            recommendation=True,
            issues=(
                field_issue(
                    "tool",
                    failure["_entity_index"],
                    failure["_pointer"] + "/description",
                    "missing_property_description",
                    "a nonblank property description",
                )
                for failure in undocumented_properties
            ),
        )


# Keywords whose values are subschemas; data keywords (default, const, enum, examples) are not walked.
_SCHEMA_MAP_KEYWORDS = ("properties", "patternProperties", "$defs", "definitions", "dependentSchemas")
_SCHEMA_KEYWORDS = (
    "items",
    "additionalItems",
    "additionalProperties",
    "unevaluatedItems",
    "unevaluatedProperties",
    "propertyNames",
    "contains",
    "not",
    "if",
    "then",
    "else",
)
_SCHEMA_LIST_KEYWORDS = ("allOf", "anyOf", "oneOf", "prefixItems")
_MAX_SCHEMA_DEPTH = 64


def _subschemas(schema: dict[str, Any], pointer: str, depth: int = 0) -> Iterator[tuple[dict[str, Any], str]]:
    """Yield *schema* and every nested subschema with its JSON pointer, to a bounded depth."""
    yield schema, pointer
    if depth >= _MAX_SCHEMA_DEPTH:
        return
    for keyword in _SCHEMA_MAP_KEYWORDS:
        children = schema.get(keyword)
        if isinstance(children, dict):
            for name, child in children.items():
                if isinstance(child, dict):
                    yield from _subschemas(child, f"{pointer}/{keyword}/{pointer_token(str(name))}", depth + 1)
    for keyword in _SCHEMA_KEYWORDS:
        child = schema.get(keyword)
        if isinstance(child, dict):
            yield from _subschemas(child, f"{pointer}/{keyword}", depth + 1)
    for keyword in _SCHEMA_LIST_KEYWORDS:
        children = schema.get(keyword)
        if isinstance(children, list):
            for index, child in enumerate(children):
                if isinstance(child, dict):
                    yield from _subschemas(child, f"{pointer}/{keyword}/{index}", depth + 1)


def _nesting_exceeds(value: Any, limit: int) -> bool:
    """Return whether JSON *value* nests deeper than *limit*, without recursing."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
        for child in children:
            if isinstance(child, (dict, list)):
                if depth + 1 > limit:
                    return True
                stack.append((child, depth + 1))
    return False


def _has_default(tool: Tool) -> bool:
    return any("default" in subschema for subschema, _ in _subschemas(tool.input_schema, ""))


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    return "array" if isinstance(value, list) else "object"


def _invalid_defaults(tool: Tool) -> list[dict[str, Any]]:
    """Find input-schema defaults that fail the subschema declaring them.

    Schemas in an unknown ``$schema`` dialect, invalid in their own dialect, or
    nested too deeply to validate are left unjudged. ``$ref`` resolves within the tool's
    schema only: an empty registry keeps remote references unresolved, never fetched.
    """
    schema = tool.input_schema
    # jsonschema validates recursively; a schema this deep would exhaust Python's stack.
    if _nesting_exceeds(schema, _MAX_SCHEMA_DEPTH * 2):
        return []
    dialect = schema.get("$schema")
    if dialect is None:
        validator_class = Draft202012Validator
    elif isinstance(dialect, str):
        # validator_for falls back to the default for an unknown URI; only a known dialect is judged.
        validator_class = validator_for(schema, default=Draft202012Validator)
        if str(validator_class.META_SCHEMA.get("$schema")).rstrip("#") != dialect.rstrip("#"):
            return []
    else:
        return []
    try:
        validator_class.check_schema(schema)
    except SchemaError:
        return []
    validator = validator_class(schema, registry=Registry())
    failures: list[dict[str, Any]] = []
    for subschema, pointer in _subschemas(schema, ""):
        if "default" not in subschema:
            continue
        default = subschema["default"]
        try:
            valid = validator.evolve(schema=subschema).is_valid(default)
        except Unresolvable:
            continue
        if not valid:
            failure: dict[str, Any] = {"tool": tool.name, "path": pointer or "/", "default_type": _json_type(default)}
            declared = subschema.get("type")
            if isinstance(declared, str) or (
                isinstance(declared, list) and all(isinstance(item, str) for item in declared)
            ):
                failure["declared_type"] = declared
            failures.append({**failure, "_pointer": "/inputSchema" + pointer})
    return failures


@register_rule
class ToolsInputDefaultsValidRule(ToolsBaseRule):
    """Medium check: Each input default must be valid against the schema declaring it."""

    rule_id = "tools_input_defaults_valid"
    basis = (
        "JSON Schema 2020-12 Validation §9.2 (default SHOULD be valid against its schema); "
        "MCP 2025-11-25 Tools §Tool (inputSchema is a JSON Schema, 2020-12 default)"
    )
    rule_order = 23

    @property
    def rule_name(self) -> str:
        return "Tools - Input defaults should match their own schema"

    @property
    def severity(self) -> RuleSeverity:
        # MEDIUM: a client that sends the advertised default gets a validation error.
        return RuleSeverity.MEDIUM

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip unless at least one tool's input schema declares a ``default``."""
        reason = super().skip_reason(audit_data)
        if reason is not None:
            return reason
        if not any(_has_default(tool) for tool in audit_data.tools or []):
            return SKIP_REASON_NOT_APPLICABLE
        return None

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Find input defaults that the subschema declaring them rejects."""
        invalid_defaults: list[dict[str, Any]] = [
            {**failure, "_entity_index": index}
            for index, tool in enumerate(tools)
            for failure in _invalid_defaults(tool)
        ]
        passed = not invalid_defaults
        message = (
            "✅ All tool input defaults are valid against their own schema"
            if passed
            else f"❌ Number of tool input defaults their own schema rejects: {len(invalid_defaults)}"
        )
        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"invalid_defaults": _legacy_locations(invalid_defaults)},
            suggested_fix=(
                "Make each reported default valid for its field, or remove it: a client that sends the "
                "advertised default gets a validation error. In Python, type an optional parameter as "
                "`T | None`; in Zod, add `.nullable()` or drop the default."
            ),
            recommendation=True,
            issues=(
                field_issue(
                    "tool",
                    failure["_entity_index"],
                    failure["_pointer"] + "/default",
                    "invalid_default",
                    "a default valid against its own schema",
                )
                for failure in invalid_defaults
            ),
        )


def _mcp_header_result(
    rule: BaseRule,
    failures: list[dict[str, Any]],
    details_key: str,
    pass_message: str,
    failure_label: str,
    *,
    suggested_fix: str,
    expected: str,
    reason: str,
    field: str = "x-mcp-header",
) -> RuleResult:
    """Build a consistent result for an x-mcp-header rule."""
    passed = not failures
    message = f"✅ {pass_message}" if passed else f"❌ Number of {failure_label}: {len(failures)}"
    return catalog_result(
        rule_name=rule.rule_name,
        severity=rule.severity,
        passed=passed,
        message=message,
        details={details_key: _legacy_locations(failures)},
        suggested_fix=suggested_fix,
        issues=(
            field_issue("tool", failure["_entity_index"], failure["_pointer"] + "/" + field, reason, expected)
            for failure in failures
        ),
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
            "✅ All tools declare behavior annotations"
            if passed
            else f"❌ Number of tools without behavior annotations: {len(tools_without_annotations)}"
        )

        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"tools_without_annotations": tools_without_annotations},
            suggested_fix=(
                "Declare behavior annotations that match the tool's actual effects. Set readOnlyHint "
                "to true only if the tool cannot change state."
            ),
            issues=fields(
                tools,
                "tool",
                "/annotations",
                "missing_behavior_annotation",
                "at least one behavior annotation reflecting actual effects",
                lambda tool: not _has_behavior_annotation(tool),
            ),
            recommendation=True,
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
        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"invalid_icons": invalid_icons},
            suggested_fix=(
                "Correct each reported icon field: use an absolute src URI (a base64 image for data "
                "URIs), a valid MIME type when supplied, and sizes such as 48x48 or any."
            ),
            issues=icon_issues(tools, "tool"),
            recommendation=False,
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

        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"task_tools": task_tools, "tasks_capability": has_tasks_capability},
            suggested_fix=(
                "Implement and declare tasks support for task-augmented tools, or remove their "
                "task-execution declarations if task execution is not implemented."
            ),
            issues=fields(
                tools or [],
                "tool",
                "/execution/taskSupport",
                "undeclared_task_support",
                "a matching tasks capability",
                lambda tool: tool.execution is not None and tool.execution.task_support in ("optional", "required"),
            ),
            recommendation=False,
        )


def _legacy_locations(failures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep exact private locations out of the legacy evidence dictionaries."""
    return [
        {key: value for key, value in failure.items() if key not in {"_pointer", "_entity_index"}}
        for failure in failures
    ]


_ANNOTATIONS_BASIS = "MCP 2025-11-25 Schema Reference §ToolAnnotations; Tools §Tool (annotations)"


def _hint(tool: Tool, hint: str) -> bool | None:
    return getattr(tool.annotations, hint, None) if tool.annotations is not None else None


class _AnnotationConsistencyRule(ToolsBaseRule):
    """Base for rules that compare a tool's declared hints with what it says it does.

    Each rule judges only the tools in its scope and skips a catalog without any.
    """

    basis = _ANNOTATIONS_BASIS

    @abstractmethod
    def _in_scope(self, tool: Tool) -> bool:
        """Whether this rule has anything to judge on ``tool``."""

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when no tool in the catalog is in this rule's scope."""
        if reason := super().skip_reason(audit_data):
            return reason
        if not any(self._in_scope(tool) for tool in audit_data.tools or []):
            return SKIP_REASON_NOT_APPLICABLE
        return None


@register_rule
class ToolsAnnotationsDestructiveDeclaredRule(_AnnotationConsistencyRule):
    """High check: a tool that says it deletes must not declare itself read-only or non-destructive.

    Clients may skip confirmation for a tool declared read-only or non-destructive. A delete tool that
    declares either misleads that consent decision in the dangerous direction.
    """

    rule_id = "tools_annotations_destructive_declared"
    rule_order = 18

    @property
    def rule_name(self) -> str:
        return "Tools - Delete tools must not be declared read-only or non-destructive"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _in_scope(self, tool: Tool) -> bool:
        return tool_intent(tool) is ToolIntent.DESTRUCTIVE

    @staticmethod
    def _understated(tool: Tool) -> bool:
        return _hint(tool, "read_only_hint") is True or _hint(tool, "destructive_hint") is False

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """High check: Verify that no delete tool declares readOnlyHint true or destructiveHint false.

        Args:
            tools: The tools to validate
        Returns:
            RuleResult with the check outcome

        """
        understated = [tool.name for tool in tools if self._in_scope(tool) and self._understated(tool)]
        passed = not understated
        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=(
                "✅ Every delete tool is declared as one"
                if passed
                else f"❌ Delete tools declared read-only or non-destructive: {len(understated)}"
            ),
            details={"understated_tools": understated},
            suggested_fix=(
                "For a tool that deletes, set readOnlyHint to false and destructiveHint to true (or omit "
                "destructiveHint, which defaults to true), so clients ask before calling it."
            ),
            issues=fields(
                tools,
                "tool",
                "/annotations",
                "destructive_tool_declared_safe",
                "readOnlyHint false and destructiveHint true for a tool that deletes",
                lambda tool: self._in_scope(tool) and self._understated(tool),
            ),
        )


@register_rule
class ToolsAnnotationsReadOnlyDeclaredRule(_AnnotationConsistencyRule):
    """Low check: an annotated tool that only reads should declare readOnlyHint.

    readOnlyHint defaults to false, so a reading tool that declares other hints but omits it is
    treated as one that changes state, and clients ask for confirmation they do not need.
    """

    rule_id = "tools_annotations_read_only_declared"
    rule_order = 19

    @property
    def rule_name(self) -> str:
        return "Tools - Annotated read tools should declare readOnlyHint"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def _in_scope(self, tool: Tool) -> bool:
        return _has_behavior_annotation(tool) and tool_intent(tool) is ToolIntent.READ

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Low check: Verify that annotated read tools declare readOnlyHint.

        Args:
            tools: The tools to validate
        Returns:
            RuleResult with the check outcome

        """
        undeclared = [tool.name for tool in tools if self._in_scope(tool) and _hint(tool, "read_only_hint") is None]
        passed = not undeclared
        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=(
                "✅ Every annotated read tool declares readOnlyHint"
                if passed
                else f"❌ Annotated read tools without readOnlyHint: {len(undeclared)}"
            ),
            details={"tools_without_read_only_hint": undeclared},
            suggested_fix=(
                "Set readOnlyHint to true on tools that only read. Leave it false for a tool that also "
                "changes state, for example one that charges, creates a key or saves a result."
            ),
            issues=fields(
                tools,
                "tool",
                "/annotations/readOnlyHint",
                "read_tool_without_read_only_hint",
                "readOnlyHint declared for a tool that only reads",
                lambda tool: self._in_scope(tool) and _hint(tool, "read_only_hint") is None,
            ),
            recommendation=True,
        )


@register_rule
class ToolsAnnotationsHintsConsistentRule(_AnnotationConsistencyRule):
    """Low check: a read-only tool should not also declare destructiveHint true.

    destructiveHint is meaningful only when readOnlyHint is false, so declaring both says two
    opposite things about the same tool.
    """

    rule_id = "tools_annotations_hints_consistent"
    rule_order = 20

    @property
    def rule_name(self) -> str:
        return "Tools - Read-only tools should not declare destructiveHint true"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def _in_scope(self, tool: Tool) -> bool:
        return _hint(tool, "read_only_hint") is True

    def _check_tools(self, tools: list[Tool]) -> RuleResult:
        """Low check: Verify that no read-only tool declares destructiveHint true.

        Args:
            tools: The tools to validate
        Returns:
            RuleResult with the check outcome

        """
        contradictory = [
            tool.name for tool in tools if self._in_scope(tool) and _hint(tool, "destructive_hint") is True
        ]
        passed = not contradictory
        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=(
                "✅ No read-only tool declares destructiveHint true"
                if passed
                else f"❌ Read-only tools that also declare destructiveHint true: {len(contradictory)}"
            ),
            details={"contradictory_tools": contradictory},
            suggested_fix=(
                "Decide whether the tool changes state. If it only reads, drop destructiveHint. If it "
                "can delete or overwrite, set readOnlyHint to false."
            ),
            issues=fields(
                tools,
                "tool",
                "/annotations/destructiveHint",
                "read_only_tool_declared_destructive",
                "no destructiveHint true on a read-only tool",
                lambda tool: self._in_scope(tool) and _hint(tool, "destructive_hint") is True,
            ),
            recommendation=True,
        )
