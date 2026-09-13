"""Exercise catalog repair guidance through public rule checks and wire locations."""

from copy import deepcopy
import json
from typing import Any

from mcp_types import (
    Annotations,
    Icon,
    Implementation,
    Prompt,
    PromptArgument,
    Resource,
    ResourceTemplate,
    ServerCapabilities,
    Tool,
    ToolAnnotations,
    ToolExecution,
)
import pytest

from mcpscore.rules.base import AuditData
from mcpscore.rules.registry import create_all_rules

RULES = {rule.rule_id: rule for rule in create_all_rules()}
PHASE2_GROUPS = {"tools", "resources", "resource_templates", "prompts", "server_info", "capabilities"}


def tool(**kwargs: Any) -> Tool:
    return Tool(**{"name": "search", "input_schema": {"type": "object"}, **kwargs})


def failure_cases() -> list[tuple[str, AuditData, str, str]]:
    """Supply independently chosen failures and a concrete repair action per rule."""
    cases: list[tuple[str, AuditData, str, str]] = []
    tool_cases = [
        ("at_least_one", [], "/tools", "Resources-only"),
        ("name_present_in_all", [tool(name="")], "/name", "non-empty"),
        ("names_unique", [tool(), tool()], "/name", "distinct name"),
        ("names_valid_format", [tool(name="search customers")], "/name", "1-128"),
        ("title_present_in_all", [tool()], "/title", "title"),
        ("description_present_in_all", [tool(description=" \t")], "/description", "when to use"),
        ("input_schema_valid", [tool(input_schema={"type": "bad"})], "/inputSchema/type", "inputSchema"),
        ("output_schema_valid", [tool(output_schema={"type": "bad"})], "/outputSchema/type", "outputSchema"),
        (
            "output_schema_root_object",
            [tool(output_schema={"type": "array"})],
            "/outputSchema/type",
            "structuredContent",
        ),
        ("annotations_present", [tool()], "/annotations", "actual effects"),
        (
            "execution_consistent",
            [tool(execution=ToolExecution(task_support="required"))],
            "/execution/taskSupport",
            "or remove",
        ),
        (
            "input_properties_documented",
            [tool(input_schema={"type": "object", "properties": {"q": {"type": "string"}}})],
            "/inputSchema/properties/q/description",
            "expected format",
        ),
    ]
    for suffix, tools, path, action in tool_cases:
        cases.append((f"tools_{suffix}", AuditData(tools=tools, capabilities=ServerCapabilities()), path, action))
    for suffix, schema, path, action in [
        (
            "valid_names",
            {"properties": {"q": {"type": "string", "x-mcp-header": "bad header"}}},
            "/inputSchema/properties/q/x-mcp-header",
            "Region",
        ),
        (
            "unique",
            {
                "properties": {
                    "a": {"type": "string", "x-mcp-header": "Q"},
                    "b": {"type": "string", "x-mcp-header": "q"},
                }
            },
            "/inputSchema/properties/a/x-mcp-header",
            "ignoring letter case",
        ),
        (
            "primitive_types",
            {"properties": {"q": {"type": "number", "x-mcp-header": "Q"}}},
            "/inputSchema/properties/q/type",
            "do not change",
        ),
        (
            "statically_reachable",
            {"anyOf": [{"properties": {"q": {"type": "string", "x-mcp-header": "Q"}}}]},
            "/inputSchema/anyOf/0/properties/q/x-mcp-header",
            "direct properties",
        ),
        (
            "not_sensitive",
            {"properties": {"password": {"type": "string", "x-mcp-header": "Q"}}},
            "/inputSchema/properties/password/x-mcp-header",
            "renaming",
        ),
    ]:
        cases.append((f"tools_mcp_headers_{suffix}", AuditData(tools=[tool(input_schema=schema)]), path, action))
    for group, factory, base, entries in [
        (
            "resources",
            Resource,
            {"name": "report", "uri": "file:///report"},
            [
                ("uris_valid", {"uri": "relative"}, "/uri", "absolute URI"),
                ("sizes_valid", {"size": -1}, "/size", "bytes"),
                ("uris_unique", {}, "/uri", "once"),
            ],
        ),
        (
            "resource_templates",
            ResourceTemplate,
            {"name": "report", "uri_template": "file:///reports/{id}"},
            [
                ("uri_templates_valid", {"uri_template": "file:///{"}, "/uriTemplate", "balanced braces"),
                ("unique", {}, "/uriTemplate", "once"),
            ],
        ),
    ]:
        entries += [
            ("names_present", {"name": " \t"}, "/name", "nonblank"),
            ("mime_types_valid", {"mime_type": "bad"}, "/mimeType", "application/json"),
            (
                "annotations_valid",
                {"annotations": Annotations(last_modified="yesterday")},
                "/annotations/lastModified",
                "ISO 8601",
            ),
            ("description_present", {}, "/description", "intended use"),
            ("titles_present", {}, "/title", "title"),
        ]
        for suffix, updates, path, action in entries:
            item = factory(**{**base, **updates})
            items = [item, deepcopy(item)] if suffix.endswith("unique") else [item]
            cases.append((f"{group}_{suffix}", AuditData(**{group: items}), path, action))
    for suffix, prompts, path, action in [
        ("names_unique", [Prompt(name="review"), Prompt(name="review")], "/name", "distinct name"),
        ("titles_present", [Prompt(name="review")], "/title", "title"),
        ("description_present", [Prompt(name="review")], "/description", "intended use"),
        (
            "argument_names_unique",
            [Prompt(name="review", arguments=[PromptArgument(name="q"), PromptArgument(name="q")])],
            "/arguments/0/name",
            "distinct name",
        ),
        (
            "argument_names_present",
            [Prompt(name="review", arguments=[PromptArgument(name="")])],
            "/arguments/0/name",
            "nonblank",
        ),
        (
            "arguments_documented",
            [Prompt(name="review", arguments=[PromptArgument(name="q")])],
            "/arguments/0/description",
            "expected format",
        ),
    ]:
        cases.append((f"prompts_{suffix}", AuditData(prompts=prompts), path, action))
    for group, item in [
        ("tools", tool(icons=[Icon(src="relative")])),
        ("resources", Resource(name="r", uri="file:///r", icons=[Icon(src="relative")])),
        ("resource_templates", ResourceTemplate(name="r", uri_template="file:///{id}", icons=[Icon(src="relative")])),
        ("prompts", Prompt(name="p", icons=[Icon(src="relative")])),
    ]:
        cases.append((f"{group}_icons_valid", AuditData(**{group: [item]}), "/icons/0/src", "absolute src URI"))
    for suffix, info, path, action in [
        ("name_present", Implementation(name="", version="1"), "/serverInfo/name", "non-empty"),
        ("version_present", Implementation(name="s", version=""), "/serverInfo/version", "implementation version"),
        ("title_present", Implementation(name="s", version="1"), "/serverInfo/title", "human-readable"),
        ("websiteurl_present", Implementation(name="s", version="1"), "/serverInfo/websiteUrl", "documentation"),
        ("icons_present", Implementation(name="s", version="1"), "/serverInfo/icons", "Consider"),
    ]:
        cases.append((f"server_{suffix}", AuditData(server_info=info), path, action))
    cases.append(("server_instructions_present", AuditData(instructions=None), "/instructions", "limitations"))
    for feature in ["tools", "resources", "prompts"]:
        caps = ServerCapabilities.model_validate({feature: {}})
        cases.append(
            (
                f"capability_{feature}_list_changed",
                AuditData(capabilities=caps),
                f"/capabilities/{feature}/listChanged",
                "implement",
            )
        )
        cases.append(
            (
                f"capability_{feature}_present",
                AuditData(capabilities=ServerCapabilities(), **{feature: []}),
                f"/capabilities/{feature}",
                "Declare",
            )
        )
    return cases


@pytest.mark.parametrize(
    ("rule_id", "data", "path", "action"), failure_cases(), ids=lambda v: v if isinstance(v, str) else None
)
def test_failure_has_specific_repair_and_location(rule_id: str, data: AuditData, path: str, action: str) -> None:
    result = RULES[rule_id].check(data)
    assert not result.passed
    assert result.suggested_fix is not None
    assert 0 < len(result.suggested_fix) <= 255
    assert action in result.suggested_fix
    assert result.details is not None
    assert result.details["issues"][0]["path"] == path
    assert result.details["issues"][0]["expected"]
    assert result.details["issues_total"] >= 1
    wire = result.to_dict()
    assert json.loads(json.dumps(wire))["suggested_fix"] == result.suggested_fix


def test_failure_inventory_covers_every_phase2_rule() -> None:
    assert {case[0] for case in failure_cases()} == {
        key for key, rule in RULES.items() if rule.group_name in PHASE2_GROUPS
    }


def passing_data() -> AuditData:
    return AuditData(
        tools=[tool(title="Search", description="Find reports.", annotations=ToolAnnotations(read_only_hint=True))],
        resources=[Resource(name="r", uri="file:///r", title="Report", description="A report.")],
        resource_templates=[
            ResourceTemplate(name="r", uri_template="file:///{id}", title="Reports", description="Reports by ID.")
        ],
        prompts=[Prompt(name="review", title="Review", description="Review a report.")],
        server_info=Implementation(
            name="s",
            version="1",
            title="Server",
            website_url="https://example.com",
            icons=[Icon(src="https://example.com/icon.png")],
        ),
        instructions="Use search to find reports.",
        capabilities=ServerCapabilities.model_validate(
            {feature: {"listChanged": True} for feature in ["tools", "resources", "prompts"]}
        ),
    )


@pytest.mark.parametrize("rule_id", [key for key, rule in RULES.items() if rule.group_name in PHASE2_GROUPS])
def test_passing_findings_omit_repairs_and_new_failure_evidence(rule_id: str) -> None:
    result = RULES[rule_id].check(passing_data())
    assert result.passed
    assert "suggested_fix" not in result.to_dict()
    assert "issues" not in (result.details or {}) or result.details["issues"] == []


def test_blank_and_duplicate_names_keep_distinct_indexes_and_bound_evidence() -> None:
    result = RULES["tools_names_unique"].check(AuditData(tools=[tool(name="\n" * 500)] * 25))
    assert not result.passed
    assert result.details["issues_total"] == 25
    assert result.details["issues_omitted"] == 5
    assert [issue["entity_index"] for issue in result.details["issues"]] == list(range(20))
    assert "\n" not in result.message
    assert len(result.message) < 350
    assert all("name" not in issue and "actual" not in issue for issue in result.details["issues"])


@pytest.mark.parametrize(
    ("rule_id", "field"),
    [
        ("tools_input_properties_documented", "description"),
        ("tools_mcp_headers_valid_names", "x-mcp-header"),
        ("tools_mcp_headers_not_sensitive", "x-mcp-header"),
    ],
)
def test_paths_resolve_literal_property_names_and_terminal_message_is_single_line(rule_id: str, field: str) -> None:
    name = 'a.b/~\n"\\'
    schema = {
        "type": "object",
        "properties": {name: {"type": "string", "x-mcp-header": "bad header", "title": "password"}},
    }
    result = RULES[rule_id].check(AuditData(tools=[tool(input_schema=schema)]))
    path = result.details["issues"][0]["path"]
    assert path == '/inputSchema/properties/a.b~1~0\n"\\/' + field
    node = {"inputSchema": schema}
    for token in path.split("/")[1:-1]:
        node = node[token.replace("~1", "/").replace("~0", "~")]
    assert node is schema["properties"][name]
    assert "\n" not in result.message
    assert "\\n" in result.message


def test_overlong_path_is_omitted_without_losing_owner_index() -> None:
    schema = {"type": "object", "properties": {"x" * 300: {"type": "string"}}}
    result = RULES["tools_input_properties_documented"].check(AuditData(tools=[tool(input_schema=schema)]))
    issue = result.details["issues"][0]
    assert issue["path_omitted"] is True
    assert "path" not in issue
    assert issue["entity_index"] == 0


def test_icons_keep_owner_and_icon_indexes_without_uri_payloads() -> None:
    bad = Icon(src="data:image/png;base64,SECRET", mime_type="bad", sizes=["0x4"])
    result = RULES["resources_icons_valid"].check(
        AuditData(
            resources=[
                Resource(name="same", uri="https://user:SECRET@example.com/?token=SECRET"),
                Resource(
                    name="same",
                    uri="https://user:SECRET@example.com/?token=SECRET",
                    icons=[Icon(src="https://example.com/ok"), bad],
                ),
            ]
        )
    )
    issues = result.details["issues"]
    assert [issue["path"] for issue in issues] == ["/icons/1/src", "/icons/1/mimeType", "/icons/1/sizes"]
    assert all(issue["entity_index"] == 1 for issue in issues)
    assert "SECRET" not in json.dumps(issues)
    assert "SECRET" not in result.message
    assert "SECRET" not in result.suggested_fix


def test_server_icons_distinguish_optional_absence_from_prefix_failure() -> None:
    rule = RULES["server_icons_present"]
    absent = rule.check(AuditData(server_info=Implementation(name="s", version="1")))
    invalid = rule.check(AuditData(server_info=Implementation(name="s", version="1", icons=[Icon(src="relative")])))
    assert "optional quality recommendation" in absent.message
    assert "optional quality recommendation" not in invalid.message
    assert absent.suggested_fix != invalid.suggested_fix
    assert invalid.details["issues"][0]["path"] == "/serverInfo/icons/0/src"
    # Preserve the existing prefix-only predicate; do not claim URI validation.
    prefix_only = rule.check(AuditData(server_info=Implementation(name="s", version="1", icons=[Icon(src="https://")])))
    assert prefix_only.passed
    assert "content not checked" in prefix_only.message


def test_optional_guidance_does_not_invent_support() -> None:
    result = RULES["capability_tools_list_changed"].check(
        AuditData(capabilities=ServerCapabilities.model_validate({"tools": {}}))
    )
    assert "optional quality recommendation" in result.message
    assert "static catalog" in result.suggested_fix
    assert "implement" in result.suggested_fix
    assert "notifications not tested" in RULES["capability_tools_list_changed"].check(passing_data()).message


def test_duplicate_tool_names_do_not_change_existing_header_uniqueness_verdict() -> None:
    schema = {"properties": {"q": {"type": "string", "x-mcp-header": "Q"}}}
    result = RULES["tools_mcp_headers_unique"].check(
        AuditData(tools=[tool(input_schema=schema), tool(input_schema=schema)])
    )
    # Existing grouping by tool name is a separate correctness concern.
    assert not result.passed
    assert [issue["entity_index"] for issue in result.details["issues"]] == [0, 1]
    assert "separate tools with the same name" in result.suggested_fix


@pytest.mark.parametrize(
    ("rule_id", "label"),
    [
        ("tools_name_present_in_all", "Tool index 0"),
        ("resources_names_present", "Resource index 0"),
        ("resource_templates_names_present", "Resource template index 0"),
        ("prompts_arguments_documented", "Prompt index 0"),
        ("server_name_present", "Server"),
        ("tools_at_least_one", "Catalog"),
    ],
)
def test_cli_labels_the_actual_entity_kind(rule_id: str, label: str, caplog: pytest.LogCaptureFixture) -> None:
    from mcpscore.mcp_auditor import MCPAuditor

    data = next(data for key, data, _, _ in failure_cases() if key == rule_id)
    result = RULES[rule_id].check(data)
    with caplog.at_level("INFO", logger="mcpscore"):
        MCPAuditor._log_guidance(result)
    assert f"{label} · " in caplog.text
    assert "index None" not in caplog.text
