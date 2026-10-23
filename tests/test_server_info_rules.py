from dataclasses import replace
from typing import Any

from mcp_types import (
    Prompt,
    PromptsCapability,
    Resource,
    ResourcesCapability,
    ResourceTemplate,
    ServerCapabilities,
    Tool,
    ToolsCapability,
)
import pytest

from mcpscore.probes import (
    PROBE_DISCOVER,
    PROBE_PROMPTS_CATALOG_CONNECTION_INDEPENDENT,
    PROBE_RESOURCES_CATALOG_CONNECTION_INDEPENDENT,
    PROBE_STATELESS_LIST,
    PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT,
    ProbeOutcome,
    ProbeResult,
)
from mcpscore.rules import (
    AuditData,
    RuleSeverity,
    ServerExposesPrimitiveRule,
    ServerIconsPresentRule,
    ServerInstructionsPresentRule,
    ServerNamePresentRule,
    ServerTitlePresentRule,
    ServerVersionPresentRule,
    ServerWebsiteUrlPresentRule,
)
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA
from mcpscore.skills import SkillsEvidence


def test_server_name_present_rule(implementation_full, implementation_missing):
    rule = ServerNamePresentRule()
    assert rule.check(AuditData(server_info=implementation_full)).passed
    assert not rule.check(AuditData(server_info=implementation_missing)).passed


def test_server_title_present_rule(implementation_full, implementation_missing):
    rule = ServerTitlePresentRule()
    assert rule.check(AuditData(server_info=implementation_full)).passed
    assert not rule.check(AuditData(server_info=implementation_missing)).passed


def test_server_version_present_rule(implementation_full, implementation_missing):
    rule = ServerVersionPresentRule()
    assert rule.check(AuditData(server_info=implementation_full)).passed
    assert not rule.check(AuditData(server_info=implementation_missing)).passed


def test_server_instructions_present_rule():
    rule = ServerInstructionsPresentRule()
    assert rule.rule_id == "server_instructions_present"
    assert rule.severity == RuleSeverity.LOW
    assert rule.check(AuditData(instructions="Use tool X to do Y.")).passed
    # Missing, empty, and whitespace-only instructions all fail.
    assert not rule.check(AuditData(instructions=None)).passed
    assert not rule.check(AuditData(instructions="")).passed
    assert not rule.check(AuditData(instructions="   ")).passed


def test_server_websiteurl_present_rule(implementation_full, implementation_missing):
    rule = ServerWebsiteUrlPresentRule()
    assert rule.rule_id == "server_websiteurl_present"
    assert rule.min_spec_version == "2025-11-25"
    with_url = replace(implementation_full, website_url="https://server.example")
    assert rule.check(AuditData(server_info=with_url)).passed
    assert not rule.check(AuditData(server_info=implementation_full)).passed
    assert not rule.check(AuditData(server_info=implementation_missing)).passed


def test_server_icons_present_rule(implementation_full, implementation_missing):
    from mcp_types import Icon

    rule = ServerIconsPresentRule()
    assert rule.rule_id == "server_icons_present"
    assert rule.min_spec_version == "2025-11-25"

    valid = replace(implementation_full, icons=[Icon(src="https://server.example/icon.png")])
    assert rule.check(AuditData(server_info=valid)).passed

    data_uri = replace(implementation_full, icons=[Icon(src="data:image/png;base64,AAAA")])
    assert rule.check(AuditData(server_info=data_uri)).passed

    # No icons at all fails.
    no_icons = rule.check(AuditData(server_info=implementation_missing))
    assert not no_icons.passed
    assert "icons is absent or empty" in no_icons.message

    # A plain-http src is not a valid icon source.
    invalid = replace(implementation_full, icons=[Icon(src="http://server.example/icon.png")])
    result = rule.check(AuditData(server_info=invalid))
    assert not result.passed
    assert result.details is not None
    assert result.details["invalid_srcs"] == ["http://server.example/icon.png"]


SKILLS = {"io.modelcontextprotocol/skills": {}}
ALL_CAPABILITIES = ServerCapabilities(
    tools=ToolsCapability(), resources=ResourcesCapability(), prompts=PromptsCapability(), extensions=SKILLS
)
SESSION = "2025-11-25"
EMPTY_LISTINGS: dict[str, Any] = {
    "tools": [],
    "resources": [],
    "resource_templates": [],
    "prompts": [],
    "session_protocol_version": SESSION,
}
TOOL = Tool(name="search", input_schema={"type": "object"})


def skills(entries: list[Any] | None, **fields: Any) -> SkillsEvidence:
    return SkillsEvidence(entries=entries, **fields)


def judge(data: AuditData) -> bool | str:
    """Return the rule's skip reason, or whether it passed."""
    rule = ServerExposesPrimitiveRule()
    reason = rule.skip_reason(data)
    return reason if reason is not None else rule.check(data).passed


def test_server_exposes_primitive_metadata() -> None:
    rule = ServerExposesPrimitiveRule()
    assert rule.rule_id == "server_exposes_primitive"
    assert rule.severity == RuleSeverity.MEDIUM
    assert rule.group_name == "server_info"
    assert "Server Features" in (rule.basis or "")


@pytest.mark.parametrize(
    "exposed",
    [
        {"tools": [TOOL]},
        {"resources": [Resource(name="r", uri="file:///r")]},
        {"resource_templates": [ResourceTemplate(name="r", uri_template="file:///{id}")]},
        {"prompts": [Prompt(name="review")]},
        {"skills": skills([{"name": "pdf", "uri": "skill://pdf/SKILL.md"}])},
    ],
    ids=["tools", "resources", "resource_templates", "prompts", "skills"],
)
def test_any_one_primitive_passes(exposed: dict[str, Any]) -> None:
    data = AuditData(capabilities=ALL_CAPABILITIES, **{**EMPTY_LISTINGS, "skills": skills([]), **exposed})
    assert judge(data) is True


def test_skills_only_server_without_tools_capability_passes() -> None:
    data = AuditData(
        capabilities=ServerCapabilities(extensions=SKILLS),
        skills=skills([{"name": "pdf", "uri": "skill://pdf/SKILL.md"}]),
    )
    result = ServerExposesPrimitiveRule().check(data)
    assert result.passed
    assert result.details["exposed"]["skills"] == 1
    assert result.details["exposed"]["tools"] is None


def test_every_listing_empty_fails_and_names_what_was_checked() -> None:
    data = AuditData(capabilities=ALL_CAPABILITIES, **EMPTY_LISTINGS, skills=skills([]))
    rule = ServerExposesPrimitiveRule()
    assert rule.skip_reason(data) is None
    result = rule.check(data)
    assert not result.passed
    assert result.details["checked"] == ["tools", "resources", "resource_templates", "prompts", "skills"]
    assert "every listing it serves came back empty" in result.message
    assert result.details["issues"][0]["reason"] == "empty_catalog"
    assert "tool, resource, prompt or skill" in result.suggested_fix


def test_server_that_declares_nothing_fails() -> None:
    result = ServerExposesPrimitiveRule().check(AuditData(capabilities=ServerCapabilities()))
    assert not result.passed
    assert "declares no tools, resources, prompts or skills" in result.message


@pytest.mark.parametrize(
    "gap",
    [
        {"tools": None},
        {"resources": None},
        {"resource_templates": None},
        {"prompts": None},
        {"skills": None},
        {"skills": skills(None, list_error={"code": -32601})},
        {"skills": skills([], list_incomplete=True)},
        {"incomplete_listings": frozenset({"tools"})},
        {"incomplete_listings": frozenset({"resources"})},
    ],
    ids=[
        "tools-failed",
        "resources-failed",
        "templates-failed",
        "prompts-failed",
        "skills-uncollected",
        "skills-list-failed",
        "skills-list-incomplete",
        "tools-incomplete",
        "resources-incomplete",
    ],
)
def test_failed_or_incomplete_listing_with_nothing_collected_skips(gap: dict[str, Any]) -> None:
    data = AuditData(capabilities=ALL_CAPABILITIES, **{**EMPTY_LISTINGS, "skills": skills([]), **gap})
    assert judge(data) == SKIP_REASON_INSUFFICIENT_DATA


def test_undeclared_listing_never_attempted_is_not_a_gap() -> None:
    data = AuditData(
        capabilities=ServerCapabilities(tools=ToolsCapability()), tools=[], session_protocol_version=SESSION
    )
    assert judge(data) is False


def test_attempted_listing_without_a_result_is_a_gap_even_undeclared() -> None:
    data = AuditData(capabilities=ServerCapabilities(), listings_attempted=frozenset({"tools"}))
    assert judge(data) == SKIP_REASON_INSUFFICIENT_DATA


def test_collected_primitive_passes_despite_another_failed_listing() -> None:
    data = AuditData(capabilities=ALL_CAPABILITIES, tools=None, prompts=[Prompt(name="review")])
    assert judge(data) is True


def test_nonempty_incomplete_listing_proves_presence() -> None:
    data = AuditData(capabilities=ALL_CAPABILITIES, tools=[TOOL], incomplete_listings=frozenset({"tools"}))
    assert judge(data) is True


@pytest.mark.parametrize(
    "data",
    [
        AuditData(partial=True, tools=[TOOL]),
        AuditData(capabilities=None, tools=[]),
    ],
    ids=["partial-audit", "no-capabilities"],
)
def test_audit_without_session_data_skips(data: AuditData) -> None:
    assert judge(data) == SKIP_REASON_INSUFFICIENT_DATA


def test_skills_declared_only_in_discover_are_judged_on_the_stateless_lifecycle() -> None:
    capabilities = ServerCapabilities(tools=ToolsCapability())
    probes = _probes(discover={"capabilities": {"extensions": SKILLS}})
    common: dict[str, Any] = {"capabilities": capabilities, "tools": [], "session_protocol_version": SESSION}
    failed = SkillsEvidence(entries=None, stateless=True)
    assert judge(AuditData(**common, skills=failed, probes=probes)) == SKIP_REASON_INSUFFICIENT_DATA
    served = SkillsEvidence(entries=[{"name": "pdf", "uri": "skill://pdf/SKILL.md"}], stateless=True)
    assert judge(AuditData(**common, skills=served, probes=probes)) is True
    empty = SkillsEvidence(entries=[], stateless=True)
    assert judge(AuditData(**common, skills=empty, probes=probes)) is False


def _probes(**payloads: dict[str, Any]) -> dict[str, ProbeResult]:
    names = {"discover": PROBE_DISCOVER, "stateless": PROBE_STATELESS_LIST}
    return {
        names[key]: ProbeResult(names[key], ProbeOutcome.SUPPORTED, {}, payload=payload)
        for key, payload in payloads.items()
    }


def test_tools_served_only_on_the_stateless_lifecycle_count() -> None:
    probes = _probes(stateless={"tools": [{"name": "search", "inputSchema": {"type": "object"}}]})
    data = AuditData(capabilities=ServerCapabilities(), probes=probes)
    result = ServerExposesPrimitiveRule().check(data)
    assert judge(data) is True
    assert result.details["exposed"]["tools"] == 1


def test_unsupported_stateless_probe_does_not_count() -> None:
    probes = {PROBE_STATELESS_LIST: ProbeResult(PROBE_STATELESS_LIST, ProbeOutcome.UNSUPPORTED, {}, payload=None)}
    assert judge(AuditData(capabilities=ServerCapabilities(), probes=probes)) is False


@pytest.mark.parametrize(
    "discovered",
    [{"resources": {}}, {"prompts": {}}, {"tools": {}}, {"extensions": SKILLS}],
    ids=["resources", "prompts", "tools", "skills"],
)
def test_catalog_declared_only_in_discover_and_never_collected_skips(discovered: dict[str, Any]) -> None:
    data = AuditData(capabilities=ServerCapabilities(), probes=_probes(discover={"capabilities": discovered}))
    assert judge(data) == SKIP_REASON_INSUFFICIENT_DATA


@pytest.mark.parametrize(
    ("page", "expected"),
    [
        ({"tools": []}, SKIP_REASON_INSUFFICIENT_DATA),
        ({"tools": [], "resultType": "incomplete"}, SKIP_REASON_INSUFFICIENT_DATA),
        ({"tools": [], "resultType": "complete", "nextCursor": "2"}, SKIP_REASON_INSUFFICIENT_DATA),
        ({"tools": [], "resultType": "complete"}, False),
        ({"tools": [{"name": "search", "inputSchema": {"type": "object"}}]}, True),
    ],
    ids=["no-result-type", "incomplete", "more-pages", "complete", "nonempty"],
)
def test_modern_only_tools_page_must_be_whole_to_prove_emptiness(page: dict[str, Any], expected: bool | str) -> None:
    tools = [] if not page["tools"] else None
    data = AuditData(
        capabilities=ServerCapabilities(tools=ToolsCapability()),
        tools=tools,
        listings_attempted=frozenset({"tools"}),
        probes=_probes(stateless=page),
    )
    assert judge(data) == expected


@pytest.mark.parametrize(
    ("page", "attempted", "expected"),
    [
        ({"tools": [], "resultType": "complete"}, False, False),
        ({"tools": []}, False, SKIP_REASON_INSUFFICIENT_DATA),
        ({"tools": [], "resultType": "complete"}, True, SKIP_REASON_INSUFFICIENT_DATA),
    ],
    ids=["whole-empty-page", "unfinished-page", "session-listing-failed"],
)
def test_discover_declared_tools_judged_on_the_stateless_page(
    page: dict[str, Any], attempted: bool, expected: bool | str
) -> None:
    data = AuditData(
        capabilities=ServerCapabilities(),
        session_protocol_version=SESSION,
        listings_attempted=frozenset({"tools"}) if attempted else frozenset(),
        probes=_probes(discover={"capabilities": {"tools": {}}}, stateless=page),
    )
    assert judge(data) == expected


def test_whole_empty_session_listing_fails_a_legacy_server_whose_probe_page_lacks_result_type() -> None:
    data = AuditData(
        capabilities=ServerCapabilities(tools=ToolsCapability()),
        tools=[],
        session_protocol_version=SESSION,
        listings_attempted=frozenset({"tools"}),
        probes=_probes(stateless={"tools": []}),
    )
    assert judge(data) is False


def test_empty_listing_without_a_session_proves_nothing() -> None:
    data = AuditData(capabilities=ServerCapabilities(tools=ToolsCapability()), tools=[])
    assert judge(data) == SKIP_REASON_INSUFFICIENT_DATA


def test_recovered_catalog_is_judged_as_the_stateless_page() -> None:
    data = AuditData(
        capabilities=ServerCapabilities(tools=ToolsCapability()),
        tools=[],
        session_protocol_version=SESSION,
        catalog_versions={"tools": "2026-07-28"},
        probes=_probes(stateless={"tools": []}),
    )
    assert judge(data) == SKIP_REASON_INSUFFICIENT_DATA


@pytest.mark.parametrize(
    ("probe_id", "outcome"),
    [
        (PROBE_RESOURCES_CATALOG_CONNECTION_INDEPENDENT, ProbeOutcome.SUPPORTED),
        (PROBE_PROMPTS_CATALOG_CONNECTION_INDEPENDENT, ProbeOutcome.UNSUPPORTED),
        (PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT, ProbeOutcome.SUPPORTED),
    ],
    ids=["resources", "prompts-differing", "tools"],
)
def test_items_seen_by_the_catalog_connection_probes_count(probe_id: str, outcome: ProbeOutcome) -> None:
    probe = ProbeResult(probe_id, outcome, {"first_count": 0, "second_count": 2})
    data = AuditData(capabilities=ALL_CAPABILITIES, **EMPTY_LISTINGS, skills=skills([]), probes={probe_id: probe})
    assert judge(data) is True


def test_errored_catalog_connection_probe_counts_nothing() -> None:
    probe_id = PROBE_RESOURCES_CATALOG_CONNECTION_INDEPENDENT
    probe = ProbeResult(probe_id, ProbeOutcome.ERROR, {"first_count": 3})
    data = AuditData(capabilities=ALL_CAPABILITIES, **EMPTY_LISTINGS, skills=skills([]), probes={probe_id: probe})
    assert judge(data) is False


@pytest.mark.parametrize(
    ("probes", "expected"),
    [
        (_probes(discover={"capabilities": {"tools": {}}}, stateless={"tools": [], "nextCursor": "more"}), "skip"),
        (
            {
                **_probes(discover={"capabilities": {"tools": {}}}, stateless={"tools": [], "nextCursor": "more"}),
                PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT: ProbeResult(
                    PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT,
                    ProbeOutcome.SUPPORTED,
                    {"first_count": 0, "second_count": 0, "results_complete": True},
                ),
            },
            False,
        ),
        (
            {
                **_probes(discover={"capabilities": {"tools": {}}}, stateless={"tools": [], "nextCursor": "more"}),
                PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT: ProbeResult(
                    PROBE_TOOLS_CATALOG_CONNECTION_INDEPENDENT,
                    ProbeOutcome.SUPPORTED,
                    {"first_count": 0, "second_count": 0, "results_complete": False},
                ),
            },
            "skip",
        ),
        (_probes(discover={"capabilities": {"tools": {}}}, stateless={"tools": [], "resultType": "complete"}), False),
    ],
    ids=["stateless-unfinished", "connection-probe-whole", "connection-probe-unfinished", "stateless-whole"],
)
def test_dual_era_empty_session_needs_a_whole_stateless_listing(probes: dict, expected: bool | str) -> None:
    data = AuditData(
        capabilities=ServerCapabilities(tools=ToolsCapability()),
        tools=[],
        session_protocol_version=SESSION,
        listings_attempted=frozenset({"tools"}),
        probes=probes,
    )
    assert judge(data) == (SKIP_REASON_INSUFFICIENT_DATA if expected == "skip" else expected)


@pytest.mark.parametrize(
    ("session_capabilities", "expected"),
    [
        (ServerCapabilities(), SKIP_REASON_INSUFFICIENT_DATA),
        (ServerCapabilities(resources=ResourcesCapability()), SKIP_REASON_INSUFFICIENT_DATA),
    ],
    ids=["discover-only-resources", "both-declare-resources"],
)
def test_resource_templates_declared_in_discover_stay_unproven(
    session_capabilities: ServerCapabilities, expected: bool | str
) -> None:
    resources_probe = ProbeResult(
        PROBE_RESOURCES_CATALOG_CONNECTION_INDEPENDENT,
        ProbeOutcome.SUPPORTED,
        {"first_count": 0, "second_count": 0, "results_complete": True},
    )
    session_lists = session_capabilities.resources is not None
    data = AuditData(
        capabilities=session_capabilities,
        session_protocol_version=SESSION,
        resources=[] if session_lists else None,
        resource_templates=[] if session_lists else None,
        listings_attempted=frozenset({"resources", "resource_templates"}) if session_lists else frozenset(),
        probes={
            **_probes(discover={"capabilities": {"resources": {}}}),
            PROBE_RESOURCES_CATALOG_CONNECTION_INDEPENDENT: resources_probe,
        },
    )
    assert judge(data) == expected


def test_legacy_only_server_with_empty_resource_catalogs_fails() -> None:
    data = AuditData(
        capabilities=ServerCapabilities(resources=ResourcesCapability()),
        session_protocol_version=SESSION,
        resources=[],
        resource_templates=[],
        listings_attempted=frozenset({"resources", "resource_templates"}),
    )
    assert judge(data) is False


@pytest.mark.parametrize(
    ("page", "expected"),
    [
        ({"tools": [], "resultType": "incomplete"}, SKIP_REASON_INSUFFICIENT_DATA),
        ({"tools": [], "resultType": "complete", "nextCursor": "2"}, SKIP_REASON_INSUFFICIENT_DATA),
        ({"tools": []}, SKIP_REASON_INSUFFICIENT_DATA),
        ({"tools": [], "resultType": "complete"}, False),
    ],
    ids=["incomplete", "more-pages", "no-result-type", "whole"],
)
def test_undeclared_tools_page_of_a_modern_server_must_be_whole(page: dict[str, Any], expected: bool | str) -> None:
    data = AuditData(
        capabilities=ServerCapabilities(),
        session_protocol_version=SESSION,
        probes=_probes(discover={"capabilities": {}}, stateless=page),
    )
    assert judge(data) == expected


def test_undeclared_plain_tools_page_of_a_legacy_server_is_ignored() -> None:
    data = AuditData(
        capabilities=ServerCapabilities(), session_protocol_version=SESSION, probes=_probes(stateless={"tools": []})
    )
    assert judge(data) is False


@pytest.mark.parametrize(
    ("tools", "expected"),
    [
        ([None], SKIP_REASON_INSUFFICIENT_DATA),
        ([{"description": "no name"}], SKIP_REASON_INSUFFICIENT_DATA),
        ([None, {"name": "search", "inputSchema": {"type": "object"}}], True),
        ([{"name": "ghost", "inputSchema": None}], True),
    ],
    ids=["null-entry", "unnamed-entry", "one-named", "named-with-broken-schema"],
)
def test_only_named_stateless_tools_count(tools: list[Any], expected: bool | str) -> None:
    data = AuditData(
        capabilities=ServerCapabilities(tools=ToolsCapability()),
        listings_attempted=frozenset({"tools"}),
        probes=_probes(discover={"capabilities": {"tools": {}}}, stateless={"tools": tools, "resultType": "complete"}),
    )
    assert judge(data) == expected


@pytest.mark.parametrize(
    ("skills_evidence", "expected"),
    [
        (SkillsEvidence(entries=[None]), SKIP_REASON_INSUFFICIENT_DATA),
        (SkillsEvidence(entries=[{"name": "pdf"}]), SKIP_REASON_INSUFFICIENT_DATA),
        (SkillsEvidence(entries=[None, {"uri": "skill://pdf/SKILL.md"}]), True),
        (SkillsEvidence(entries=[], stateless_count=None, stateless_whole=True), SKIP_REASON_INSUFFICIENT_DATA),
        (SkillsEvidence(entries=[], stateless_count=1), True),
    ],
    ids=["session-null", "session-no-uri", "session-one-uri", "stateless-unidentified", "stateless-one"],
)
def test_only_skills_with_a_uri_count(skills_evidence: SkillsEvidence, expected: bool | str) -> None:
    data = AuditData(
        capabilities=ServerCapabilities(extensions=SKILLS),
        session_protocol_version=SESSION,
        skills=skills_evidence,
        probes=_probes(discover={"capabilities": {"extensions": SKILLS}}),
    )
    assert judge(data) == expected


@pytest.mark.parametrize(
    ("outcome", "payload", "expected"),
    [
        (ProbeOutcome.UNSUPPORTED, {"resultType": "complete"}, SKIP_REASON_INSUFFICIENT_DATA),
        (ProbeOutcome.UNSUPPORTED, None, False),
    ],
    ids=["malformed-result", "refusal"],
)
def test_modern_tools_result_without_a_tools_array_is_a_gap(
    outcome: ProbeOutcome, payload: dict[str, Any] | None, expected: bool | str
) -> None:
    probes = {
        **_probes(discover={"capabilities": {}}),
        PROBE_STATELESS_LIST: ProbeResult(PROBE_STATELESS_LIST, outcome, {}, payload=payload),
    }
    data = AuditData(capabilities=ServerCapabilities(), session_protocol_version=SESSION, probes=probes)
    assert judge(data) == expected


@pytest.mark.parametrize(
    ("listings", "expected"),
    [
        ({"tools": [Tool(name="", input_schema={"type": "object"})]}, SKIP_REASON_INSUFFICIENT_DATA),
        ({"prompts": [Prompt(name="")]}, SKIP_REASON_INSUFFICIENT_DATA),
        ({"tools": [Tool(name="", input_schema={"type": "object"}), TOOL]}, True),
    ],
    ids=["unnamed-tool", "unnamed-prompt", "one-named-tool"],
)
def test_parsed_catalog_items_count_only_with_an_identity(listings: dict[str, Any], expected: bool | str) -> None:
    data = AuditData(capabilities=ALL_CAPABILITIES, **{**EMPTY_LISTINGS, "skills": skills([]), **listings})
    assert judge(data) == expected
