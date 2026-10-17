"""Tests for the tool-annotation consistency rules and the intent reader behind them."""

from typing import Any

from mcp_types import Tool, ToolAnnotations
import pytest

from mcpscore.rules import AuditData, RuleSeverity
from mcpscore.rules.base import SKIP_REASON_NOT_APPLICABLE
from mcpscore.rules.tool_intent import ToolIntent, tool_intent
from mcpscore.rules.tools import (
    ToolsAnnotationsDestructiveDeclaredRule,
    ToolsAnnotationsHintsConsistentRule,
    ToolsAnnotationsReadOnlyDeclaredRule,
)


def tool(name: str, description: str | None = None, **hints: Any) -> Tool:
    return Tool(
        name=name,
        description=description,
        inputSchema={"type": "object"},
        annotations=ToolAnnotations(**hints) if hints else None,
    )


@pytest.mark.parametrize(
    ("name", "description", "intent"),
    [
        ("delete_file", None, ToolIntent.DESTRUCTIVE),
        ("deleteFile", None, ToolIntent.DESTRUCTIVE),
        ("github_delete_repo", None, ToolIntent.DESTRUCTIVE),
        ("drop_table", None, ToolIntent.DESTRUCTIVE),
        ("chart_remove_indicator", "Delete an indicator instance from the chart.", ToolIntent.DESTRUCTIVE),
        ("purge_cache", "Permanently deletes every cached page.", ToolIntent.DESTRUCTIVE),
        ("get_user", "Get a user by ID.", ToolIntent.READ),
        ("list-channels", None, ToolIntent.READ),
        ("slack.search_messages", None, ToolIntent.READ),
        ("searchIcons", "Search 20,000 icons.", ToolIntent.READ),
        # Ambiguous words are left alone rather than guessed.
        ("truncate_to_tokens", "Truncate text to at most N tokens.", ToolIntent.UNKNOWN),
        ("text_purge_v1", "Removes invisible Unicode characters from a text string.", ToolIntent.UNKNOWN),
        ("ship_spec", "Drop a spec file in .specs/ so the autopilot picks it up.", ToolIntent.UNKNOWN),
        ("remove_background", "Remove the background from an image.", ToolIntent.UNKNOWN),
        # The description's own verb decides over the name.
        ("delete_person_preview", "Create a durable, non-mutating snapshot first.", ToolIntent.UNKNOWN),
        ("delete_accounting_run", "Hide one run from normal lists; its data is kept.", ToolIntent.UNKNOWN),
        ("restore_drop", "Bring back an expired drop.", ToolIntent.UNKNOWN),
        ("clear_filters", "Wipe every predicate applied to a layer.", ToolIntent.UNKNOWN),
        ("wipe_disk", None, ToolIntent.DESTRUCTIVE),
        # A description repeating the name's verb keeps a name-only verb's evidence.
        ("drop_table", "Drop a database table.", ToolIntent.DESTRUCTIVE),
        ("wipe_disk", "Wipe all data on the disk.", ToolIntent.DESTRUCTIVE),
        # Previews and dry runs of a delete do not delete.
        ("delete_file_preview", "Preview the effects of deleting a file without changing it.", ToolIntent.UNKNOWN),
        ("delete_repo", "Preview what deleting the repository would remove.", ToolIntent.UNKNOWN),
        ("dry_run_delete", None, ToolIntent.UNKNOWN),
        # A description that joins a changing action is not a read.
        ("get_user", "Get or create a user by ID.", ToolIntent.UNKNOWN),
        ("list_jobs", "List jobs and cancel the stale ones.", ToolIntent.UNKNOWN),
        ("search_docs", "Search the docs and return the best matches.", ToolIntent.READ),
        # A read verb with a change in the name or the description is not a read.
        ("get_or_create_user", None, ToolIntent.UNKNOWN),
        ("get_api_key", "Create a free API key for an email address.", ToolIntent.UNKNOWN),
        ("weather", "Current weather for a city.", ToolIntent.UNKNOWN),
        ("forget_everything_now", None, ToolIntent.UNKNOWN),
    ],
)
def test_tool_intent(name: str, description: str | None, intent: ToolIntent):
    assert tool_intent(tool(name, description)) is intent


class TestToolsAnnotationsDestructiveDeclaredRule:
    def test_metadata(self):
        rule = ToolsAnnotationsDestructiveDeclaredRule()
        assert rule.rule_id == "tools_annotations_destructive_declared"
        assert rule.severity is RuleSeverity.HIGH
        assert "ToolAnnotations" in rule.basis

    @pytest.mark.parametrize("hints", [{"destructiveHint": False}, {"readOnlyHint": True}])
    def test_fails_a_delete_tool_declared_safe(self, hints: dict[str, bool]):
        result = ToolsAnnotationsDestructiveDeclaredRule().check(
            AuditData(tools=[tool("delete_file", **hints), tool("get_file", readOnlyHint=True)])
        )
        assert not result.passed
        assert result.details["understated_tools"] == ["delete_file"]
        assert result.details["issues"][0]["entity_index"] == 0

    @pytest.mark.parametrize("hints", [{}, {"destructiveHint": True}, {"readOnlyHint": False, "idempotentHint": True}])
    def test_passes_a_delete_tool_left_destructive(self, hints: dict[str, bool]):
        result = ToolsAnnotationsDestructiveDeclaredRule().check(AuditData(tools=[tool("delete_file", **hints)]))
        assert result.passed

    def test_skips_a_catalog_without_delete_tools(self):
        rule = ToolsAnnotationsDestructiveDeclaredRule()
        assert (
            rule.skip_reason(AuditData(tools=[tool("get_file", destructiveHint=False)])) == SKIP_REASON_NOT_APPLICABLE
        )
        assert rule.skip_reason(AuditData(tools=[tool("delete_file")])) is None


class TestToolsAnnotationsReadOnlyDeclaredRule:
    def test_metadata(self):
        rule = ToolsAnnotationsReadOnlyDeclaredRule()
        assert rule.rule_id == "tools_annotations_read_only_declared"
        assert rule.severity is RuleSeverity.LOW

    def test_fails_an_annotated_read_tool_without_read_only_hint(self):
        result = ToolsAnnotationsReadOnlyDeclaredRule().check(
            AuditData(tools=[tool("list_users", openWorldHint=False), tool("get_user", readOnlyHint=True)])
        )
        assert not result.passed
        assert result.details["tools_without_read_only_hint"] == ["list_users"]

    def test_accepts_an_explicit_false(self):
        # A read-named tool may still change state (charging, minting a key); its explicit choice stands.
        result = ToolsAnnotationsReadOnlyDeclaredRule().check(AuditData(tools=[tool("get_report", readOnlyHint=False)]))
        assert result.passed

    def test_skips_read_tools_without_any_hint(self):
        # Missing annotations altogether are tools_annotations_present's finding, not this rule's.
        rule = ToolsAnnotationsReadOnlyDeclaredRule()
        assert rule.skip_reason(AuditData(tools=[tool("get_user")])) == SKIP_REASON_NOT_APPLICABLE
        assert rule.skip_reason(AuditData(tools=[tool("get_user", title="User")])) == SKIP_REASON_NOT_APPLICABLE


class TestToolsAnnotationsHintsConsistentRule:
    def test_metadata(self):
        rule = ToolsAnnotationsHintsConsistentRule()
        assert rule.rule_id == "tools_annotations_hints_consistent"
        assert rule.severity is RuleSeverity.LOW

    def test_fails_read_only_and_destructive(self):
        result = ToolsAnnotationsHintsConsistentRule().check(
            AuditData(tools=[tool("find_curriculum", readOnlyHint=True, destructiveHint=True)])
        )
        assert not result.passed
        assert result.details["contradictory_tools"] == ["find_curriculum"]

    @pytest.mark.parametrize("hints", [{"readOnlyHint": True}, {"readOnlyHint": True, "destructiveHint": False}])
    def test_passes_a_consistent_read_only_tool(self, hints: dict[str, bool]):
        assert ToolsAnnotationsHintsConsistentRule().check(AuditData(tools=[tool("find", **hints)])).passed

    def test_skips_without_read_only_tools(self):
        rule = ToolsAnnotationsHintsConsistentRule()
        assert rule.skip_reason(AuditData(tools=[tool("x", readOnlyHint=False, destructiveHint=True)])) == (
            SKIP_REASON_NOT_APPLICABLE
        )


def test_rules_defer_to_the_catalog_checks_when_tools_are_missing():
    for rule in (
        ToolsAnnotationsDestructiveDeclaredRule(),
        ToolsAnnotationsReadOnlyDeclaredRule(),
        ToolsAnnotationsHintsConsistentRule(),
    ):
        assert rule.skip_reason(AuditData(tools=[])) == SKIP_REASON_NOT_APPLICABLE
