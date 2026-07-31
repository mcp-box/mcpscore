"""Tests for prompt-quality rules."""

from mcp_types import Prompt, PromptArgument

from mcpscore.rules import (
    AuditData,
    PromptsArgumentNamesPresentRule,
    PromptsArgumentNamesUniqueRule,
    PromptsArgumentsDocumentedRule,
    PromptsDescriptionPresentRule,
    PromptsNamesUniqueRule,
    PromptsTitlesPresentRule,
    RuleSeverity,
)
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA


def _prompt(
    name: str,
    description: str | None = "desc",
    arguments: list[PromptArgument] | None = None,
) -> Prompt:
    return Prompt(name=name, description=description, arguments=arguments)


class TestPromptsDescriptionPresentRule:
    def test_rule_properties(self) -> None:
        rule = PromptsDescriptionPresentRule()
        assert rule.rule_id == "prompts_description_present"
        assert rule.severity == RuleSeverity.MEDIUM
        assert rule.group_name == "prompts"

    def test_no_prompts_is_not_applicable_and_passes(self) -> None:
        rule = PromptsDescriptionPresentRule()
        assert rule.check(AuditData(prompts=None)).passed
        assert rule.check(AuditData(prompts=[])).passed

    def test_all_described_passes(self) -> None:
        rule = PromptsDescriptionPresentRule()
        result = rule.check(AuditData(prompts=[_prompt("a"), _prompt("b")]))
        assert result.passed is True

    def test_missing_description_fails(self) -> None:
        rule = PromptsDescriptionPresentRule()
        result = rule.check(AuditData(prompts=[_prompt("good"), _prompt("bad", description=None)]))
        assert result.passed is False
        assert result.details is not None
        assert result.details["prompts_without_description"] == ["bad"]


class TestPromptsNamesUniqueRule:
    def test_unique_names_pass(self) -> None:
        result = PromptsNamesUniqueRule().check(AuditData(prompts=[_prompt("one"), _prompt("two")]))
        assert result.passed is True
        assert result.details == {"duplicate_names": []}

    def test_duplicate_name_fails_once(self) -> None:
        result = PromptsNamesUniqueRule().check(AuditData(prompts=[_prompt("same"), _prompt("same"), _prompt("same")]))
        assert result.passed is False
        assert result.details == {"duplicate_names": ["same"]}

    def test_incomplete_listing_skips(self) -> None:
        rule = PromptsNamesUniqueRule()
        data = AuditData(prompts=[_prompt("one")], incomplete_listings=frozenset({"prompts"}))
        assert rule.skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA


class TestPromptsTitlesPresentRule:
    def test_scoped_to_revisions_that_have_title(self) -> None:
        """`title` first appeared in 2025-06-18 — earlier servers cannot declare one."""
        rule = PromptsTitlesPresentRule()
        assert rule.min_spec_version == "2025-06-18"
        assert not rule.applies_to("2025-03-26")
        assert rule.applies_to("2025-06-18")

    def test_non_blank_titles_pass(self) -> None:
        prompts = [
            Prompt(name="one", title="First prompt"),
            Prompt(name="two", title="Second prompt"),
        ]
        result = PromptsTitlesPresentRule().check(AuditData(prompts=prompts))
        assert result.passed is True
        assert result.details == {"prompts_without_title": []}

    def test_missing_and_blank_titles_fail_with_names(self) -> None:
        prompts = [_prompt("missing"), Prompt(name="blank", title="   ")]
        result = PromptsTitlesPresentRule().check(AuditData(prompts=prompts))
        assert result.passed is False
        assert result.details == {"prompts_without_title": ["missing", "blank"]}


class TestPromptsArgumentNamesUniqueRule:
    def test_unique_names_and_separate_prompt_scopes_pass(self) -> None:
        result = PromptsArgumentNamesUniqueRule().check(
            AuditData(
                prompts=[
                    _prompt("first", arguments=[PromptArgument(name="topic"), PromptArgument(name="format")]),
                    _prompt("second", arguments=[PromptArgument(name="topic")]),
                ]
            )
        )
        assert result.passed is True
        assert result.details == {"duplicate_arguments": []}

    def test_duplicate_name_within_prompt_fails(self) -> None:
        result = PromptsArgumentNamesUniqueRule().check(
            AuditData(
                prompts=[
                    _prompt(
                        "review",
                        arguments=[PromptArgument(name="code"), PromptArgument(name="code")],
                    )
                ]
            )
        )
        assert result.passed is False
        assert result.details == {"duplicate_arguments": ["review.code"]}


class TestPromptsArgumentNamesPresentRule:
    def test_named_arguments_and_prompt_without_arguments_pass(self) -> None:
        result = PromptsArgumentNamesPresentRule().check(
            AuditData(
                prompts=[
                    _prompt("none"),
                    _prompt("named", arguments=[PromptArgument(name="topic")]),
                ]
            )
        )
        assert result.passed is True
        assert result.details == {"prompts_with_unnamed_arguments": []}

    def test_blank_argument_name_fails_once_per_prompt(self) -> None:
        result = PromptsArgumentNamesPresentRule().check(
            AuditData(
                prompts=[
                    _prompt(
                        "bad",
                        arguments=[PromptArgument(name=""), PromptArgument(name="  ")],
                    )
                ]
            )
        )
        assert result.passed is False
        assert result.details == {"prompts_with_unnamed_arguments": ["bad"]}


class TestPromptsArgumentsDocumentedRule:
    def test_rule_properties(self) -> None:
        rule = PromptsArgumentsDocumentedRule()
        assert rule.rule_id == "prompts_arguments_documented"
        assert rule.severity == RuleSeverity.LOW

    def test_no_prompts_passes(self) -> None:
        assert PromptsArgumentsDocumentedRule().check(AuditData(prompts=None)).passed

    def test_prompt_without_arguments_passes(self) -> None:
        """A prompt with no arguments has nothing to document."""
        rule = PromptsArgumentsDocumentedRule()
        assert rule.check(AuditData(prompts=[_prompt("a", arguments=None)])).passed

    def test_documented_arguments_pass(self) -> None:
        rule = PromptsArgumentsDocumentedRule()
        prompt = _prompt("p", arguments=[PromptArgument(name="x", description="the x")])
        assert rule.check(AuditData(prompts=[prompt])).passed is True

    def test_undocumented_argument_fails(self) -> None:
        rule = PromptsArgumentsDocumentedRule()
        prompt = _prompt(
            "p",
            arguments=[
                PromptArgument(name="x", description="the x"),
                PromptArgument(name="y", description=None),
            ],
        )
        result = rule.check(AuditData(prompts=[prompt]))
        assert result.passed is False
        assert result.details is not None
        assert result.details["undocumented_arguments"] == ["p.y"]
