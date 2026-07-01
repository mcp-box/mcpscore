"""Tests for prompt-quality rules."""

from mcp.types import Prompt, PromptArgument

from mcpscore.rules import (
    AuditData,
    PromptsArgumentsDocumentedRule,
    PromptsDescriptionPresentRule,
    RuleSeverity,
)


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
