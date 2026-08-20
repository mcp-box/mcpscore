from abc import abstractmethod
from collections import Counter

from mcp_types import Prompt

from .base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_NOT_APPLICABLE,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
    requires_fields,
)
from .icon_validation import find_invalid_icons
from .registry import register_rule


class PromptsBaseRule(BaseRule):
    """Base class for prompt-quality audit rules.

    Prompts are an optional MCP capability. With no prompts there is nothing
    whose quality can be judged, so these rules skip as not applicable and add
    no score weight. Capability consistency is judged separately.
    """

    group_name = "prompts"
    group_order = 8

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when the prompt catalog is unavailable or has no prompts to judge."""
        listing = "prompts"
        declares_prompts = getattr(audit_data.capabilities, "prompts", None) is not None
        unavailable = audit_data.prompts is None and (declares_prompts or listing in audit_data.listings_attempted)
        empty_partial = not audit_data.prompts and listing in audit_data.incomplete_listings
        if unavailable or empty_partial:
            return SKIP_REASON_INSUFFICIENT_DATA
        if not audit_data.prompts:
            return SKIP_REASON_NOT_APPLICABLE
        return None

    @requires_fields("prompts")
    def check(self, prompts: list[Prompt] | None) -> RuleResult:  # type: ignore[override]
        """Execute the prompt rule check, skipping servers with no prompts.

        Args:
            prompts: The declared prompts, or None if unsupported

        Returns:
            RuleResult indicating whether the prompt check passed

        """
        assert prompts  # noqa: S101 — skip_reason guarantees prompts to judge
        return self._check_prompts(prompts)

    @abstractmethod
    def _check_prompts(self, prompts: list[Prompt]) -> RuleResult:
        """Perform the actual prompt validation.

        Args:
            prompts: The declared prompts to validate

        Returns:
            RuleResult with the validation outcome

        """
        ...


@register_rule
class PromptsArgumentNamesUniqueRule(PromptsBaseRule):
    """High check: Verify that argument names are unique within each prompt.

    The spec text imposes no explicit uniqueness requirement on argument
    names; the rule enforces the mechanism instead: ``prompts/get`` passes
    arguments as a JSON object keyed by name, so only one of two same-named
    declarations can ever be addressed.
    """

    rule_id = "prompts_argument_names_unique"
    basis = "MCP 2026-07-28 Prompts §Getting a Prompt (prompts/get arguments are keyed by name)"
    rule_order = 1

    @property
    def rule_name(self) -> str:
        return "Prompts - Argument names must be unique"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def _check_prompts(self, prompts: list[Prompt]) -> RuleResult:
        """Find duplicate argument names within each prompt."""
        duplicate_arguments: list[str] = []
        for prompt in prompts:
            seen: set[str] = set()
            for argument in prompt.arguments or []:
                if argument.name in seen:
                    duplicate_arguments.append(f"{prompt.name}.{argument.name}")
                seen.add(argument.name)

        passed = not duplicate_arguments
        message = (
            "✅ All prompt argument names are unique"
            if passed
            else f"❌ Number of duplicate prompt arguments: {len(duplicate_arguments)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"duplicate_arguments": duplicate_arguments},
        )


@register_rule
class PromptsArgumentNamesPresentRule(PromptsBaseRule):
    """Medium check: Verify that every prompt argument has a non-blank name."""

    rule_id = "prompts_argument_names_present"
    basis = "MCP 2026-07-28 Prompts §Prompt (arguments)"
    rule_order = 2

    @property
    def rule_name(self) -> str:
        return "Prompts - All arguments must have a name"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_prompts(self, prompts: list[Prompt]) -> RuleResult:
        """Find prompt arguments whose names contain no visible text."""
        prompts_with_unnamed_arguments = [
            prompt.name for prompt in prompts if any(not argument.name.strip() for argument in (prompt.arguments or []))
        ]
        passed = not prompts_with_unnamed_arguments
        message = (
            "✅ All prompt arguments have a name"
            if passed
            else f"❌ Number of prompts with unnamed arguments: {len(prompts_with_unnamed_arguments)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"prompts_with_unnamed_arguments": prompts_with_unnamed_arguments},
        )


@register_rule
class PromptsDescriptionPresentRule(PromptsBaseRule):
    """Medium check: Verify that all declared prompts have a description."""

    rule_id = "prompts_description_present"
    basis = "MCP 2025-11-25 Prompts §Prompt (description)"
    rule_order = 3

    @property
    def rule_name(self) -> str:
        return "Prompts - All prompts should have a description"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def _check_prompts(self, prompts: list[Prompt]) -> RuleResult:
        """Medium check: Verify that every prompt has a non-empty description.

        Args:
            prompts: The declared prompts to validate

        Returns:
            RuleResult with the check outcome

        """
        prompts_without_description: list[str] = [
            prompt.name for prompt in prompts if not (prompt.description and prompt.description.strip())
        ]

        passed = len(prompts_without_description) == 0

        message = (
            "✅ All prompts have a description"
            if passed
            else f"❌ Number of prompts without a description: {len(prompts_without_description)}"
        )

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"prompts_without_description": prompts_without_description},
        )


@register_rule
class PromptsArgumentsDocumentedRule(PromptsBaseRule):
    """Low check: Verify that every prompt argument has a description.

    A documented argument tells a client what to pass; undocumented arguments
    make a prompt hard to use correctly.
    """

    rule_id = "prompts_arguments_documented"
    basis = "MCP 2025-11-25 Prompts §Prompt (arguments: name, description, required)"
    rule_order = 4

    @property
    def rule_name(self) -> str:
        return "Prompts - All prompt arguments should be documented"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def _check_prompts(self, prompts: list[Prompt]) -> RuleResult:
        """Low check: Verify that every prompt argument has a description.

        Args:
            prompts: The declared prompts to validate

        Returns:
            RuleResult with the check outcome

        """
        undocumented_arguments: list[str] = [
            f"{prompt.name}.{argument.name}"
            for prompt in prompts
            for argument in (prompt.arguments or [])
            if not (argument.description and argument.description.strip())
        ]

        passed = len(undocumented_arguments) == 0

        message = (
            "✅ All prompt arguments are documented"
            if passed
            else f"❌ Number of undocumented prompt arguments: {len(undocumented_arguments)}"
        )

        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"undocumented_arguments": undocumented_arguments},
        )


@register_rule
class PromptsNamesUniqueRule(PromptsBaseRule):
    """High check: Verify that each listed prompt has a unique name."""

    rule_id = "prompts_names_unique"
    basis = "MCP 2026-07-28 Prompts §Prompt (name: Unique identifier for the prompt)"
    rule_order = 5

    @property
    def rule_name(self) -> str:
        return "Prompts - Prompt names must be unique"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when pagination did not produce the complete prompt list."""
        if reason := super().skip_reason(audit_data):
            return reason
        return SKIP_REASON_INSUFFICIENT_DATA if "prompts" in audit_data.incomplete_listings else None

    def _check_prompts(self, prompts: list[Prompt]) -> RuleResult:
        """Find prompt names declared more than once."""
        counts = Counter(prompt.name for prompt in prompts)
        duplicate_names = sorted(name for name, count in counts.items() if count > 1)
        passed = not duplicate_names
        message = (
            "✅ All prompt names are unique"
            if passed
            else f"❌ Number of duplicate prompt names: {len(duplicate_names)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"duplicate_names": duplicate_names},
        )


@register_rule
class PromptsTitlesPresentRule(PromptsBaseRule):
    """Low check: Encourage human-readable display titles for prompts."""

    rule_id = "prompts_titles_present"
    basis = "MCP 2026-07-28 Prompts §Prompt (title: optional human-readable name for display)"
    # `title` was introduced in the 2025-06-18 revision — earlier servers
    # cannot declare one and must not be penalized for its absence. (The
    # basis cites the revision the rule was verified against, per repo
    # policy — intentionally not the introduction revision.)
    min_spec_version = "2025-06-18"
    rule_order = 6

    @property
    def rule_name(self) -> str:
        return "Prompts - All prompts should have a display title"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def _check_prompts(self, prompts: list[Prompt]) -> RuleResult:
        """Find prompts without a non-blank display title."""
        prompts_without_title = [prompt.name for prompt in prompts if not (prompt.title and prompt.title.strip())]
        passed = not prompts_without_title
        message = (
            "✅ All prompts have a display title"
            if passed
            else f"❌ Number of prompts without a display title: {len(prompts_without_title)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"prompts_without_title": prompts_without_title},
        )


@register_rule
class PromptsIconsValidRule(PromptsBaseRule):
    """Low check: validate every declared prompt icon."""

    rule_id = "prompts_icons_valid"
    basis = "MCP 2026-07-28 Schema Reference §Common Types (Icon); Prompts §Prompt (icons)"
    min_spec_version = "2025-11-25"
    rule_order = 7

    @property
    def rule_name(self) -> str:
        return "Prompts - Declared icons must be valid"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def _check_prompts(self, prompts: list[Prompt]) -> RuleResult:
        invalid_icons = find_invalid_icons([(prompt.name, prompt) for prompt in prompts])
        passed = not invalid_icons
        message = (
            "✅ All declared prompt icons are valid"
            if passed
            else f"❌ Number of invalid prompt icons: {len(invalid_icons)}"
        )
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details={"invalid_icons": invalid_icons},
        )
