"""Registry of retired rule_ids.

A `rule_id` is a public contract: it appears in every JSON report, in CI
configuration that waives or asserts specific rules, and in stored audit
history. When a rule stops running, the id must not simply vanish — someone
reading an old report, or a CI job whose waiver silently stopped matching,
needs to find out what happened to it.

This registry is that record. It feeds the "Retired rules" table in
`docs/rules.mdx` (see `scripts/generate_rules_doc.py`).

**When to retire versus version-scope** — the distinction matters:

- The rule was **wrong** (it asserted something the spec does not require, or
  contradicted another rule): retire it. Keeping an incorrect judgement alive
  in any form means continuing to publish it.
- The rule was **right but the feature is era-bound** (the spec removed or
  deprecated what it checked): do NOT retire it. Set `max_spec_version` so it
  still judges servers on the revisions where the requirement held and is
  skipped elsewhere — `BaseRule.applies_to` exists for exactly this, and the
  rules reference shows the range. Deleting such a rule would silently stop
  auditing servers that are still subject to it.

Retired ids are **never reused**: a future rule that means something different
must take a new id, or a consumer's waiver would start matching a check it
never agreed to.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RetiredRule:
    """A rule_id that no longer runs, and why.

    Attributes:
        rule_id: The retired identifier. Never reused.
        version: mcpscore release that retired it.
        severity: Severity it carried when it last ran, so an old report's
            arithmetic can still be understood.
        reason: One line, written for someone holding an old report.

    """

    rule_id: str
    version: str
    severity: str
    reason: str


RETIRED_RULES: tuple[RetiredRule, ...] = (
    RetiredRule(
        rule_id="capability_resources_subscribe",
        version="1.1.0",
        severity="HIGH",
        reason=(
            "Scored the absence of an optional capability — 2025-11-25 Resources §Capabilities calls "
            "`subscribe` optional — and 2026-07-28 removes `resources/subscribe` outright (SEP-2575)."
        ),
    ),
    RetiredRule(
        rule_id="capability_logging_present",
        version="1.1.0",
        severity="MEDIUM",
        reason=(
            "Scored the absence of an optional capability, and contradicted "
            "`readiness_2026_deprecated_features`, which fails a server for *declaring* `logging` "
            "(deprecated by SEP-2577). No server could pass both."
        ),
    ),
)
"""Every retired rule_id, oldest first. Append only — entries are permanent."""
