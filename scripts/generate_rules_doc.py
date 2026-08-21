"""Generate docs/rules.mdx from the live rule registry.

Run via `make docs-rules`. Keeping the reference generated (instead of
hand-written) guarantees it never drifts from the code: every registered rule
appears, with its stable rule_id, severity, and spec-version applicability.
"""

from collections import defaultdict
from pathlib import Path

from mcpscore.rules import create_all_rules
from mcpscore.rules.base import READINESS_GROUP, BaseRule, rule_sort_key
from mcpscore.rules.packaging import PACKAGING_GROUP
from mcpscore.rules.retired import RETIRED_RULES
from mcpscore.spec import DRAFT, LATEST

HEADER = """\
---
title: "Rules Reference"
description: "Every rule mcpscore runs — generated from the rule registry, so it cannot drift from the code."
icon: "list-check"
---

Every rule mcpscore runs, generated from the rule registry
(`make docs-rules`) — this page cannot drift from the code.

- **Rule ID** is the stable machine contract used in JSON reports and CI.
- **Weight** is the severity's contribution to the score when the rule passes.
- **Applies to** is the spec-version range; outside it the rule is skipped and
  excluded from the maximum score (see the
  [methodology](/methodology#multi-spec-version-scoring)).

"""

READINESS_HEADER = """\
## Readiness rules

These rules assess readiness for MCP **{target}** on the independent readiness
axis. For modern-lifecycle servers in full audits, they are also counted in the
main score; legacy and partial audits keep them separate. See the
[methodology](/methodology#the-readiness-score-separate-informative) for the
normative citations behind each rule.

"""


PACKAGING_HEADER = """\
## Packaging rules

These rules apply **only** to `mcpscore --package <coordinate>`, which reads a
published package's registry metadata and never downloads or runs it. They are
the only rules a package audit runs, and no server audit runs any of them — the
two judge different targets, so their scores share no denominator. A package
audit says how well a server is *published*; run the server with `--stdio` to
score whether it speaks MCP.

"""


def _applies_to(rule: BaseRule) -> str:
    if rule.min_spec_version is None and rule.max_spec_version is None:
        return "all versions"
    low = rule.min_spec_version or "…"
    high = rule.max_spec_version or "…"
    return f"{low} – {high}"


RETIRED_HEADER = """\
## Retired rules

These `rule_id`s no longer run. They are listed because a rule ID is a public
contract: it appears in JSON reports you may have stored and in CI
configuration that may still reference it. **Retired IDs are never reused.**

A rule is retired only when it was *wrong*. A rule that was correct but applies
only to certain spec revisions is not retired — it keeps its ID and gains a
version range in the **Applies to** column above.

If a report of yours shows one of these, its result was accurate for the
mcpscore version that produced it; the check simply no longer exists.

"""


def _retired_table() -> list[str]:
    """Render the retired-rule registry, or nothing when it is empty."""
    if not RETIRED_RULES:
        return []
    lines = [RETIRED_HEADER, "| Rule ID | Retired in | Last severity | Why |\n", "|---|---|---|---|\n"]
    lines.extend(f"| `{r.rule_id}` | {r.version} | {r.severity} | {r.reason} |\n" for r in RETIRED_RULES)
    lines.append("\n")
    return lines


def generate() -> str:
    groups: dict[str, list[BaseRule]] = defaultdict(list)
    for rule in sorted(create_all_rules(), key=rule_sort_key):
        groups[rule.group_name].append(rule)

    lines = [HEADER]
    for group_name, rules in groups.items():
        if group_name == READINESS_GROUP:
            lines.append(READINESS_HEADER.format(target=(DRAFT or LATEST).version))
        elif group_name == PACKAGING_GROUP:
            lines.append(PACKAGING_HEADER)
        else:
            lines.append(f"## {group_name.replace('_', ' ').title()}\n\n")
        lines.append("| Rule ID | Name | Severity | Weight | Applies to |\n")
        lines.append("|---|---|---|---|---|\n")
        lines.extend(
            f"| `{rule.rule_id}` | {rule.rule_name} | {rule.severity.name} "
            f"| {int(rule.severity)} | {_applies_to(rule)} |\n"
            for rule in rules
        )
        lines.append("\n")
    lines.extend(_retired_table())
    # Single trailing newline at EOF (keeps the end-of-file-fixer hook happy).
    return "".join(lines).rstrip("\n") + "\n"


if __name__ == "__main__":
    output = Path(__file__).parent.parent / "docs" / "rules.mdx"
    output.write_text(generate(), encoding="utf-8")
    print(f"Wrote {output}")
