"""Generate docs/rules.mdx from the live rule registry.

Run via `make docs-rules`. Keeping the reference generated (instead of
hand-written) guarantees it never drifts from the code: every registered rule
appears, with its stable rule_id, severity, and spec-version applicability.
"""

from collections import defaultdict
from pathlib import Path

from mcpscore.rules import create_all_rules
from mcpscore.rules.base import READINESS_GROUP, BaseRule
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
## Readiness rules (separate score)

These rules assess readiness for MCP **{target}** on the independent readiness
axis — they never affect the main score. See the
[methodology](/methodology#the-readiness-score-separate-informative) for the
normative citations behind each rule.

"""


def _applies_to(rule: BaseRule) -> str:
    if rule.min_spec_version is None and rule.max_spec_version is None:
        return "all versions"
    low = rule.min_spec_version or "…"
    high = rule.max_spec_version or "…"
    return f"{low} – {high}"


def generate() -> str:
    groups: dict[str, list[BaseRule]] = defaultdict(list)
    for rule in sorted(create_all_rules(), key=lambda r: r.sort_order):
        groups[rule.group_name].append(rule)

    lines = [HEADER]
    for group_name, rules in groups.items():
        if group_name == READINESS_GROUP:
            lines.append(READINESS_HEADER.format(target=(DRAFT or LATEST).version))
        else:
            lines.append(f"## {group_name.replace('_', ' ').title()}\n\n")
        lines.append("| Rule ID | Name | Severity | Weight | Applies to |\n")
        lines.append("|---|---|---|---|---|\n")
        for rule in rules:
            lines.append(
                f"| `{rule.rule_id}` | {rule.rule_name} | {rule.severity.name} "
                f"| {int(rule.severity)} | {_applies_to(rule)} |\n"
            )
        lines.append("\n")
    # Single trailing newline at EOF (keeps the end-of-file-fixer hook happy).
    return "".join(lines).rstrip("\n") + "\n"


if __name__ == "__main__":
    output = Path(__file__).parent.parent / "docs" / "rules.mdx"
    output.write_text(generate())
    print(f"Wrote {output}")
