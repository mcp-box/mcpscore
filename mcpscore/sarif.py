"""SARIF 2.1.0 export of an audit's findings, for GitHub code scanning (``--sarif``).

SARIF is a findings format, not a report format: every **failed** rule becomes
one ``result``; passed and skipped rules are not results. The ``--json``
report remains the complete record of a run. The two are built from the same
report dictionary, so they cannot disagree.

Shape (one ``run``):

- ``tool.driver`` names mcpscore, its version, and the docs site; ``rules[]``
  carries one entry per rule that produced a finding, with the rule's name,
  its primary-source basis where the rule declares one, and a help link to
  the rules reference.
- Each ``result`` maps the rule's severity to a SARIF level (critical and
  high → ``error``, medium → ``warning``, low → ``note``). A readiness rule
  that this run did not count in the main score is informative, so it is a
  ``note`` whatever its severity: the Security tab must not show as an error
  something the score itself waves through.
- SARIF requires a physical location, and GitHub requires it to be a path
  relative to the repository: ``upload-sarif`` hands GitHub a ``file://``
  checkout root, and an absolute URI with any other scheme (``https://``,
  ``npm:``) makes GitHub reject the whole upload. An audit has no source
  file, so the location is a repository-relative path derived from the
  target (``mcp.example.com/mcp`` for a URL, ``npm/name`` for a package, the
  file itself for a local server), on line 1. The exact target is kept in
  the run's ``artifacts`` description. Nothing is annotated in a pull
  request diff: GitHub annotates only alerts whose lines are in the diff,
  and these findings are about a running server, not a line of source.
- ``partialFingerprints.primaryLocationLineHash`` — the one fingerprint key
  GitHub reads — is a hash of the rule id and the target, so a re-upload
  for the same server updates the alert instead of opening a new one, and
  the same rule on two servers stays two alerts. ``upload-sarif`` keeps an
  existing value (it computes one only for locations it can read from
  disk, which these are not). The target's identity ignores a trailing
  slash on its path, in both the fingerprint and the run's automation id:
  ``/mcp`` and ``/mcp/`` are one server (the engine follows that redirect
  as same-origin), so they must be one series of alerts.
- Security rules carry GitHub's ``security-severity`` score so they sort
  into the Security tab's critical/high/medium/low bands.
"""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from mcpscore.rules import create_all_rules

if TYPE_CHECKING:
    from mcpscore.rules.base import BaseRule

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DOCS_URL = "https://docs.mcpscore.dev"
RULES_URL = f"{DOCS_URL}/rules"

LEVEL_BY_SEVERITY: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}
"""SARIF ``result.level`` per mcpscore severity name. Unknown names fall back to ``warning``."""

SECURITY_SEVERITY_BY_SEVERITY: dict[str, str] = {
    "CRITICAL": "9.0",
    "HIGH": "7.0",
    "MEDIUM": "5.0",
    "LOW": "2.0",
}
"""GitHub's ``security-severity`` (0.1-10.0) per severity: ≥9 critical, 7-8.9 high, 4-6.9 medium, <4 low."""

SECURITY_GROUP = "security"
"""Rule group whose findings are tagged ``security`` and scored for the Security tab."""

FINGERPRINT_KEY = "mcpscoreFinding/v1"
"""Name of the partial fingerprint; the ``/v1`` lets a future scheme coexist with old uploads."""

_URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def build_sarif(report: dict) -> dict:
    """Build a SARIF 2.1.0 log from a ``--json``-shaped report (see ``cli.build_report``).

    Args:
        report: The full report dictionary: ``target``, ``mcpscore_version``,
            ``results``, ``readiness``, ``score``/``max_score``, ``partial``.

    Returns:
        The SARIF log as a JSON-serializable dictionary.

    """
    target = str(report["target"])
    readiness = report.get("readiness") or {}
    counted_in_main = bool(readiness.get("counted_in_main", False))

    findings: list[tuple[dict, bool]] = [(res, False) for res in report.get("results", []) if not res["passed"]]
    findings.extend((res, True) for res in readiness.get("results", []) if not res["passed"])
    catalog = _catalog() if findings else {}

    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    results: list[dict] = []
    for res, is_readiness in findings:
        rule_id = res["rule_id"]
        if rule_id not in rule_index:
            rule_index[rule_id] = len(rules)
            rules.append(_rule_entry(res, catalog.get(rule_id), is_readiness=is_readiness))
        results.append(
            _result_entry(
                res,
                rule_index[rule_id],
                target,
                is_readiness=is_readiness,
                counted_in_main=counted_in_main,
            )
        )

    package = report.get("package")
    run_properties: dict[str, Any] = {
        "score": report.get("score"),
        "max_score": report.get("max_score"),
        "partial": bool(report.get("partial", False)),
        "authenticated": bool(report.get("authenticated", False)),
    }
    if report.get("partial_reason"):
        run_properties["partial_reason"] = report["partial_reason"]
    if package is not None:
        run_properties["package"] = package
    if report.get("transport") is not None:
        run_properties["transport"] = report["transport"]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcpscore",
                        "version": str(report.get("mcpscore_version", "unknown")),
                        "informationUri": DOCS_URL,
                        "rules": rules,
                    }
                },
                # GitHub keys uploads on this id, so two servers audited in one
                # workflow stay two sets of alerts. The upload step's `category`
                # input, when given, overrides it. GitHub reads the text up to
                # the last slash as the category, hence exactly one trailing
                # slash whether or not the target ends in one.
                "automationDetails": {"id": f"mcpscore/{target_identity(target)}/"},
                "invocations": [{"executionSuccessful": True}],
                "artifacts": [{"location": {"uri": _artifact_uri(target)}, "description": {"text": target}}],
                "results": results,
                "properties": run_properties,
            }
        ],
    }


def _catalog() -> dict[str, BaseRule]:
    """Return the registered rules by id, for the group and basis a result does not carry itself."""
    return {rule.rule_id: rule for rule in create_all_rules()}


def _rule_entry(res: dict, rule: BaseRule | None, *, is_readiness: bool) -> dict:
    """SARIF ``reportingDescriptor`` for a rule, from its result and (when registered) the rule itself."""
    rule_id = res["rule_id"]
    group = rule.group_name if rule is not None else ("readiness" if is_readiness else "default")
    basis = (res.get("details") or {}).get("basis") or (rule.basis if rule is not None else None)
    entry: dict[str, Any] = {
        "id": rule_id,
        "name": _pascal_case(rule_id),
        "shortDescription": {"text": res["rule_name"]},
        "helpUri": f"{RULES_URL}#{_heading_anchor(group)}",
        "help": {"text": f"{res['rule_name']} — {RULES_URL}#{_heading_anchor(group)}"},
        "defaultConfiguration": {"level": LEVEL_BY_SEVERITY.get(res["severity"], "warning")},
        "properties": {"tags": [group], "category": group},
    }
    if basis:
        entry["fullDescription"] = {"text": f"{res['rule_name']}. Basis: {basis}"}
    if group == SECURITY_GROUP:
        entry["properties"]["security-severity"] = SECURITY_SEVERITY_BY_SEVERITY.get(res["severity"], "5.0")
    return entry


def _result_entry(res: dict, rule_index: int, target: str, *, is_readiness: bool, counted_in_main: bool) -> dict:
    """SARIF ``result`` for one failed rule."""
    severity = res["severity"]
    informative = is_readiness and not counted_in_main
    level = "note" if informative else LEVEL_BY_SEVERITY.get(severity, "warning")
    properties: dict[str, Any] = {
        "severity": severity,
        "severity_value": res.get("severity_value"),
        "readiness": is_readiness,
        "counted_in_score": not informative,
    }
    if res.get("details"):
        properties["details"] = res["details"]
    return {
        "ruleId": res["rule_id"],
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": res["message"]},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _artifact_uri(target), "index": 0},
                    "region": {"startLine": 1},
                }
            }
        ],
        "partialFingerprints": {FINGERPRINT_KEY: fingerprint(res["rule_id"], target)},
        "properties": properties,
    }


def fingerprint(rule_id: str, target: str) -> str:
    """Stable fingerprint of a finding: the same rule on the same target hashes the same across runs.

    The target enters by its identity (``target_identity``), so the alert
    keys agree with the run's automation id: a trailing slash never splits
    one server's alerts into two series.
    """
    digest = hashlib.sha256(f"{rule_id}\n{target_identity(target)}".encode()).hexdigest()
    return digest[:32]


def target_identity(target: str) -> str:
    """Return the target as GitHub should key alerts on: the string itself, minus any trailing slashes."""
    return target.rstrip("/")


def _artifact_uri(target: str) -> str:
    """Return the target as a URI reference: URLs verbatim, else percent-encoded (a stdio command has spaces)."""
    if _URI_SCHEME.match(target):
        return target
    return quote(target, safe="/:@+.-_~")


def _pascal_case(rule_id: str) -> str:
    """``tools_have_descriptions`` → ``ToolsHaveDescriptions``, the ``reportingDescriptor.name`` convention."""
    return "".join(part.capitalize() for part in rule_id.split("_") if part)


def _heading_anchor(group: str) -> str:
    """Anchor of the group's heading on the rules page, as the docs generator titles it."""
    if group == "readiness":
        return "readiness-rules"
    if group == "packaging":
        return "packaging-rules"
    return group.replace("_", "-")
