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
- The file carries no credentials. Everyone who can read the repository's
  alerts can read the upload, a wider audience than a local report, so a
  URL target is written without userinfo, query, or fragment wherever it is
  displayed (automation id, artifact, location), every URL inside a rule
  message (auth rules quote server-supplied metadata and issuer URLs) is
  written the same way, and rule ``details`` — which can hold the audited
  URL verbatim — stay in the ``--json`` report. The fingerprint hashes the
  target without userinfo or fragment but with its query, so two endpoints
  that differ only by query stay two alerts while a token in the query is
  never recoverable from the file. Only a URL target is normalized at all:
  a stdio command line is its own identity, verbatim.
"""

from __future__ import annotations

import hashlib
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import SplitResult, quote, urlsplit, urlunsplit

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

FINGERPRINT_KEY = "primaryLocationLineHash"
"""The one ``partialFingerprints`` key GitHub code scanning uses to match alerts across uploads.

Any other key is ignored. ``upload-sarif`` fills this key in only when it is
absent and the location is a readable file, so the value written here is the
one GitHub sees."""

POINT_REGION: dict[str, int] = {"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 1}
"""The location's region: a zero-length point at line 1, column 1 (``endColumn`` is the column after the end)."""

_URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_PACKAGE_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]+:")  # npm:, pypi: — two+ letters, so C:\ is a path
_DRIVE_LETTER = re.compile(r"^[A-Za-z]:[\\/]")
_URL_IN_TEXT = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"<>,)]+")


def build_sarif(report: dict) -> dict:
    """Build a SARIF 2.1.0 log from a ``--json``-shaped report (see ``cli.build_report``).

    Args:
        report: The full report dictionary: ``target``, ``mcpscore_version``,
            ``results``, ``readiness``, ``score``/``max_score``, ``partial``.

    Returns:
        The SARIF log as a JSON-serializable dictionary.

    """
    target = str(report["target"])
    shown = display_target(target)
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
                shown,
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
                # workflow stay two sets of alerts. It wins over the upload
                # step's `category` input: upload-sarif sets automationDetails
                # only when the run has none. GitHub reads the text up to the
                # last slash as the category, hence exactly one trailing slash
                # whether or not the target ends in one.
                "automationDetails": {"id": f"mcpscore/{target_identity(shown)}/"},
                "invocations": [{"executionSuccessful": True}],
                "artifacts": [{"location": {"uri": _artifact_uri(shown)}, "description": {"text": shown}}],
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
    # GitHub lists shortDescription.text, fullDescription.text and help.text
    # as required for a rule (its SARIF support tables), so every entry
    # carries all three; the basis, when the rule declares one, extends the
    # full description rather than gating it.
    full_description = f"{res['rule_name']}. Basis: {basis}" if basis else res["rule_name"]
    entry: dict[str, Any] = {
        "id": rule_id,
        "name": _pascal_case(rule_id),
        "shortDescription": {"text": res["rule_name"]},
        "fullDescription": {"text": full_description},
        "helpUri": f"{RULES_URL}#{_heading_anchor(group)}",
        "help": {"text": f"{res['rule_name']} — {RULES_URL}#{_heading_anchor(group)}"},
        "defaultConfiguration": {"level": LEVEL_BY_SEVERITY.get(res["severity"], "warning")},
        "properties": {"tags": [group], "category": group},
    }
    if group == SECURITY_GROUP:
        entry["properties"]["security-severity"] = SECURITY_SEVERITY_BY_SEVERITY.get(res["severity"], "5.0")
    return entry


def _result_entry(
    res: dict, rule_index: int, target: str, shown: str, *, is_readiness: bool, counted_in_main: bool
) -> dict:
    """SARIF ``result`` for one failed rule: ``target`` keys the fingerprint, ``shown`` is what the file displays."""
    severity = res["severity"]
    informative = is_readiness and not counted_in_main
    level = "note" if informative else LEVEL_BY_SEVERITY.get(severity, "warning")
    properties: dict[str, Any] = {
        "severity": severity,
        "severity_value": res.get("severity_value"),
        "readiness": is_readiness,
        "counted_in_score": not informative,
    }
    # No `details`: several rules record the audited URL there verbatim,
    # credentials included, and the message plus the rule's basis already
    # say what failed. The --json report keeps the details.
    return {
        "ruleId": res["rule_id"],
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": scrub_urls(res["message"])},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _artifact_uri(shown), "index": 0},
                    # GitHub requires all four region fields; a zero-length
                    # point at 1:1 is the honest region for a finding about a
                    # running server rather than a span of source.
                    "region": POINT_REGION,
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
    digest = hashlib.sha256(f"{rule_id}\n{target_identity(_canonical(target))}".encode()).hexdigest()
    return digest[:32]


def display_target(target: str) -> str:
    """Return the target as the file may show it: a URL without userinfo, query, or fragment; anything else as is.

    A query can carry a signed credential and userinfo is one by definition,
    and code scanning data is readable by everyone with access to the
    repository's alerts.
    """
    if not _URI_SCHEME.match(target):
        return target
    parts = urlsplit(target)
    return urlunsplit((parts.scheme, _host_port(parts), parts.path, "", ""))


def scrub_urls(text: str) -> str:
    """Return ``text`` with every URL in it reduced to its displayable form (no userinfo, query, or fragment).

    Rule messages quote URLs the server supplied (a challenge's
    ``resource_metadata``, an issuer), and those can carry credentials as
    easily as the target can.
    """
    return _URL_IN_TEXT.sub(lambda m: display_target(m.group(0)), text)


def _canonical(target: str) -> str:
    """Return a URL target minus userinfo and fragment, keeping the query; anything else unchanged.

    Userinfo is a credential, and a fragment never reaches the server, so
    neither can make two spellings of one endpoint two alerts. The query is
    part of the endpoint and stays.
    """
    if not _URI_SCHEME.match(target):
        return target
    parts = urlsplit(target)
    return urlunsplit((parts.scheme, _host_port(parts), parts.path, parts.query, ""))


def _host_port(parts: SplitResult) -> str:
    """Return ``host`` or ``host:port`` from a split URL, never its userinfo."""
    host = parts.hostname or ""
    if ":" in host:  # an IPv6 literal keeps its brackets
        host = f"[{host}]"
    return f"{host}:{parts.port}" if parts.port is not None else host


def target_identity(target: str) -> str:
    """Return the target as GitHub should key alerts on: a URL minus trailing slashes on its path, else itself.

    Only a URL is normalized, and only the part before any query or fragment:
    ``?resource=https://tenant/`` is a different target from
    ``?resource=https://tenant``, and a stdio command such as
    ``server --root /tmp/a/`` names what it names.
    """
    if not _URI_SCHEME.match(target):
        return target
    cut = min((i for i in (target.find("?"), target.find("#")) if i >= 0), default=len(target))
    return target[:cut].rstrip("/") + target[cut:]


def _artifact_uri(target: str) -> str:
    """Return a repository-relative path standing for the (displayable) target, the only location GitHub accepts.

    A URL keeps its host and path (``mcp.example.com/mcp``), a package
    coordinate becomes ``registry/name``, a local path loses its ``./``,
    leading slashes, or drive letter, and a stdio command line is used as is.
    Everything that is not a path character is percent-encoded — including
    ``:``, so the result can never parse as a scheme.
    """
    if _URI_SCHEME.match(target):
        parts = urlsplit(target)
        relative = parts.netloc + parts.path
    elif _PACKAGE_SCHEME.match(target):
        relative = target.replace(":", "/", 1)
    elif _DRIVE_LETTER.match(target):
        relative = target[3:]
    else:
        relative = target
    relative = relative.replace("\\", "/")
    relative = relative.removeprefix("./")
    return quote(relative.lstrip("/"), safe="/@+.-_~=")


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
