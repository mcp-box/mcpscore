"""SARIF 2.1.0 export of an audit's findings, for GitHub code scanning (``--sarif``).

SARIF is a findings format, not a report format: every **failed** rule becomes
one ``result``; passed and skipped rules are not results. The ``--json``
report remains the complete record of a run. The two are built from the same
report dictionary, so they cannot disagree.

Shape (one ``run``):

- ``tool.driver`` names mcpscore, its version, and the docs site; ``rules[]``
  carries one entry per rule that produced a finding, with the rule's name,
  its primary-source basis where the rule declares one, and a help link to
  the rules reference. GitHub requires ``shortDescription``,
  ``fullDescription`` and ``help`` text on every rule, so every entry has
  all three.
- Each ``result`` maps the rule's severity to a SARIF level (critical and
  high → ``error``, medium → ``warning``, low → ``note``). A readiness rule
  that this run did not count in the main score is informative, so it is a
  ``note`` whatever its severity: the Security tab must not show as an error
  something the score itself waves through.
- SARIF requires a physical location, and GitHub requires it to be a path
  relative to the repository: ``upload-sarif`` hands GitHub a ``file://``
  checkout root, and an absolute URI with any other scheme (``https://``,
  ``npm:``) makes GitHub reject the whole upload. An audit has no source
  file, so the location is a repository-relative path standing for the
  target (``mcp.example.com/mcp`` for a URL, ``npm/name`` for a package, the
  file itself for a local server), as a zero-length point at line 1, column 1
  (GitHub requires all four region fields). Nothing is annotated in a pull
  request diff: GitHub annotates only alerts whose lines are in the diff,
  and these findings are about a running server, not a line of source.
- ``partialFingerprints.primaryLocationLineHash`` — the one fingerprint key
  GitHub reads — is a hash of the rule id and the target's identity, so a
  re-upload for the same server updates the alert instead of opening a new
  one. ``upload-sarif`` keeps an existing value (it computes one only for
  locations it can read from disk, which these are not).
- No ``automationDetails``: ``upload-sarif`` assigns a category per workflow
  and job when the file carries none, and its ``category`` input is the
  standard way to keep two servers audited in one job apart. Fingerprints
  only have to be distinct within a category, so the identity below can be
  coarse.
- Security rules carry GitHub's ``security-severity`` score so they sort
  into the Security tab's critical/high/medium/low bands.

What the file shows of the target — and this is the whole rule, there is no
heuristic behind it: a URL's scheme, host, port and path; a stdio command's
program name; a local path; a package coordinate. Never a URL's userinfo,
query or fragment, never a command's arguments, never rule ``details``
(transport and security rules record the audited URL there verbatim). URLs
quoted in rule messages (auth rules cite server-supplied metadata and issuer
URLs) are cut down the same way. The identity that is hashed is that shown
form, so nothing the file hides enters a hash either. Code scanning data is
readable by everyone who can read the repository's alerts, a wider audience
than a local report; what this export cannot do is guess which part of a
path or a program name is secret, and the CLI already says never to put a
credential in a URL or on a command line — ``--token``, ``--header`` and
``--env NAME`` exist for that.
"""

from __future__ import annotations

import hashlib
from pathlib import PurePath
import re
import shlex
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

INVALID_URL = "<invalid-url>"
"""What a syntactically unusable URL (a non-numeric port, say) becomes in the file; it is server-supplied text."""

_URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_PACKAGE_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]+:")  # npm:, pypi: — two+ letters, so C:\ is a path
_DRIVE_LETTER = re.compile(r"^[A-Za-z]:[\\/]")
_URL_IN_TEXT = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://\S+")
_TRAILING_PUNCTUATION = re.compile(r"['\")\],.;:>]+$")


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
        run_properties["partial_reason"] = scrub_urls(str(report["partial_reason"]))
    if package is not None:
        # The registry supplies repository_url and error text; scrub them like any URL.
        run_properties["package"] = {k: scrub_urls(v) if isinstance(v, str) else v for k, v in package.items()}
    if report.get("transport") is not None:
        run_properties["transport"] = report["transport"]
    if report.get("incomplete_listings"):
        # The run says which listings paginated incompletely, so a reader can
        # tell a finding closed by a transient pagination failure from a fix.
        run_properties["incomplete_listings"] = sorted(report["incomplete_listings"])

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
    # No `details`: several rules record the audited URL there verbatim, and
    # the message plus the rule's basis already say what failed. The --json
    # report keeps the details.
    return {
        "ruleId": res["rule_id"],
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": scrub_urls(res["message"])},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _artifact_uri(shown), "index": 0},
                    "region": POINT_REGION,
                }
            }
        ],
        "partialFingerprints": {FINGERPRINT_KEY: fingerprint(res["rule_id"], target)},
        "properties": {
            "severity": severity,
            "severity_value": res.get("severity_value"),
            "readiness": is_readiness,
            "counted_in_score": not informative,
        },
    }


def fingerprint(rule_id: str, target: str) -> str:
    """Stable fingerprint of a finding: the same rule on the same target hashes the same across runs.

    The target enters by ``target_identity``, the shown form of the target,
    so nothing the file hides is in the digest.
    """
    digest = hashlib.sha256(f"{rule_id}\n{target_identity(target)}".encode()).hexdigest()
    return digest[:32]


def target_identity(target: str) -> str:
    """Return the target as alerts are keyed on: its shown form, minus one trailing slash on a URL path.

    ``/mcp`` and ``/mcp/`` are one server (the engine follows that redirect
    as same-origin), so they must be one series of alerts; ``/mcp//`` is a
    different path and stays different.
    """
    shown = display_target(target)
    if _URI_SCHEME.match(shown) and shown.endswith("/"):
        return shown[:-1]
    return shown


def display_target(target: str) -> str:
    """Return the target as the file shows it, and all of it that the file shows.

    A URL keeps scheme, host, port and path; userinfo, query and fragment
    never appear. A URL that cannot be parsed (server-supplied text can be
    anything) becomes ``INVALID_URL``. A stdio command line shows its
    program's name only (``npx``, ``python3``, ``server``): the arguments
    are where a secret passed on a command line sits, and no parser of
    arbitrary command lines can tell a package name from a password. A local
    path or a package coordinate (no whitespace) is itself.
    """
    if _URI_SCHEME.match(target):
        try:
            parts = urlsplit(target)
            return urlunsplit((parts.scheme, _host_port(parts), parts.path, "", ""))
        except ValueError:
            return INVALID_URL
    if any(ch.isspace() for ch in target):
        try:
            program = shlex.split(target)[0]
        except (ValueError, IndexError):
            program = target.split()[0]
        return PurePath(program).name
    return target


def scrub_urls(text: str) -> str:
    """Return ``text`` with every URL in it reduced to its displayable form (no userinfo, query, or fragment).

    Rule messages quote URLs the server supplied (a challenge's
    ``resource_metadata``, an issuer), and those can carry credentials as
    easily as the target can.
    """

    def replace(match: re.Match[str]) -> str:
        # Greedy to the next whitespace, so a credential containing a comma or
        # a quote cannot survive as a suffix; closing punctuation that merely
        # follows the URL in prose is put back after the scrubbed form.
        url = match.group(0)
        trailing = _TRAILING_PUNCTUATION.search(url)
        if trailing:
            url = url[: trailing.start()]
        return display_target(url) + (trailing.group(0) if trailing else "")

    return _URL_IN_TEXT.sub(replace, text)


def _host_port(parts: SplitResult) -> str:
    """Return ``host`` or ``host:port`` from a split URL, never its userinfo."""
    host = parts.hostname or ""
    if ":" in host:  # an IPv6 literal keeps its brackets
        host = f"[{host}]"
    return f"{host}:{parts.port}" if parts.port is not None else host


def _artifact_uri(shown: str) -> str:
    """Return a repository-relative path standing for the shown target, the only location GitHub accepts.

    A URL keeps its host and path (``mcp.example.com/mcp``), a package
    coordinate becomes ``registry/name``, a local path loses its ``./``,
    leading slashes, drive letter and any ``..`` segment (the path must not
    resolve outside the checkout), and a program name is used as is.
    Everything that is not a path character is percent-encoded — including
    ``:``, so the result can never parse as a scheme.
    """
    if _URI_SCHEME.match(shown):
        parts = urlsplit(shown)
        relative = parts.netloc + parts.path
    elif _PACKAGE_SCHEME.match(shown):
        relative = shown.replace(":", "/", 1)
    elif _DRIVE_LETTER.match(shown):
        relative = shown[3:]
    else:
        relative = shown
    segments = [seg for seg in relative.replace("\\", "/").split("/") if seg not in ("", ".", "..")]
    return quote("/".join(segments), safe="/@+.-_~=")


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
