"""Skills extension rules (SEP-2640): servers that declare ``io.modelcontextprotocol/skills``.

A server that declares the extension serves Agent Skills as MCP resources and
answers ``skills/list`` and ``skills/get``. These rules judge only such servers;
every other server skips them as not-applicable. The skill format is the Agent
Skills specification (agentskills.io), which SEP-2640 adopts unchanged.
"""

from bisect import bisect_left
from collections.abc import Iterator
from typing import Any, ClassVar

from ..skills import (
    DIGEST_RE,
    SKILL_FILE,
    UNOBSERVED_OUTCOMES,
    SkillFile,
    SkillsEvidence,
    declared_settings,
    manifest,
    markdown_blocks,
    name_problems,
    normalize_newlines,
    normalize_uri,
    parse_frontmatter,
    relative_references,
    resolve_reference,
    size_value,
    skill_path_name,
    skill_root,
    split_frontmatter,
)
from .base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_NOT_APPLICABLE,
    AuditData,
    BaseRule,
    RuleResult,
    RuleSeverity,
)
from .catalog_diagnostics import catalog_result, field_issue, pointer_token
from .catalog_security import _publishable_path, hidden_unicode_classes, injection_classes, secret_classes
from .registry import register_rule

SEP = "MCP Skills Extension (SEP-2640, Final)"
AGENT_SKILLS = "Agent Skills specification (agentskills.io/specification, read 2026-10-18)"


def _entries(evidence: SkillsEvidence) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield the listing entries that are objects, with their listing index."""
    for index, entry in enumerate(evidence.entries or []):
        if isinstance(entry, dict):
            yield index, entry


def _skill_file(evidence: SkillsEvidence, entry: dict[str, Any]) -> SkillFile | None:
    """Return the read of an entry's ``SKILL.md`` when it returned content."""
    uri = entry.get("uri")
    read = evidence.files.get(uri) if isinstance(uri, str) else None
    return read if read is not None and read.error is None and read.text is not None else None


class SkillsBaseRule(BaseRule):
    """Base for rules that judge a server declaring the Skills extension."""

    group_name = "skills"
    group_order = 10
    needs_listing: ClassVar[bool] = True
    """The rule judges ``skills/list`` entries, so it skips when the listing is unavailable or empty."""

    def judges(self, entry: Any) -> bool:
        """Whether this rule has anything to judge in a raw listing entry; it skips when no entry qualifies."""
        return isinstance(entry, dict)

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip unless the server declared the extension and its skills evidence was collected."""
        if audit_data.capabilities is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        if declared_settings(audit_data.capabilities) is None:
            return SKIP_REASON_NOT_APPLICABLE
        evidence = audit_data.skills
        if evidence is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        if self.needs_listing:
            if evidence.entries is None:
                return SKIP_REASON_INSUFFICIENT_DATA
            if not evidence.entries:
                # An empty listing is legal (SEP-2640 §Enumeration): no skill to judge, not a failure. An empty
                # first page with more pages unread says nothing about the catalog.
                return SKIP_REASON_INSUFFICIENT_DATA if evidence.list_incomplete else SKIP_REASON_NOT_APPLICABLE
            if not any(self.judges(entry) for entry in evidence.entries):
                return SKIP_REASON_INSUFFICIENT_DATA
        return None

    @staticmethod
    def _evidence(audit_data: AuditData) -> SkillsEvidence:
        assert audit_data.skills is not None  # noqa: S101 — guaranteed by skip_reason
        return audit_data.skills

    def _result(
        self, *, passed: bool, message: str, details: dict[str, Any], fix: str, issues: list[dict[str, Any]]
    ) -> RuleResult:
        return catalog_result(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=passed,
            message=message,
            details=details,
            suggested_fix=fix,
            issues=issues,
        )


def _issue(index: int | None, path: str, reason: str, expected: str) -> dict[str, Any]:
    return field_issue("skill", index, path, reason, expected)


def _lists_file_at_or_under(listed: set[str], ordered: list[str], target: str) -> bool:
    """Whether the manifest lists *target*, or a file under it (a directory link, SEP-2640 §Directory Listing)."""
    if target in listed:
        return True
    prefix = target + "/"
    position = bisect_left(ordered, prefix)
    return position < len(ordered) and ordered[position].startswith(prefix)


def _json_equal(left: Any, right: Any) -> bool:
    """Compare JSON values the way JSON types them: ``true`` is not ``1``, while ``1`` equals ``1.0``."""
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(_json_equal(left[key], right[key]) for key in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_json_equal(a, b) for a, b in zip(left, right, strict=True))
    return type(left) is type(right) and left == right


def _inside(root: str, uri: str) -> bool:
    """Whether *uri* names a file inside the skill directory *root*, with no ``.``, ``..`` or empty segments."""
    root, uri = normalize_uri(root), normalize_uri(uri)
    if not uri.startswith(root + "/"):
        return False
    # In normal form an encoded "/" stays inside its segment, and an encoded "." or ".." is decoded and caught.
    segments = uri[len(root) + 1 :].split("/")
    return all(segment not in ("", ".", "..") for segment in segments)


def _complete_entry(entry: dict[str, Any], uri: str | None) -> bool:
    """Whether *entry* is a valid skill entry for *uri*, by the rules a listing entry is held to.

    The name is valid and equals the URI's last skill-path segment, the description has 1-1024 characters, and
    the manifest is valid. Values may differ from the listing's: the two are snapshots taken at different times.
    """
    frontmatter = entry.get("frontmatter")
    returned = entry.get("uri")
    if not isinstance(uri, str) or not isinstance(returned, str) or normalize_uri(returned) != normalize_uri(uri):
        return False
    if not isinstance(frontmatter, dict):
        return False
    name, description = frontmatter.get("name"), frontmatter.get("description")
    return (
        isinstance(name, str)
        and bool(name)
        and not name_problems(name)
        and skill_path_name(uri) == name
        and isinstance(description, str)
        and 1 <= len(description) <= 1024
        and not _manifest_issues(0, entry)
    )


@register_rule
class SkillsListSupportedRule(SkillsBaseRule):
    """Medium check: a server declaring the extension answers ``skills/list`` with a ``skills`` array."""

    rule_id = "skills_list_supported"
    basis = f"{SEP} §Enumeration via skills/list (MUST implement), §Capability Declaration"
    rule_order = 1
    needs_listing = False

    @property
    def rule_name(self) -> str:
        return "Skills - skills/list Answers"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when the listing got no answer (timeout or transport failure): that says nothing either way."""
        reason = super().skip_reason(audit_data)
        if reason is None and (self._evidence(audit_data).list_error or {}).get("outcome") in UNOBSERVED_OUTCOMES:
            return SKIP_REASON_INSUFFICIENT_DATA
        return reason

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: ``skills/list`` returns a result carrying a ``skills`` array (it may be empty)."""
        evidence = self._evidence(audit_data)
        error = evidence.list_error
        passed = error is None and not evidence.list_malformed
        if passed:
            message = f"✅ skills/list answered with {len(evidence.entries or [])} skill(s)"
        elif error is not None:
            message = "❌ skills/list failed" + (
                f" with JSON-RPC error {error['error_code']}" if "error_code" in error else ""
            )
        else:
            message = "❌ skills/list answered without a skills array"
        return self._result(
            passed=passed,
            message=message,
            details={"skills": len(evidence.entries or []), "error": error, "incomplete": evidence.list_incomplete},
            fix=(
                "Implement skills/list: return {skills: [...]} with one entry per skill you serve. An empty array is "
                "valid for a catalog you cannot enumerate."
            ),
            issues=[] if passed else [_issue(None, "/skills", "skills_list_failed", "a result with a skills array")],
        )


@register_rule
class SkillsGetSupportedRule(SkillsBaseRule):
    """Medium check: ``skills/get`` returns the entry of a listed skill."""

    rule_id = "skills_get_supported"
    basis = f"{SEP} §Retrieval via skills/get (MUST implement; MUST answer for every skill served)"
    rule_order = 2

    @property
    def rule_name(self) -> str:
        return "Skills - skills/get Answers"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when no listed skill had a URI to ask for, or the call got no answer."""
        reason = super().skip_reason(audit_data)
        if reason is not None:
            return reason
        evidence = self._evidence(audit_data)
        if evidence.get_uri is None:
            return SKIP_REASON_NOT_APPLICABLE
        if (evidence.get_error or {}).get("outcome") in UNOBSERVED_OUTCOMES:
            return SKIP_REASON_INSUFFICIENT_DATA
        return None

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: ``skills/get`` for the first listed ``SKILL.md`` URI returns a complete skill entry.

        The entry has the same shape as a listing entry: that URI, the frontmatter with ``name`` and
        ``description``, and a valid ``resources`` manifest. Its values may differ from the listing's, since the
        two are snapshots taken at different times.
        """
        evidence = self._evidence(audit_data)
        entry = evidence.get_entry
        passed = evidence.get_error is None and isinstance(entry, dict) and _complete_entry(entry, evidence.get_uri)
        if passed:
            message = "✅ skills/get returned the entry of a listed skill"
        elif evidence.get_error is not None:
            code = evidence.get_error.get("error_code")
            message = "❌ skills/get failed for a listed skill" + (f" with JSON-RPC error {code}" if code else "")
        else:
            message = "❌ skills/get did not return a complete skill entry for the requested URI"
        return self._result(
            passed=passed,
            message=message,
            details={"error": evidence.get_error},
            fix=(
                "Implement skills/get: given a skill's SKILL.md URI, return {skill: {...}}, the same entry skills/list "
                "carries, for every skill you serve."
            ),
            issues=[] if passed else [_issue(None, "/skill", "skills_get_failed", "a skill entry for the listed URI")],
        )


@register_rule
class SkillsResourcesCapabilityRule(SkillsBaseRule):
    """Medium check: a server declaring the extension also declares the ``resources`` capability."""

    rule_id = "skills_resources_capability"
    basis = f"{SEP} §Capability Declaration (MUST also declare the resources capability)"
    rule_order = 3
    needs_listing = False

    @property
    def rule_name(self) -> str:
        return "Skills - Resources Capability Declared"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: skill files are served as resources, so the ``resources`` capability must be declared."""
        passed = getattr(audit_data.capabilities, "resources", None) is not None
        return self._result(
            passed=passed,
            message=(
                "✅ The resources capability is declared alongside the skills extension"
                if passed
                else "❌ The skills extension is declared without the resources capability"
            ),
            details={},
            fix="Declare the resources capability: clients read skill files with resources/read.",
            issues=[]
            if passed
            else [_issue(None, "/capabilities/resources", "missing_capability", "a resources capability")],
        )


@register_rule
class SkillsEntriesWellFormedRule(SkillsBaseRule):
    """Medium check: every listing entry has a string ``uri`` and frontmatter with ``name`` and ``description``."""

    rule_id = "skills_entries_well_formed"

    def judges(self, entry: Any) -> bool:
        """Judge every entry: one that is not an object is itself the finding."""
        return True

    basis = f"{SEP} §Enumeration via skills/list (result fields), §Frontmatter; {AGENT_SKILLS} §Frontmatter"
    rule_order = 4

    @property
    def rule_name(self) -> str:
        return "Skills - Listing Entries Well-Formed"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: each entry is an object with ``uri`` and a frontmatter object holding non-empty strings.

        The frontmatter is the skill's ``SKILL.md`` YAML frontmatter rendered as JSON; Agent Skills requires
        ``name`` and a ``description`` of 1-1024 characters.
        """
        issues = []
        for index, entry in enumerate(self._evidence(audit_data).entries or []):
            if not isinstance(entry, dict):
                issues.append(_issue(index, "", "not_an_object", "a skill entry object"))
                continue
            if not isinstance(entry.get("uri"), str) or not entry["uri"]:
                issues.append(_issue(index, "/uri", "missing_uri", "the URI of the skill's SKILL.md"))
            frontmatter = entry.get("frontmatter")
            if not isinstance(frontmatter, dict):
                issues.append(_issue(index, "/frontmatter", "missing_frontmatter", "the SKILL.md frontmatter as JSON"))
                continue
            if not isinstance(frontmatter.get("name"), str) or not frontmatter["name"]:
                issues.append(_issue(index, "/frontmatter/name", "missing_name", "a non-empty name"))
            description = frontmatter.get("description")
            if not isinstance(description, str) or not 1 <= len(description) <= 1024:
                issues.append(
                    _issue(
                        index, "/frontmatter/description", "invalid_description", "a description of 1-1024 characters"
                    )
                )
        passed = not issues
        return self._result(
            passed=passed,
            message="✅ Every skills/list entry is well-formed"
            if passed
            else f"❌ Number of skills/list entry problems: {len(issues)}",
            details={},
            fix=(
                "Give every skills/list entry a uri (the SKILL.md resource URI) and a frontmatter object copied from "
                "SKILL.md, with a name and a description of at most 1024 characters."
            ),
            issues=issues,
        )


def _manifest_issues(index: int, entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Check one entry's ``resources``: ``"dynamic"`` or a complete array of ``{uri, digest, size}``."""
    resources = entry.get("resources")
    if resources == "dynamic":
        return []
    if not isinstance(resources, list):
        return [_issue(index, "/resources", "missing_resources", 'an array of skill files or "dynamic"')]
    issues: list[dict[str, Any]] = []
    uri = entry.get("uri")
    root = skill_root(uri) if isinstance(uri, str) else None
    seen: set[str] = set()
    for position, item in enumerate(resources):
        path = f"/resources/{position}"
        if not isinstance(item, dict) or not isinstance(item.get("uri"), str):
            issues.append(_issue(index, path, "invalid_file_entry", "an object with uri, digest and size"))
            continue
        if not isinstance(item.get("digest"), str) or not DIGEST_RE.fullmatch(item["digest"]):
            issues.append(_issue(index, f"{path}/digest", "invalid_digest", "sha256: followed by 64 lowercase hex"))
        if size_value(item.get("size")) is None:
            issues.append(_issue(index, f"{path}/size", "invalid_size", "the file's length in bytes"))
        # Compared in RFC 3986 normal form: two spellings of one URI are one file.
        normal = normalize_uri(item["uri"])
        if normal in seen:
            issues.append(_issue(index, f"{path}/uri", "duplicate_file", "each file listed once"))
        seen.add(normal)
        if (
            root is not None
            and isinstance(uri, str)
            and normal != normalize_uri(uri)
            and not _inside(root, item["uri"])
        ):
            issues.append(_issue(index, f"{path}/uri", "outside_skill", "a file inside the skill directory"))
    if isinstance(uri, str) and normalize_uri(uri) not in seen:
        issues.append(_issue(index, "/resources", "skill_file_unlisted", "an entry for the skill's SKILL.md"))
    return issues


@register_rule
class SkillsResourcesManifestRule(SkillsBaseRule):
    """Medium check: each skill lists its files with digests and sizes, or declares itself dynamic."""

    rule_id = "skills_resources_manifest"
    basis = f'{SEP} §Resources (REQUIRED; complete array or "dynamic"), §Integrity and verification (digest format)'
    rule_order = 5

    @property
    def rule_name(self) -> str:
        return "Skills - File Manifest Valid"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: ``resources`` is ``"dynamic"`` or a complete array of valid ``{uri, digest, size}`` items.

        The array lists every file once, including the entry's ``SKILL.md``, all inside the skill directory.
        Hosts must not load an entry without it.
        """
        evidence = self._evidence(audit_data)
        issues = [issue for index, entry in _entries(evidence) for issue in _manifest_issues(index, entry)]
        dynamic = sum(1 for _, entry in _entries(evidence) if entry.get("resources") == "dynamic")
        passed = not issues
        return self._result(
            passed=passed,
            message="✅ Every skill lists its files with digests and sizes, or is marked dynamic"
            if passed
            else f"❌ Number of skill file manifest problems: {len(issues)}",
            details={"dynamic_skills": dynamic},
            fix=(
                "Set resources on every entry: list each file once, SKILL.md included, as "
                '{uri, digest: "sha256:<hex>", size}, or set "dynamic" for generated skills.'
            ),
            issues=issues,
        )


@register_rule
class SkillsNameMatchesUriRule(SkillsBaseRule):
    """Medium check: a skill's URI ends in ``<name>/SKILL.md``."""

    rule_id = "skills_name_matches_uri"

    def judges(self, entry: Any) -> bool:
        """Judge entries with a string URI and a string frontmatter name."""
        frontmatter = entry.get("frontmatter") if isinstance(entry, dict) else None
        return (
            isinstance(entry, dict)
            and isinstance(entry.get("uri"), str)
            and isinstance(frontmatter, dict)
            and isinstance(frontmatter.get("name"), str)
        )

    basis = f"{SEP} §Resource Mapping (final skill-path segment MUST equal the frontmatter name), §Frontmatter"
    rule_order = 6

    @property
    def rule_name(self) -> str:
        return "Skills - Name Matches URI"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: the URI ends in ``/SKILL.md`` and its last skill-path segment equals ``frontmatter.name``.

        That is what lets a host recover the skill name from the URI alone.
        """
        issues = []
        for index, entry in _entries(self._evidence(audit_data)):
            uri, frontmatter = entry.get("uri"), entry.get("frontmatter")
            name = frontmatter.get("name") if isinstance(frontmatter, dict) else None
            if not isinstance(uri, str) or not isinstance(name, str):
                continue
            if skill_root(uri) is None:
                issues.append(_issue(index, "/uri", "not_skill_md", f"a URI ending in /{SKILL_FILE}"))
            elif skill_path_name(uri) != name:
                issues.append(_issue(index, "/uri", "name_mismatch", "a skill path whose last segment is the name"))
        passed = not issues
        return self._result(
            passed=passed,
            message="✅ Every skill URI ends in <name>/SKILL.md"
            if passed
            else f"❌ Number of skills whose URI does not match their name: {len(issues)}",
            details={},
            fix=(
                "Serve each skill at <prefix>/<name>/SKILL.md, where <name> is the frontmatter name, "
                "e.g. skill://acme/billing/refunds/SKILL.md for name: refunds."
            ),
            issues=issues,
        )


@register_rule
class SkillsNameValidRule(SkillsBaseRule):
    """Medium check: skill names follow the Agent Skills naming rules."""

    rule_id = "skills_name_valid"

    def judges(self, entry: Any) -> bool:
        """Judge entries with a non-empty string frontmatter name."""
        frontmatter = entry.get("frontmatter") if isinstance(entry, dict) else None
        return isinstance(frontmatter, dict) and isinstance(frontmatter.get("name"), str) and bool(frontmatter["name"])

    basis = f"{AGENT_SKILLS} §name field; {SEP} §Resource Mapping (the name MUST satisfy the naming rules)"
    rule_order = 7

    @property
    def rule_name(self) -> str:
        return "Skills - Names Valid"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.MEDIUM

    def check(self, audit_data: AuditData) -> RuleResult:
        """Medium check: 1-64 lowercase letters or digits (Unicode allowed) and single hyphens, not at either end."""
        issues = []
        for index, entry in _entries(self._evidence(audit_data)):
            frontmatter = entry.get("frontmatter")
            name = frontmatter.get("name") if isinstance(frontmatter, dict) else None
            if isinstance(name, str) and name and name_problems(name):
                issues.append(
                    {
                        **_issue(
                            index,
                            "/frontmatter/name",
                            "invalid_name",
                            "1-64 lowercase letters, digits and single hyphens",
                        ),
                        "problems": name_problems(name),
                    }
                )
        passed = not issues
        return self._result(
            passed=passed,
            message="✅ Every skill name follows the Agent Skills naming rules"
            if passed
            else f"❌ Number of skills with invalid names: {len(issues)}",
            details={},
            fix=(
                "Rename the skill with lowercase letters, digits and single hyphens, at most 64 characters, not "
                "starting or ending with a hyphen, and rename its directory to match."
            ),
            issues=issues,
        )


def _listed_size(item: dict[str, Any]) -> int | None:
    return size_value(item.get("size"))


def _listed_digest(item: dict[str, Any]) -> str | None:
    digest = item.get("digest")
    return digest if isinstance(digest, str) and DIGEST_RE.fullmatch(digest) else None


def _listed_files(evidence: SkillsEvidence) -> Iterator[tuple[int, int, dict[str, Any], SkillFile]]:
    """Yield each read file whose manifest item lists a valid size or digest, with its index and position.

    Reads match items in RFC 3986 normal form, and every read of an item is yielded, so a file read under two
    spellings is judged on both responses. An item without size or digest has nothing to verify against;
    skills_resources_manifest reports it.
    """
    reads: dict[str, list[SkillFile]] = {}
    for read_uri, read in evidence.files.items():
        reads.setdefault(normalize_uri(read_uri), []).append(read)
    for index, entry in _entries(evidence):
        for position, item in enumerate(manifest(entry) or []):
            uri = item.get("uri") if isinstance(item, dict) else None
            for read in reads.get(normalize_uri(uri), []) if isinstance(uri, str) else []:
                if read.error not in (None, "too_large"):
                    continue
                # An oversized read kept only its length: it can still contradict a listed size.
                if _listed_size(item) is not None or (read.error is None and _listed_digest(item) is not None):
                    yield index, position, item, read


@register_rule
class SkillsDigestIntegrityRule(SkillsBaseRule):
    """High check: skill files served match the digest and size the listing promised."""

    rule_id = "skills_digest_integrity"
    basis = f"{SEP} §Integrity and verification (hosts MUST NOT use content that fails the digest or size)"
    rule_order = 8

    @property
    def rule_name(self) -> str:
        return "Skills - Files Match Their Digests"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when no file with a listed digest was read (dynamic skills only, or every read failed)."""
        reason = super().skip_reason(audit_data)
        if reason is None and next(_listed_files(self._evidence(audit_data)), None) is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        return reason

    def check(self, audit_data: AuditData) -> RuleResult:
        """High check: each read file's byte length equals ``size`` and its SHA-256 equals ``digest``.

        A mismatch means hosts refuse the file: the content is not what users approved from the listing.
        """
        evidence = self._evidence(audit_data)
        issues, checked = [], 0
        for index, position, item, read in _listed_files(evidence):
            checked += 1
            size, digest = _listed_size(item), _listed_digest(item)
            if size is not None and read.size != size:
                issues.append(_issue(index, f"/resources/{position}/size", "size_mismatch", "the served byte length"))
            elif digest is not None and read.digest is not None and read.digest != digest:
                issues.append(_issue(index, f"/resources/{position}/digest", "digest_mismatch", "the served SHA-256"))
        passed = not issues
        return self._result(
            passed=passed,
            message=f"✅ {checked} skill file(s) match their listed digest and size"
            if passed
            else f"❌ Number of skill files that do not match their listing: {len(issues)} of {checked} read",
            details={"files_checked": checked, "budget_exhausted": evidence.budget_exhausted},
            fix=(
                "Recompute each file's digest and size from the exact bytes resources/read returns, and refresh the "
                "listing whenever a skill file changes."
            ),
            issues=issues,
        )


@register_rule
class SkillsFrontmatterMatchesRule(SkillsBaseRule):
    """High check: the served ``SKILL.md`` frontmatter is the frontmatter the listing shows."""

    rule_id = "skills_frontmatter_matches"
    basis = (
        f"{SEP} §Frontmatter (MUST be identical in content), §Integrity and verification (hosts MUST compare "
        f"field by field); {AGENT_SKILLS} §SKILL.md format"
    )
    rule_order = 9

    @property
    def rule_name(self) -> str:
        return "Skills - SKILL.md Frontmatter Matches Listing"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when no listed ``SKILL.md`` was read."""
        reason = super().skip_reason(audit_data)
        evidence = audit_data.skills
        if (
            reason is None
            and evidence is not None
            and not any(
                _skill_file(evidence, entry) and isinstance(entry.get("frontmatter"), dict)
                for _, entry in _entries(evidence)
            )
        ):
            return SKIP_REASON_INSUFFICIENT_DATA
        return reason

    def check(self, audit_data: AuditData) -> RuleResult:
        """High check: each read ``SKILL.md`` starts with YAML frontmatter equal to the entry's ``frontmatter``.

        Hosts parse the served file and refuse the skill on any difference, so what users approve from the
        listing is what the model receives.
        """
        evidence = self._evidence(audit_data)
        issues, checked = [], 0
        for index, entry in _entries(evidence):
            read = _skill_file(evidence, entry)
            if read is None or not isinstance(entry.get("frontmatter"), dict):
                continue
            checked += 1
            try:
                served = parse_frontmatter(read.text or "")
            except ValueError:
                issues.append(_issue(index, f"/{SKILL_FILE}", "frontmatter_unparseable", "YAML frontmatter"))
                continue
            if not _json_equal(served, entry["frontmatter"]):
                issues.append(_issue(index, "/frontmatter", "frontmatter_mismatch", "the served SKILL.md frontmatter"))
        passed = not issues
        return self._result(
            passed=passed,
            message=f"✅ {checked} served SKILL.md file(s) carry the frontmatter their listing shows"
            if passed
            else f"❌ Number of SKILL.md files whose frontmatter differs from the listing: {len(issues)} of {checked}",
            details={"skills_checked": checked},
            fix=(
                "Build the listing's frontmatter by parsing the served SKILL.md, so both always carry the same "
                "fields and values."
            ),
            issues=issues,
        )


@register_rule
class SkillsReferencesResolveRule(SkillsBaseRule):
    """Low check: relative links in ``SKILL.md`` point at files the skill lists."""

    rule_id = "skills_references_resolve"
    basis = (
        f"{SEP} §Reading (relative references resolve against the skill root), §Resources (complete file list); "
        f"{AGENT_SKILLS} §File references"
    )
    rule_order = 10

    @property
    def rule_name(self) -> str:
        return "Skills - SKILL.md References Resolve"

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.LOW

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when no ``SKILL.md`` of a skill with a file manifest was read."""
        reason = super().skip_reason(audit_data)
        evidence = audit_data.skills
        if (
            reason is None
            and evidence is not None
            and not any(
                (read := _skill_file(evidence, entry)) is not None
                and manifest(entry)
                and skill_root(str(entry.get("uri"))) is not None
                and relative_references(_body(read.text or "")) is not None
                for _, entry in _entries(evidence)
            )
        ):
            return SKIP_REASON_INSUFFICIENT_DATA
        return reason

    def check(self, audit_data: AuditData) -> RuleResult:
        """Low check: every relative Markdown link in a read ``SKILL.md`` body names a file in the skill's manifest.

        Hosts may read only listed files while acting on a skill, so a link to anything else is a dead end for
        the agent.
        """
        evidence = self._evidence(audit_data)
        issues, references, unparsed = [], 0, 0
        for index, entry in _entries(evidence):
            read, files = _skill_file(evidence, entry), manifest(entry)
            root = skill_root(entry["uri"]) if isinstance(entry.get("uri"), str) else None
            if read is None or files is None or root is None:
                continue
            # Compared in RFC 3986 normal form: "b c.png" matches "b%20c.png", while "%3B" never matches ";".
            listed = {
                normalize_uri(item["uri"])
                for item in files
                if isinstance(item, dict) and isinstance(item.get("uri"), str)
            }
            ordered = sorted(listed)
            targets = relative_references(_body(read.text or ""))
            if targets is None:
                unparsed += 1
                continue
            for target in targets:
                references += 1
                resolved = resolve_reference(normalize_uri(root), normalize_uri(target))
                if resolved is None or not _lists_file_at_or_under(listed, ordered, resolved):
                    issues.append(
                        _issue(index, f"/{SKILL_FILE}", "unresolved_reference", "a link to a file the skill lists")
                    )
        passed = not issues
        return self._result(
            passed=passed,
            message=f"✅ All {references} relative link(s) in SKILL.md files point at listed skill files"
            if passed
            else f"❌ Number of SKILL.md links to files the skill does not list: {len(issues)} of {references}",
            details={"references_checked": references, "skills_too_large_to_parse": unparsed},
            fix=(
                "Link supporting files by their path relative to the skill root (references/GUIDE.md) and list each "
                "linked file in the skill's resources."
            ),
            issues=issues,
        )


def _body(text: str) -> str:
    """Return a ``SKILL.md`` body without its frontmatter."""
    split = split_frontmatter(text)
    return split[1] if split else text


def _strings(value: Any, path: str) -> Iterator[tuple[str, str]]:
    """Yield (location, text) for every string and key in a JSON value; a key is located at its parent."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            # The key is scanned at its parent's location, so a finding never publishes it.
            yield path, str(key)
            yield from _strings(item, f"{path}/{pointer_token(str(key))}")
    elif isinstance(value, list):
        for position, item in enumerate(value):
            yield from _strings(item, f"{path}/{position}")


def _decoded_served_strings(text: str, listed: Any) -> Iterator[str]:
    """Yield the decoded strings of served frontmatter that differs from the listing's (already scanned)."""
    try:
        served = parse_frontmatter(text)
    except ValueError:
        return
    if not _json_equal(served, listed):
        for _, value in _strings(served, ""):
            yield value


def _skill_texts(evidence: SkillsEvidence) -> Iterator[tuple[int | None, str, str, str, str]]:
    """Yield (listing index, location, source, rendered, prose) for frontmatter strings and ``SKILL.md`` blocks.

    ``SKILL.md`` is scanned a paragraph or fenced code block at a time, so a directive wrapped across lines is
    still one string; the location is the block's first line.
    """
    for index, entry in _entries(evidence):
        for path, text in _strings(entry.get("frontmatter"), "/frontmatter"):
            yield index, path, text, text, text
        read = _skill_file(evidence, entry)
        if read is not None:
            text = normalize_newlines(read.text or "")
            split = split_frontmatter(text)
            # The frontmatter is scanned as YAML text, never as Markdown: a fence inside a block scalar must not
            # turn the body that follows into "code".
            if split is not None:
                # The whole header, delimiter lines included, so nothing hidden on a delimiter escapes the scan.
                header = text[: len(text) - len(split[1])]
                yield index, f"/{SKILL_FILE}#L1", header, header, header
                # YAML escapes decode only when parsed: served values that differ from the listing's are judged
                # decoded too, under the header's location so a finding never publishes a key.
                for value in _decoded_served_strings(text, entry.get("frontmatter")):
                    yield index, f"/{SKILL_FILE}#L1", value, value, value
                body, first_line = split[1], split[0].count("\n") + 3
            else:
                body, first_line = text, 1
            for block in markdown_blocks(body, first_line):
                yield index, f"/{SKILL_FILE}#L{block.line}", block.text, block.rendered, block.prose
    # The sampled skills/get entry is its own snapshot: frontmatter that differs from the listing's is scanned
    # too, under its own location; identical frontmatter was already scanned.
    got = evidence.get_entry
    if isinstance(got, dict):
        got_uri = got.get("uri")
        listed = next(
            (
                (i, e)
                for i, e in _entries(evidence)
                if isinstance(got_uri, str)
                and isinstance(e.get("uri"), str)
                and normalize_uri(e["uri"]) == normalize_uri(got_uri)
            ),
            None,
        )
        if listed is None or not _json_equal(got.get("frontmatter"), listed[1].get("frontmatter")):
            for path, text in _strings(got.get("frontmatter"), "/skills/get/frontmatter"):
                yield listed[0] if listed else None, path, text, text, text


class SkillsSecurityRule(SkillsBaseRule):
    """Base for the catalog security checks applied to skill frontmatter and ``SKILL.md`` text."""

    group_name = "security"
    group_order = 3
    issue_reason: ClassVar[str]
    expected: ClassVar[str]
    passed_message: ClassVar[str]
    failure_label: ClassVar[str]
    fix: ClassVar[str]
    allowed_in_code: ClassVar[frozenset[str]] = frozenset()
    """Classes that do not count inside code (fenced blocks and inline spans), where a skill shows examples."""

    def matches(self, text: str) -> list[str]:
        """Return the class name of each finding in *text*."""
        raise NotImplementedError

    def skip_reason(self, audit_data: AuditData) -> str | None:
        """Skip when no skill text was observed: no frontmatter string and no ``SKILL.md`` read."""
        reason = super().skip_reason(audit_data)
        if reason is None and next(_skill_texts(self._evidence(audit_data)), None) is None:
            return SKIP_REASON_INSUFFICIENT_DATA
        return reason

    @property
    def severity(self) -> RuleSeverity:
        return RuleSeverity.HIGH

    def check(self, audit_data: AuditData) -> RuleResult:
        """Scan skill text and report locations (listing index and line), never the matched text."""
        issues, classes = [], set()
        for index, path, source, rendered, prose_text in _skill_texts(self._evidence(audit_data)):
            # The source, and the rendered text (markup removed, inline code kept), count every class but those
            # exempt in code; the prose (code removed) counts every class. Markup or a code span can split a
            # directive in the source, but not in what a reader sees.
            found: list[str] = []
            for text, exempt in ((source, True), (rendered, True), (prose_text, False)):
                for name in self.matches(text):
                    if name not in found and not (exempt and name in self.allowed_in_code):
                        found.append(name)
            if found:
                classes.update(found)
                # A frontmatter key can itself be the finding; the published path stops above it.
                published, truncated = _publishable_path(path)
                issue = {**_issue(index, published, self.issue_reason, self.expected), "matched": sorted(set(found))}
                issues.append({**issue, "path_truncated": True} if truncated else issue)
        passed = not issues
        return self._result(
            passed=passed,
            message=f"✅ {self.passed_message}" if passed else f"❌ Number of {self.failure_label}: {len(issues)}",
            details={"matched": sorted(classes)},
            fix=self.fix,
            issues=issues,
        )


_SECURITY_BASIS = (
    f"{SEP} §Security Implications (skill content is untrusted input); OWASP MCP Top 10 (beta) MCP03:2025 Tool "
    "Poisoning and MCP06:2025 Prompt Injection via Contextual Payloads"
)


@register_rule
class SkillsHiddenUnicodeRule(SkillsSecurityRule):
    """High check: skill text carries no invisible characters."""

    rule_id = "skills_hidden_unicode"
    basis = f"{_SECURITY_BASIS}; Unicode UTS #51 §2.8, CVE-2021-42574"
    rule_order = 23
    issue_reason = "hidden_unicode"
    expected = "visible text without tag characters, bidirectional controls, control characters or invisible runs"
    passed_message = "Skill text contains no hidden Unicode characters"
    failure_label = "skill text locations with hidden Unicode characters"
    fix = (
        "Remove the invisible characters from the listed skill locations; text a reviewer cannot see should not "
        "reach the model."
    )

    @property
    def rule_name(self) -> str:
        return "No Hidden Unicode in Skills"

    def matches(self, text: str) -> list[str]:
        """Return the hidden-Unicode classes found in *text*."""
        return hidden_unicode_classes(text)


@register_rule
class SkillsNoEmbeddedSecretsRule(SkillsSecurityRule):
    """High check: skill text carries no credentials."""

    rule_id = "skills_no_embedded_secrets"
    basis = f"{SEP} §Security Implications; OWASP MCP Top 10 (beta) MCP01:2025 Token Mismanagement & Secret Exposure"
    rule_order = 24
    issue_reason = "embedded_secret"
    expected = "no provider-issued credentials in skill text"
    passed_message = "Skill text contains no embedded credentials"
    failure_label = "skill text locations with embedded credentials"
    fix = (
        "Remove the credential from the skill, revoke it with its provider, and have the skill read secrets from "
        "the environment instead."
    )

    @property
    def rule_name(self) -> str:
        return "No Secrets in Skills"

    def matches(self, text: str) -> list[str]:
        """Return the secret classes found in *text*."""
        return secret_classes(text)


@register_rule
class SkillsPromptInjectionPhrasingRule(SkillsSecurityRule):
    """High check: skill text does not address the model with hidden directives."""

    rule_id = "skills_prompt_injection_phrasing"
    basis = _SECURITY_BASIS
    rule_order = 25
    allowed_in_code = frozenset({"chat_template_token"})
    issue_reason = "prompt_injection_phrasing"
    expected = "instructions for the task, without directives about earlier instructions, roles or the user"
    passed_message = "Skill text contains no prompt-injection phrasing"
    failure_label = "skill text locations with prompt-injection phrasing"
    fix = (
        "Rewrite the listed skill lines as instructions for the task. Remove directives to override earlier "
        "instructions, change role, or keep anything from the user."
    )

    @property
    def rule_name(self) -> str:
        return "No Prompt-Injection Phrasing in Skills"

    def matches(self, text: str) -> list[str]:
        """Return the injection-phrasing classes found in *text*."""
        return injection_classes(text)
