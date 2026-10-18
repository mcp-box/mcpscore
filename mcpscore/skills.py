"""Collect evidence about a server's Skills extension (SEP-2640) for the skills rules.

A server that declares ``io.modelcontextprotocol/skills`` serves Agent Skills as
MCP resources and answers ``skills/list`` and ``skills/get``. This module lists
the skills, asks ``skills/get`` for one of them, and reads a bounded sample of
skill files so the rules can compare what was served with what the listing
promised. Skill content is untrusted text: it is hashed, parsed as YAML
frontmatter with ``yaml.safe_load`` and scanned, never executed or followed.
"""

import asyncio
import base64
from dataclasses import dataclass, field
import hashlib
import json
import logging
import posixpath
import re
from typing import Any, Protocol
from urllib.parse import urlsplit

from pydantic import ValidationError
import yaml

logger = logging.getLogger(__name__)

SKILLS_EXTENSION = "io.modelcontextprotocol/skills"
"""Extension identifier a server declares under ``capabilities.extensions``."""

SKILL_FILE = "SKILL.md"

MAX_LIST_PAGES = 20
"""Pages of ``skills/list`` collected before the listing counts as incomplete."""

MAX_SKILL_FILES = 32
"""``SKILL.md`` files read per audit, in listing order."""

MAX_SUPPORTING_FILES = 16
"""Supporting files read per audit for digest checks, at most one per skill."""

MAX_FILE_BYTES = 1024 * 1024
"""A listed file larger than this is not read."""

MAX_TOTAL_BYTES = 8 * 1024 * 1024
"""Declared bytes read per audit across all skill files."""

COLLECTION_TIMEOUT_S = 90.0
"""Total budget for listing, the ``skills/get`` call and file reads."""

READ_CONCURRENCY = 4

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
NAME_MAX_LENGTH = 64


class SkillsSession(Protocol):
    """The two session calls the collector needs; :class:`mcpscore.mcp_client.MCPClient` provides them."""

    async def request_raw(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Send one JSON-RPC request and return its result object; raise on an error response."""
        ...

    async def read_resource_contents(self, uri: str) -> list[dict[str, Any]]:
        """Read one resource and return its contents as dicts (``uri``, ``mimeType``, ``text`` or ``blob``)."""
        ...


@dataclass
class SkillFile:
    """What one ``resources/read`` of a skill file returned."""

    uri: str
    size: int | None = None
    digest: str | None = None
    mime_type: str | None = None
    text: str | None = None
    """Decoded text, kept for ``SKILL.md`` files only."""
    error: str | None = None
    """``rpc_error``, ``timeout``, ``empty`` or ``exception`` when the read did not return content."""
    error_code: int | None = None


@dataclass
class SkillsEvidence:
    """Everything the skills rules judge, collected once per audit."""

    settings: dict[str, Any] = field(default_factory=dict)
    """The server's extension settings, e.g. ``{"directoryRead": true}``."""
    entries: list[Any] | None = None
    """Raw ``skills/list`` entries in listing order; None when the method failed."""
    list_error: dict[str, Any] | None = None
    list_malformed: bool = False
    """The result had no ``skills`` array."""
    list_incomplete: bool = False
    get_uri: str | None = None
    """The listed ``SKILL.md`` URI passed to ``skills/get``."""
    get_entry: Any = None
    get_error: dict[str, Any] | None = None
    files: dict[str, SkillFile] = field(default_factory=dict)
    budget_exhausted: bool = False


def declared_settings(capabilities: Any) -> dict[str, Any] | None:
    """Return the skills extension settings a server declared, or None when it did not declare it."""
    extensions = getattr(capabilities, "extensions", None)
    if not isinstance(extensions, dict) or SKILLS_EXTENSION not in extensions:
        return None
    settings = extensions[SKILLS_EXTENSION]
    return settings if isinstance(settings, dict) else {}


def skill_root(uri: str) -> str | None:
    """Return the skill directory URI of a ``SKILL.md`` URI, or None when *uri* does not end in ``/SKILL.md``."""
    suffix = "/" + SKILL_FILE
    if not uri.endswith(suffix) or len(uri) <= len(suffix):
        return None
    return uri[: -len(suffix)]


def skill_path_name(uri: str) -> str | None:
    """Return the final ``<skill-path>`` segment of a ``SKILL.md`` URI (the skill name it implies)."""
    root = skill_root(uri)
    if root is None:
        return None
    try:
        parts = urlsplit(root)
    except ValueError:
        return None
    if not parts.scheme:
        return None
    path = (parts.netloc + parts.path).strip("/")
    return path.rsplit("/", 1)[-1] or None


def name_problems(name: str) -> list[str]:
    """Return the Agent Skills naming rules *name* breaks (empty when valid)."""
    problems = []
    if not 1 <= len(name) <= NAME_MAX_LENGTH:
        problems.append("length")
    if not NAME_RE.fullmatch(name):
        problems.append("characters")
    return problems


def manifest(entry: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Return the entry's ``resources`` array, or None when it is ``"dynamic"`` or not an array."""
    resources = entry.get("resources")
    return resources if isinstance(resources, list) else None


def source_lines(text: str) -> list[str]:
    """Split text on line feeds only, so form feeds, vertical tabs and U+0085 stay in the text they hide in."""
    return [line.removesuffix("\r") for line in text.split("\n")]


def split_frontmatter(text: str) -> tuple[str, str] | None:
    """Split ``SKILL.md`` text into its YAML frontmatter and body, or None when it has no frontmatter."""
    lines = text.split("\n")
    lines = [line + "\n" for line in lines[:-1]] + [lines[-1]]
    if not lines or lines[0].strip() != "---":
        return None
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            return "".join(lines[1:index]), "".join(lines[index + 1 :])
    return None


def parse_frontmatter(text: str) -> Any:
    """Parse ``SKILL.md`` frontmatter as the JSON a listing renders it to; raise ValueError when absent or invalid.

    ``yaml.safe_load`` turns unquoted dates into date objects, which JSON carries as ISO strings.
    """
    split = split_frontmatter(text)
    if split is None:
        raise ValueError("no frontmatter")
    try:
        _check_yaml_shape(split[0])
        parsed = yaml.safe_load(split[0])
        return json.loads(json.dumps(parsed, default=_json_scalar))
    except (yaml.YAMLError, TypeError, RecursionError) as exc:
        raise ValueError("invalid YAML") from exc


MAX_FRONTMATTER_DEPTH = 32


def _check_yaml_shape(source: str) -> None:
    """Refuse aliases and deep nesting before loading, so a small document cannot expand without bound."""
    depth = 0
    for event in yaml.parse(source, Loader=yaml.SafeLoader):
        if isinstance(event, yaml.AliasEvent):
            raise ValueError("YAML aliases")  # noqa: TRY004 — callers report any refused document as invalid YAML
        if isinstance(event, yaml.CollectionStartEvent):
            depth += 1
            if depth > MAX_FRONTMATTER_DEPTH:
                raise ValueError("YAML nesting")
        elif isinstance(event, yaml.CollectionEndEvent):
            depth -= 1


def _json_scalar(value: Any) -> str:
    """Render a YAML scalar JSON has no type for (dates, timestamps) as its ISO string."""
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


# Each part stops at the next bracket, parenthesis or line end, so a failed match never rescans the rest of the
# text: extraction stays linear on untrusted input full of unmatched brackets.
_LINK_RE = re.compile(r"!?\[[^\[\]\n]*\]\(\s*(?:<([^<>\n]+)>|([^()\[\]<>\s]+))(?:[ \t]+\"[^\"\n]{0,256}\")?\s*\)")


_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_INLINE_CODE_RE = re.compile(r"(?<!`)(`+)(?!`)[^`]+\1(?!`)")
"""An inline code span; a span that itself contains backticks is not recognised, which keeps matching linear."""
_FENCE_RE = re.compile(r"(`{3,}|~{3,})(.*)")


def _fence_open(line: str) -> str | None:
    """Return the opening delimiter of a fenced code block on *line*, or None."""
    match = _FENCE_RE.fullmatch(line.lstrip())
    if match is None or (match.group(1)[0] == "`" and "`" in match.group(2)):
        return None
    return match.group(1)


def _fence_closes(line: str, opening: str) -> bool:
    """Whether *line* closes a block opened by *opening*: the same character, at least as many, nothing else."""
    stripped = line.strip()
    return len(stripped) >= len(opening) and stripped == opening[0] * len(stripped)


def markdown_blocks(body: str, first_line: int = 1) -> list[tuple[int, str, bool]]:
    """Split Markdown into blocks: each fenced code block, and each paragraph of prose.

    Returns (first line number, text, is code). Fence marker lines belong to their code block.
    """
    blocks: list[tuple[int, str, bool]] = []
    current: list[str] = []
    start = first_line
    fence: str | None = None

    def flush(*, is_code: bool) -> None:
        if current:
            blocks.append((start, "\n".join(current), is_code))
            current.clear()

    for number, line in enumerate(source_lines(body), start=first_line):
        opening = _fence_open(line) if fence is None else None
        if opening is not None:
            flush(is_code=False)
            fence, start = opening, number
            current.append(line)
        elif fence is not None:
            current.append(line)
            if _fence_closes(line, fence):
                flush(is_code=True)
                fence = None
        elif not line.strip():
            flush(is_code=False)
        else:
            if not current:
                start = number
            current.append(line)
    flush(is_code=fence is not None)
    return blocks


def strip_inline_code(text: str) -> str:
    """Replace inline code spans with a space."""
    return _INLINE_CODE_RE.sub(" ", text)


def relative_references(body: str) -> list[str]:
    """Return relative Markdown link targets in *body*'s prose (not code), without anchors or queries, in order."""
    targets = []
    prose = "\n\n".join(strip_inline_code(text) for _, text, is_code in markdown_blocks(body) if not is_code)
    for match in _LINK_RE.finditer(prose):
        target = match.group(1) or match.group(2)
        if target.startswith(("#", "/")) or _SCHEME_RE.match(target):
            continue
        target = target.split("#", 1)[0].split("?", 1)[0]
        if target:
            targets.append(target)
    return targets


def resolve_reference(root: str, target: str) -> str | None:
    """Resolve a relative reference against a skill root URI; None when it climbs out of the skill."""
    normalized = posixpath.normpath(target)
    if normalized == ".." or normalized.startswith("../"):
        return None
    if normalized == ".":
        return root
    return f"{root}/{normalized}"


def content_bytes(contents: list[dict[str, Any]], uri: str) -> tuple[bytes, str | None] | None:
    """Return the raw bytes and MIME type of the content item for *uri* (the first item otherwise)."""
    if not contents:
        return None
    item = next((c for c in contents if c.get("uri") == uri), contents[0])
    mime_type = item.get("mimeType")
    if isinstance(item.get("text"), str):
        return item["text"].encode("utf-8"), mime_type
    if isinstance(item.get("blob"), str):
        try:
            return base64.b64decode(item["blob"], validate=True), mime_type
        except ValueError:
            return None
    return None


def _reads(entries: list[Any]) -> list[tuple[str, bool]]:
    """Choose the files to read: each listed ``SKILL.md``, then one supporting file per skill, each URI once.

    A nested skill's ``SKILL.md`` can also be its parent's supporting file; it is read once, with its text kept.
    """
    skill_files: list[tuple[str, bool]] = []
    supporting: list[tuple[str, bool]] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("uri"), str):
            continue
        uri = entry["uri"]
        if len(skill_files) < MAX_SKILL_FILES:
            skill_files.append((uri, True))
        files = manifest(entry) or []
        extra = next(
            (
                item["uri"]
                for item in files
                if isinstance(item, dict)
                and isinstance(item.get("uri"), str)
                and item["uri"] != uri
                and isinstance(item.get("size"), int)
                and item["size"] <= MAX_FILE_BYTES
            ),
            None,
        )
        if extra is not None and len(supporting) < MAX_SUPPORTING_FILES:
            supporting.append((extra, False))
    reads: dict[str, bool] = {}
    for uri, keep_text in skill_files + supporting:
        reads[uri] = reads.get(uri, False) or keep_text
    return list(reads.items())


def _declared_size(entries: list[Any], uri: str) -> int | None:
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for item in manifest(entry) or []:
            if isinstance(item, dict) and item.get("uri") == uri and isinstance(item.get("size"), int):
                return item["size"]
    return None


UNOBSERVED_OUTCOMES = frozenset({"timeout", "transport"})
"""Call outcomes with no answer from the server, so nothing about the method can be judged."""


def _rpc_error(exc: Exception) -> dict[str, Any]:
    """Classify a failed call: a JSON-RPC error, a reply that did not validate, a timeout, or no answer at all."""
    code = getattr(exc, "code", None)
    if isinstance(exc, TimeoutError) or code == -32001:
        return {"outcome": "timeout"}
    if isinstance(code, int):
        return {"outcome": "rpc_error", "error_code": code}
    if isinstance(exc, ValidationError):
        return {"outcome": "malformed"}
    return {"outcome": "transport", "exception": type(exc).__name__}


async def _list(session: SkillsSession, evidence: SkillsEvidence) -> None:
    entries: list[Any] = []
    cursor: str | None = None
    seen: set[str] = set()
    for page in range(MAX_LIST_PAGES):
        try:
            result = await session.request_raw("skills/list", {"cursor": cursor} if cursor is not None else {})
        except Exception as exc:  # noqa: BLE001 — a failed listing is evidence, not an audit abort
            if page == 0:
                evidence.list_error = _rpc_error(exc)
            else:
                evidence.entries = entries
                evidence.list_incomplete = True
            return
        skills = result.get("skills") if isinstance(result, dict) else None
        if not isinstance(skills, list):
            evidence.list_malformed = True
            evidence.entries = entries if page else None
            return
        entries.extend(skills)
        next_cursor = result.get("nextCursor")
        if not isinstance(next_cursor, str) or next_cursor in seen:
            evidence.entries = entries
            evidence.list_incomplete = isinstance(next_cursor, str)
            return
        seen.add(next_cursor)
        cursor = next_cursor
    evidence.entries = entries
    evidence.list_incomplete = True


async def _get(session: SkillsSession, evidence: SkillsEvidence) -> None:
    uri = next(
        (e["uri"] for e in evidence.entries or [] if isinstance(e, dict) and isinstance(e.get("uri"), str)),
        None,
    )
    if uri is None:
        return
    evidence.get_uri = uri
    try:
        result = await session.request_raw("skills/get", {"uri": uri})
    except Exception as exc:  # noqa: BLE001 — a failed call is evidence, not an audit abort
        evidence.get_error = _rpc_error(exc)
        return
    evidence.get_entry = result.get("skill") if isinstance(result, dict) else None


async def _read(session: SkillsSession, uri: str, keep_text: bool) -> SkillFile:
    try:
        contents = await session.read_resource_contents(uri)
    except Exception as exc:  # noqa: BLE001 — a failed read is evidence, not an audit abort
        error = _rpc_error(exc)
        return SkillFile(uri, error=error["outcome"], error_code=error.get("error_code"))
    decoded = content_bytes(contents, uri)
    if decoded is None:
        return SkillFile(uri, error="empty")
    raw, mime_type = decoded
    if len(raw) > MAX_FILE_BYTES:
        # The SDK has already received the message; this bounds what the audit keeps and scans.
        return SkillFile(uri, len(raw), mime_type=mime_type, error="too_large")
    text = raw.decode("utf-8", errors="replace") if keep_text else None
    return SkillFile(uri, len(raw), "sha256:" + hashlib.sha256(raw).hexdigest(), mime_type, text)


async def _read_files(session: SkillsSession, evidence: SkillsEvidence) -> None:
    entries = evidence.entries or []
    budget = MAX_TOTAL_BYTES
    planned: list[tuple[str, bool]] = []
    for uri, is_skill_file in _reads(entries):
        declared = _declared_size(entries, uri)
        if declared is not None and (declared > MAX_FILE_BYTES or declared > budget):
            evidence.budget_exhausted = True
            continue
        budget -= declared or 0
        planned.append((uri, is_skill_file))
    gate = asyncio.Semaphore(READ_CONCURRENCY)
    received = 0

    async def one(uri: str, keep_text: bool) -> None:
        nonlocal received
        async with gate:
            if received >= MAX_TOTAL_BYTES:
                evidence.budget_exhausted = True
                return
            result = await _read(session, uri, keep_text)
            received += result.size or 0
            # Stored as each read finishes, so a collection timeout keeps the reads already made.
            evidence.files[uri] = result

    await asyncio.gather(*(one(uri, keep) for uri, keep in planned))


async def collect_skills(session: SkillsSession, settings: dict[str, Any]) -> SkillsEvidence:
    """List the server's skills, call ``skills/get`` once, and read a bounded sample of skill files."""
    evidence = SkillsEvidence(settings=settings)
    phase = "list"
    try:
        async with asyncio.timeout(COLLECTION_TIMEOUT_S):
            await _list(session, evidence)
            phase = "get"
            await _get(session, evidence)
            phase = "read"
            await _read_files(session, evidence)
    except TimeoutError:
        # The deadline cancels the call in flight, so its own handler never records the outcome.
        evidence.budget_exhausted = True
        if phase == "list":
            evidence.list_error = {"outcome": "timeout"}
            evidence.entries = None
        elif phase == "get":
            evidence.get_error = {"outcome": "timeout"}
        logger.warning("Stopped collecting skills after %.0fs", COLLECTION_TIMEOUT_S)
    return evidence
