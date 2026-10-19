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
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import lru_cache
import hashlib
import json
import logging
import posixpath
import re
from typing import Any, Protocol
import unicodedata
from urllib.parse import unquote, urlsplit

from markdown_it import MarkdownIt
from markdown_it.token import Token
from mcp_types import CONNECTION_CLOSED, REQUEST_TIMEOUT
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
    # A "?" or "#" puts the apparent SKILL.md path in the query or fragment: the URI has no skill path.
    if root is None or "?" in uri or "#" in uri:
        return None
    try:
        parts = urlsplit(root)
    except ValueError:
        return None
    if not parts.scheme:
        return None
    path = (parts.netloc + parts.path).lstrip("/")
    # Split before decoding, so an encoded "/" cannot change which segment is the name.
    return unquote(path.rsplit("/", 1)[-1]) or None


def normalize_name(name: str) -> str:
    """NFKC-normalize a skill name, as the Agent Skills reference validator does before checking it."""
    return unicodedata.normalize("NFKC", name.strip())


def name_problems(name: str) -> list[str]:
    """Return the Agent Skills naming rules *name* breaks (empty when valid).

    Follows the reference validator (skills-ref): Unicode letters and digits are allowed, lowercase only,
    with single hyphens that neither start nor end the name.
    """
    name = normalize_name(name)
    problems = []
    if not 1 <= len(name) <= NAME_MAX_LENGTH:
        problems.append("length")
    if name != name.lower():
        problems.append("uppercase")
    if name.startswith("-") or name.endswith("-") or "--" in name:
        problems.append("hyphens")
    if not all(char.isalnum() or char == "-" for char in name):
        problems.append("characters")
    return problems


def manifest(entry: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Return the entry's ``resources`` array, or None when it is ``"dynamic"`` or not an array."""
    resources = entry.get("resources")
    return resources if isinstance(resources, list) else None


def source_lines(text: str) -> list[str]:
    """Split text on line feeds only, so form feeds, vertical tabs and U+0085 stay in the text they hide in."""
    return [line.removesuffix("\r") for line in text.split("\n")]


def normalize_newlines(text: str) -> str:
    """Turn CRLF and bare CR into LF, the line endings CommonMark and YAML both accept."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def split_frontmatter(text: str) -> tuple[str, str] | None:
    """Split ``SKILL.md`` text into its YAML frontmatter and body, or None when it has no frontmatter.

    Line endings are normalised first, so both parts use LF.
    """
    text = normalize_newlines(text)
    lines = text.split("\n")
    lines = [line + "\n" for line in lines[:-1]] + [lines[-1]]
    # Delimiters start at column zero; an indented "---" belongs to a YAML block scalar.
    if not lines or lines[0].rstrip() != "---":
        return None
    for index in range(1, len(lines)):
        if lines[index].rstrip() == "---":
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


_MARKDOWN = MarkdownIt("commonmark")
"""CommonMark parser: decides what is code, prose or a link the way a renderer does."""

MAX_MARKDOWN_BYTES = 64 * 1024
"""Larger documents are not parsed: scanned line by line as prose, and their links are not checked."""


def _parsable(body: str) -> bool:
    return len(body.encode("utf-8")) <= MAX_MARKDOWN_BYTES


@lru_cache(maxsize=64)
def _parse(body: str) -> tuple[Token, ...]:
    """Parse a document once per audit; the security and reference rules read the same tokens."""
    return tuple(_MARKDOWN.parse(body))


_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def _html_text(html: str) -> str:
    """Return the text of an HTML fragment: tags and comments dropped, a quoted ``>`` kept inside its tag.

    One linear pass, so hostile input stays cheap. An unterminated tag or comment runs to the end.
    """
    parts: list[str] = []
    i, n = 0, len(html)
    while i < n:
        start = html.find("<", i)
        if start < 0:
            parts.append(html[i:])
            break
        parts.append(html[i:start])
        if html.startswith("<!--", start):
            end = html.find("-->", start + 4)
            i = n if end < 0 else end + 3
        elif start + 1 < n and (html[start + 1].isalpha() or html[start + 1] in "/!?"):
            j, quote, last = start + 1, "", ""
            while j < n:
                char = html[j]
                if quote:
                    if char == quote:
                        quote = ""
                elif char in "\"'" and last == "=":
                    quote = char
                elif char == ">":
                    break
                if not char.isspace():
                    last = char
                j += 1
            i = j + 1
        else:
            parts.append("<")
            i = start + 1
    return "".join(parts)


@dataclass(frozen=True)
class MarkdownBlock:
    """One block of a Markdown document, with its source text and the prose a reader sees."""

    line: int
    """Line number of the block's first source line."""
    text: str
    """The block's source lines, exactly as written."""
    prose: str
    """The block's text outside code: empty for a code block, inline code spans removed from a paragraph."""
    rendered: str
    """The block's rendered text with inline code kept: what a reader sees, markup removed."""


def _prose(inline: Token, *, keep_code: bool = False) -> str:
    """Return the rendered text of an inline token, with code spans kept or replaced by a space.

    Link and image destinations (decoded), titles and inline HTML are not code, so they are judged too; they
    follow the visible text on their own lines rather than splitting a sentence that contains them.
    """
    parts: list[str] = []
    extras: list[str] = []
    _render(inline.children or [], parts, extras, keep_code=keep_code)
    return "\n".join(["".join(parts), *(extra for extra in extras if extra)])


def _render(children: list[Token], parts: list[str], extras: list[str], *, keep_code: bool) -> None:
    for child in children:
        if child.type == "code_inline":
            parts.append(child.content if keep_code else " ")
        elif child.type in ("link_open", "image"):
            extras += [
                unquote(str(child.attrs.get("href", child.attrs.get("src", "")))),
                str(child.attrs.get("title", "")),
            ]
            if child.type == "image":
                # Alt text renders from the image's own children, formatting removed.
                _render(child.children or [], parts, extras, keep_code=keep_code)
        elif child.type in ("softbreak", "hardbreak"):
            parts.append("\n")
        elif child.type == "html_inline":
            # A tag or comment renders as nothing, but it is not code: its text is judged on its own line.
            extras.append(child.content)
        else:
            parts.append(child.content)


def markdown_blocks(body: str, first_line: int = 1) -> list[MarkdownBlock]:
    """Split Markdown into code blocks, paragraphs and headings, and any other non-blank source lines.

    Lines no block covers (link reference definitions, thematic breaks) are returned as prose blocks, so every
    source line is in exactly one block. A document over ``MAX_MARKDOWN_BYTES`` is not parsed: its blocks have
    no known prose (``prose`` is empty), so only classes that count everywhere are judged in it.
    """
    # CommonMark ends a line at CR, LF or CRLF; the token line ranges count them all.
    body = normalize_newlines(body)
    lines = source_lines(body)
    blocks: list[MarkdownBlock] = []
    covered: set[int] = set()
    parsed = _parsable(body)
    tokens = _parse(body) if parsed else ()
    for token in tokens:
        if token.map is None or token.type not in ("fence", "code_block", "inline", "html_block"):
            continue
        start, end = token.map
        if covered.intersection(range(start, end)):
            continue
        covered.update(range(start, end))
        text = "\n".join(lines[start:end])
        if token.type in ("fence", "code_block"):
            prose, rendered = "", text
        elif token.type == "inline":
            prose, rendered = _prose(token), _prose(token, keep_code=True)
        else:
            # An HTML block is not code: its source counts in full, and its tag-free text catches a directive
            # that tags split.
            prose, rendered = text, _html_text(text)
        blocks.append(MarkdownBlock(first_line + start, text, prose, rendered))
    run: list[int] = []
    for number in [*range(len(lines)), len(lines)]:
        if number < len(lines) and number not in covered and lines[number].strip(" \t"):
            run.append(number)
        elif run:
            text = "\n".join(lines[run[0] : run[-1] + 1])
            # In an unparsed document code cannot be told from prose, so code-exempt classes are not judged.
            blocks.append(MarkdownBlock(first_line + run[0], text, text if parsed else "", text))
            run = []
    return sorted(blocks, key=lambda block: block.line)


def _link_targets(tokens: list[Token]) -> Iterator[str]:
    for token in tokens:
        if token.type == "link_open":
            yield str(token.attrs.get("href", ""))
        elif token.type == "image":
            # Alt text is text, not navigation: links nested in it are not followed.
            yield str(token.attrs.get("src", ""))
            continue
        if token.children:
            yield from _link_targets(token.children)


def relative_references(body: str) -> list[str] | None:
    """Return the relative targets of the links and images *body* renders, without anchors or queries, in order.

    Links inside code are not rendered, reference-style links resolve through their definitions, and an unused
    definition renders nothing. None when the document is over ``MAX_MARKDOWN_BYTES`` and was not parsed.
    """
    if not _parsable(body):
        return None
    targets = []
    for target in _link_targets(list(_parse(body))):
        if not target or target.startswith(("#", "/")) or _SCHEME_RE.match(target):
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
    if isinstance(exc, TimeoutError) or code == REQUEST_TIMEOUT:
        return {"outcome": "timeout"}
    if code == CONNECTION_CLOSED:
        return {"outcome": "transport", "exception": "ConnectionClosed"}
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
        # Visible after every page, so a collection deadline keeps the pages already received.
        evidence.entries, evidence.list_incomplete = entries, True
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
        if phase == "list" and evidence.entries is None:
            evidence.list_error = {"outcome": "timeout"}
        elif phase == "list":
            evidence.list_incomplete = True
        elif phase == "get":
            evidence.get_error = {"outcome": "timeout"}
        logger.warning("Stopped collecting skills after %.0fs", COLLECTION_TIMEOUT_S)
    return evidence
