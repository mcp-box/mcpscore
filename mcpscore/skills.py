"""Collect evidence about a server's Skills extension (SEP-2640) for the skills rules.

A server that declares ``io.modelcontextprotocol/skills`` serves Agent Skills as
MCP resources and answers ``skills/list`` and ``skills/get``. This module lists
the skills, asks ``skills/get`` for each of them (and for one it does not serve), reads
directories when the server offers ``resources/directory/read``, and reads a bounded sample of
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
import re
from typing import Any, Protocol
import unicodedata
from urllib.parse import quote, unquote, urlsplit

from markdown_it import MarkdownIt
from markdown_it.token import Token
from mcp_types import CONNECTION_CLOSED, REQUEST_TIMEOUT
from pydantic import ValidationError
import yaml

from .html_text import unescape
from .report_evidence import report_evidence

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
"""Total budget for listing, the ``skills/get`` and directory calls, and file reads."""

UNKNOWN_SKILL_NAME = "mcpscore-no-such-skill"
"""Skill path segment of the URI asked of ``skills/get`` to check that an unknown skill is refused."""

DIRECTORY_READ_KINDS = ("skill_root", "unknown", "file")
"""The directory reads made when the server sets ``directoryRead``: see :class:`DirectoryRead`."""

UNKNOWN_DIRECTORY_NAME = "mcpscore-no-such-directory"
"""Child of a skill root read with ``resources/directory/read`` to check that an unknown directory is refused."""

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
class SkillGet:
    """What one ``skills/get`` call returned."""

    uri: str
    entry: Any = None
    """The result's ``skill`` object; None when the call failed or the result carried none."""
    error: dict[str, Any] | None = None


@dataclass
class DirectoryRead:
    """What one ``resources/directory/read`` of a URI returned, across its pages."""

    uri: str
    kind: str
    """``skill_root`` (a listed skill's root), ``unknown`` (a child the server does not serve) or ``file``."""
    resources: list[Any] | None = None
    """The children across all pages read; None when the first page failed or carried no ``resources`` array."""
    error: dict[str, Any] | None = None
    incomplete: bool = False
    """A later page failed, or the page limit was reached."""


@dataclass
class SkillsEvidence:
    """Everything the skills rules judge, collected once per audit."""

    settings: dict[str, Any] = field(default_factory=dict)
    """The server's extension settings, e.g. ``{"directoryRead": true}``."""
    declared_in_discover: bool = False
    """The extension was declared in ``server/discover`` only, not in the session's capabilities."""
    entries: list[Any] | None = None
    """Raw ``skills/list`` entries in listing order; None when the method failed."""
    list_error: dict[str, Any] | None = None
    list_malformed: bool = False
    """The result had no ``skills`` array."""
    list_incomplete: bool = False
    gets: list[SkillGet] = field(default_factory=list)
    """``skills/get`` for each listed ``SKILL.md`` URI (up to ``MAX_SKILL_FILES``), in listing order."""
    unknown_get: SkillGet | None = None
    """``skills/get`` for a skill the server does not serve; None when the call was not made."""
    directory_reads: list[DirectoryRead] = field(default_factory=list)
    """Made only when the server sets ``directoryRead: true``."""
    stateless_list: dict[str, Any] | None = None
    """``resultType``, ``ttlMs`` and ``cacheScope`` of a first ``skills/list`` page on the stateless lifecycle
    (or the call's ``error``); None when no stateless listing was made."""
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
    root, _, last = uri.rpartition("/")
    # The file name is compared in normal form ("%53KILL.md" is SKILL.md); the root keeps its spelling.
    if not root or normalize_uri(last) != SKILL_FILE:
        return None
    return root


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
    """NFKC-normalize a skill name, as the Agent Skills reference validator does before checking it.

    Whitespace is kept: the naming rules allow none, and a padded name cannot equal its directory's name.
    """
    return unicodedata.normalize("NFKC", name)


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


def _html_text(html: str, tag: str = "") -> str:
    """Return the text of an HTML fragment: tags and comments become *tag*, a quoted ``>`` stays inside its tag.

    Character references are decoded. One linear pass, so hostile input stays cheap. An unterminated tag or
    comment runs to the end.
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
            parts.append(tag)
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
            parts.append(tag)
        else:
            parts.append("<")
            i = start + 1
    return unescape("".join(parts))


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


def _inline_views(inline: Token, seen: set[tuple[str, str]]) -> tuple[str, str]:
    """Return the prose (code spans replaced by a space) and rendered text (code kept) of an inline token.

    Link and image destinations (decoded), titles and inline HTML are not code, so they are judged too; they
    follow the visible text on their own lines rather than splitting a sentence that contains them. A tag may
    render as nothing or as a break, so text with inline HTML is judged both ways. Each distinct extra is added
    only in the first block of the document that has it (``seen``), so references that repeat one long
    destination do not multiply the text; each is decoded once, after that check.
    """
    extras: dict[tuple[str, str], None] = {}
    views = []
    for keep_code in (False, True):
        texts = []
        for tag in ("", "\n"):
            parts: list[str] = []
            _render(inline.children or [], parts, None if tag or keep_code else extras, keep_code=keep_code, tag=tag)
            texts.append("".join(parts))
        if texts[1] == texts[0]:
            texts.pop()
        views.append(texts)
    new = [text for key in extras if key not in seen and (text := _decode_extra(*key))]
    seen.update(extras)
    return "\n".join([*views[0], *new]), "\n".join([*views[1], *new])


def _decode_extra(kind: str, raw: str) -> str:
    """Return the text a reader sees for a raw destination, title or inline tag."""
    if kind == "href":
        return unquote(raw)
    return unescape(raw) if kind == "html" else raw


def _render(
    children: list[Token], parts: list[str], extras: dict[tuple[str, str], None] | None, *, keep_code: bool, tag: str
) -> None:
    """Append the visible text of inline tokens to ``parts``, and the raw keys of their extras to ``extras``."""
    for child in children:
        if child.type == "code_inline":
            parts.append(child.content if keep_code else " ")
        elif child.type in ("link_open", "image"):
            if extras is not None:
                extras["href", str(child.attrs.get("href", child.attrs.get("src", "")))] = None
                extras["title", str(child.attrs.get("title", ""))] = None
            if child.type == "image":
                # Alt text renders from the image's own children, formatting removed.
                _render(child.children or [], parts, extras, keep_code=keep_code, tag=tag)
        elif child.type in ("softbreak", "hardbreak"):
            parts.append("\n")
        elif child.type == "html_inline":
            # A tag or comment renders as nothing, but it is not code: its decoded text is judged on its own line.
            if extras is not None:
                extras["html", child.content] = None
            parts.append(tag)
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
    seen: set[tuple[str, str]] = set()
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
            # The content drops blockquote and list markers, so a directive wrapped inside quoted code still reads
            # as one sentence; the source keeps them.
            prose, rendered = "", token.content
        elif token.type == "inline":
            prose, rendered = _inline_views(token, seen)
        else:
            # An HTML block holds no code: its decoded content and its text, with tags read as nothing and as
            # breaks, all count in full, so neither a character reference nor a tag hides a directive. The
            # content drops blockquote and list markers, as for code blocks.
            content = token.content
            rendered = "\n".join([_html_text(content), _html_text(content, "\n")])
            prose = f"{unescape(content)}\n{rendered}"
        blocks.append(MarkdownBlock(first_line + start, text, prose, rendered))
    run: list[int] = []
    for number in [*range(len(lines)), len(lines)]:
        if number < len(lines) and number not in covered and lines[number].strip(" \t"):
            run.append(number)
        elif run:
            text = "\n".join(lines[run[0] : run[-1] + 1])
            if parsed:
                blocks.append(MarkdownBlock(first_line + run[0], text, text, unescape(text)))
            else:
                # Code cannot be told from prose here, so code-exempt classes are not judged; HTML is read the
                # way a parsed HTML block is, so a tag cannot split a directive.
                rendered = "\n".join([unescape(text), _html_text(text), _html_text(text, "\n")])
                blocks.append(MarkdownBlock(first_line + run[0], text, "", rendered))
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
    # References that repeat one destination share one stripped string rather than each copying it.
    stripped: dict[str, str] = {}
    for target in _link_targets(list(_parse(body))):
        if not target or target.startswith(("#", "/")) or _SCHEME_RE.match(target):
            continue
        if target not in stripped:
            stripped[target] = target.split("#", 1)[0].split("?", 1)[0]
        if stripped[target]:
            targets.append(stripped[target])
    return targets


# RFC 3986 §2.2-2.3: characters a URI may carry unencoded; "%" keeps existing escapes.
_URI_SAFE = ":/?#[]@!$&'()*+,;=-._~%"
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_ESCAPE_RE = re.compile("%([0-9A-Fa-f]{2})")


def _normal_escape(match: re.Match[str]) -> str:
    char = chr(int(match[1], 16))
    return char if char in _UNRESERVED else f"%{match[1].upper()}"


def normalize_uri(uri: str) -> str:
    """Return *uri* in RFC 3986 normal form for comparison (§6.2.2.1-2).

    The scheme is lowercased; characters a URI cannot carry (non-ASCII, spaces) are percent-encoded as UTF-8,
    escapes are uppercased, and only escapes of unreserved characters are decoded: ``%2D`` equals ``-``, while
    ``%3B``, ``%2F`` or ``%25`` stay distinct from ``;``, ``/`` or ``%``. The rest stays case-sensitive.
    """
    normal = _ESCAPE_RE.sub(_normal_escape, quote(uri, safe=_URI_SAFE))
    scheme = _SCHEME_RE.match(normal)
    return normal[: scheme.end()].lower() + normal[scheme.end() :] if scheme else normal


def resolve_reference(root: str, target: str) -> str | None:
    """Resolve a relative reference against a skill root URI; None when it climbs out of the skill.

    Dot segments are removed as in RFC 3986 §5.2.4 and empty segments are kept, since ``a//b`` names a
    different resource than ``a/b``. A trailing ``/`` names the directory itself.
    """
    segments = target.split("/")
    if len(segments) > 1 and segments[-1] == "":
        segments.pop()
    resolved: list[str] = []
    for segment in segments:
        if segment == "..":
            if not resolved:
                return None
            resolved.pop()
        elif segment != ".":
            resolved.append(segment)
    return "/".join([root, *resolved])


def size_value(value: Any) -> int | None:
    """Return a listed byte length, or None when it is not a nonnegative integer.

    JSON does not tell 42 from 42.0, so an integral float counts; booleans, fractions and non-finite numbers do not.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    return value if isinstance(value, int) and value >= 0 else None


def content_bytes(contents: list[dict[str, Any]], uri: str) -> tuple[bytes, str | None] | None:
    """Return the raw bytes and MIME type of the content item for *uri* (the first item otherwise)."""
    if not contents:
        return None
    item = next(
        (c for c in contents if isinstance(c.get("uri"), str) and normalize_uri(c["uri"]) == normalize_uri(uri)),
        contents[0],
    )
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
                and normalize_uri(item["uri"]) != normalize_uri(uri)
                and (size := size_value(item.get("size"))) is not None
                and size <= MAX_FILE_BYTES
            ),
            None,
        )
        if extra is not None and len(supporting) < MAX_SUPPORTING_FILES:
            supporting.append((extra, False))
    # One request per URI in normal form, under its first spelling (a SKILL.md's own, as skill files come first).
    reads: dict[str, tuple[str, bool]] = {}
    for uri, keep_text in skill_files + supporting:
        first, kept = reads.get(normalize_uri(uri), (uri, False))
        reads[normalize_uri(uri)] = (first, kept or keep_text)
    return list(reads.values())


def _declared_size(entries: list[Any], uri: str) -> int | None:
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for item in manifest(entry) or []:
            listed = item.get("uri") if isinstance(item, dict) else None
            if (
                isinstance(listed, str)
                and normalize_uri(listed) == normalize_uri(uri)
                and (size := size_value(item.get("size"))) is not None
            ):
                return size
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


def _scalar(value: Any) -> Any:
    """Keep a JSON scalar (a string masked, then bounded to 200 characters); replace anything else with its type."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return report_evidence(value)[:200]
    return {"type": "array" if isinstance(value, list) else "object" if isinstance(value, dict) else "other"}


def _list_hints(result: Any) -> dict[str, Any]:
    """Return the caching attributes of a ``skills/list`` result (SEP-2549), with non-scalar values summarized."""
    result = result if isinstance(result, dict) else {}
    return {
        "result_type": _scalar(result.get("resultType")),
        "ttl_ms": _scalar(result.get("ttlMs")),
        "cache_scope": _scalar(result.get("cacheScope")),
    }


async def stateless_list_hints(session: SkillsSession) -> dict[str, Any]:
    """Return the caching attributes of a first ``skills/list`` page on a stateless session, or the call's error."""
    try:
        return _list_hints(await session.request_raw("skills/list", {}))
    except Exception as exc:  # noqa: BLE001 — a failed call is evidence, not an audit abort
        return {"error": _rpc_error(exc)}


async def _list(session: SkillsSession, evidence: SkillsEvidence, *, stateless: bool = False) -> None:
    entries: list[Any] = []
    cursor: str | None = None
    seen: set[str] = set()
    for page in range(MAX_LIST_PAGES):
        try:
            result = await session.request_raw("skills/list", {"cursor": cursor} if cursor is not None else {})
        except Exception as exc:  # noqa: BLE001 — a failed listing is evidence, not an audit abort
            if page == 0:
                evidence.list_error = _rpc_error(exc)
                if stateless:
                    evidence.stateless_list = {"error": evidence.list_error}
            else:
                evidence.entries = entries
                evidence.list_incomplete = True
            return
        if stateless and page == 0:
            evidence.stateless_list = _list_hints(result)
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
            # A repeated cursor, or one that is not a string, leaves pages unread.
            evidence.list_incomplete = next_cursor is not None
            return
        seen.add(next_cursor)
        cursor = next_cursor
    evidence.entries = entries
    evidence.list_incomplete = True


def _listed_skill_uris(entries: list[Any]) -> list[str]:
    """Return the distinct ``SKILL.md`` URIs of the listing, in order, up to ``MAX_SKILL_FILES``."""
    uris: dict[str, str] = {}
    for e in entries:
        if isinstance(e, dict) and isinstance(e.get("uri"), str):
            uris.setdefault(normalize_uri(e["uri"]), e["uri"])
    return list(uris.values())[:MAX_SKILL_FILES]


def _unused_name(base: str, taken: set[str]) -> str:
    """Return *base*, or *base* with the first numeric suffix that makes it absent from *taken*."""
    name, suffix = base, 1
    while name in taken:
        suffix += 1
        name = f"{base}-{suffix}"
    return name


def unknown_skill_uri(entries: list[Any]) -> str:
    """Return a ``SKILL.md`` URI beside the first listed skill that no listed skill uses."""
    listed = {normalize_uri(e["uri"]) for e in entries if isinstance(e, dict) and isinstance(e.get("uri"), str)}
    parent = next(
        (root.rpartition("/")[0] for uri in _listed_skill_uris(entries) if (root := skill_root(uri))),
        "",
    )
    prefix = f"{parent}/" if parent else "skill://"
    taken = {
        uri.removeprefix(normalize_uri(prefix)).removesuffix(f"/{SKILL_FILE}")
        for uri in listed
        if uri.startswith(normalize_uri(prefix))
    }
    return f"{prefix}{_unused_name(UNKNOWN_SKILL_NAME, taken)}/{SKILL_FILE}"


async def _get_one(session: SkillsSession, uri: str) -> SkillGet:
    try:
        result = await session.request_raw("skills/get", {"uri": uri})
    except Exception as exc:  # noqa: BLE001 — a failed call is evidence, not an audit abort
        return SkillGet(uri, error=_rpc_error(exc))
    return SkillGet(uri, result.get("skill") if isinstance(result, dict) else None)


async def _get(session: SkillsSession, evidence: SkillsEvidence) -> None:
    gate = asyncio.Semaphore(READ_CONCURRENCY)

    async def one(uri: str) -> None:
        async with gate:
            # Stored as each call finishes, so a collection timeout keeps the answers already received.
            evidence.gets.append(await _get_one(session, uri))

    uris = _listed_skill_uris(evidence.entries or [])
    await asyncio.gather(*(one(uri) for uri in uris))
    order = {uri: index for index, uri in enumerate(uris)}
    evidence.gets.sort(key=lambda got: order[got.uri])
    evidence.unknown_get = await _get_one(session, unknown_skill_uri(evidence.entries or []))


async def _read_directory(session: SkillsSession, uri: str, kind: str, reads: list[DirectoryRead]) -> DirectoryRead:
    """Read *uri* as a directory across its pages, appended to *reads* before the first call.

    Until the first page answers, the read records a timeout; once a page has answered, the children received
    stay recorded as incomplete if the collection deadline cancels a later page.
    """
    read = DirectoryRead(uri, kind, error={"outcome": "timeout"}, incomplete=True)
    reads.append(read)
    children: list[Any] = []
    cursor: str | None = None
    seen: set[str] = set()
    # The unknown-child and file probes judge their first answer alone: a refusal on a later page cannot undo it.
    pages = MAX_LIST_PAGES if kind == "skill_root" else 1
    for page in range(pages):
        params: dict[str, Any] = {"uri": uri, **({"cursor": cursor} if cursor is not None else {})}
        try:
            result = await session.request_raw("resources/directory/read", params)
        except Exception as exc:  # noqa: BLE001 — a failed call is evidence, not an audit abort
            error = _rpc_error(exc)
            if page == 0:
                read.error, read.incomplete = error, False
            elif error["outcome"] not in UNOBSERVED_OUTCOMES:
                # An answered failure on a later page is judged; the children received stay recorded.
                read.error = error
            return read
        read.error = None
        items = result.get("resources") if isinstance(result, dict) else None
        if not isinstance(items, list):
            # An answer that is not a directory result; the children of earlier pages stay recorded.
            read.error = {"outcome": "malformed"}
            read.resources = children if page else None
            read.incomplete = bool(page)
            return read
        children.extend(items)
        read.resources = children
        next_cursor = result.get("nextCursor")
        if next_cursor is not None and not isinstance(next_cursor, str):
            # A cursor that is not a string is not a directory result; the children received stay recorded.
            read.error, read.incomplete = {"outcome": "malformed"}, True
            return read
        if not isinstance(next_cursor, str) or next_cursor in seen:
            read.incomplete = isinstance(next_cursor, str)
            return read
        seen.add(next_cursor)
        cursor = next_cursor
    return read


async def _read_directories(session: SkillsSession, evidence: SkillsEvidence) -> None:
    """Read a listed skill's root, a child that does not exist, and its ``SKILL.md`` as directories."""
    if evidence.settings.get("directoryRead") is not True:
        return
    skill_file = next((uri for uri in _listed_skill_uris(evidence.entries or []) if skill_root(uri)), None)
    root = skill_root(skill_file) if skill_file else None
    if skill_file is None or root is None:
        return
    root_read = await _read_directory(session, root, "skill_root", evidence.directory_reads)
    if root_read.error is not None or root_read.resources is None or root_read.incomplete:
        # Without the root's whole listing, no child name can be shown to be unknown.
        return
    # The unknown child is named after the root's listing and the skill's manifest, so it names nothing served.
    taken = {_child_name(root, child.get("uri")) for child in root_read.resources or [] if isinstance(child, dict)}
    entry = next(
        (e for e in evidence.entries or [] if isinstance(e, dict) and e.get("uri") == skill_file),
        {},
    )
    taken |= {_child_name(root, item.get("uri")) for item in manifest(entry) or [] if isinstance(item, dict)}
    unknown = f"{root}/{_unused_name(UNKNOWN_DIRECTORY_NAME, taken)}"
    await _read_directory(session, unknown, "unknown", evidence.directory_reads)
    await _read_directory(session, skill_file, "file", evidence.directory_reads)


def _child_name(root: str, uri: Any) -> str:
    """Return the first path segment of *uri* below *root*, in normal form, or "" when it is not below it."""
    prefix = normalize_uri(root) + "/"
    if not isinstance(uri, str) or not normalize_uri(uri).startswith(prefix):
        return ""
    return normalize_uri(uri)[len(prefix) :].split("/", 1)[0]


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


async def collect_skills(
    session: SkillsSession, settings: dict[str, Any], *, stateless: bool = False
) -> SkillsEvidence:
    """List the server's skills, call ``skills/get`` for each, probe directory reads, and read a sample of files."""
    evidence = SkillsEvidence(settings=settings)
    phase = "list"
    try:
        async with asyncio.timeout(COLLECTION_TIMEOUT_S):
            await _list(session, evidence, stateless=stateless)
            phase = "listed"
            # Concurrent, so stalled skills/get or directory calls cannot starve the file reads the integrity and
            # security rules need.
            await asyncio.gather(
                _get(session, evidence), _read_directories(session, evidence), _read_files(session, evidence)
            )
    except TimeoutError:
        # The deadline cancels the call in flight, so its own handler never records the outcome.
        evidence.budget_exhausted = True
        if phase == "list" and evidence.entries is None:
            evidence.list_error = {"outcome": "timeout"}
        elif phase == "list":
            evidence.list_incomplete = True
        else:
            answered = {got.uri for got in evidence.gets}
            for uri in _listed_skill_uris(evidence.entries or []):
                if uri not in answered:
                    evidence.gets.append(SkillGet(uri, error={"outcome": "timeout"}))
        logger.warning("Stopped collecting skills after %.0fs", COLLECTION_TIMEOUT_S)
    return evidence


OPENAI_MAX_SKILLS = 5
"""Uniquely named skills OpenAI imports from one MCP server scan."""

OPENAI_MAX_FILES = 100
OPENAI_MAX_SKILL_FILE_BYTES = 256 * 1024
OPENAI_MAX_FILE_BYTES = 1024 * 1024
OPENAI_MAX_SKILL_BYTES = 5 * 1024 * 1024

OPENAI_MAX_SCAN_BYTES = 8 * 1024 * 1024
"""OpenAI's cap on the skill archives generated in one scan, ZIP overhead included."""

ZIP_FILE_OVERHEAD_BYTES = 128
"""ZIP headers per file, besides the name twice and the data (local header 30, central directory entry 46)."""

ZIP_ARCHIVE_OVERHEAD_BYTES = 22
"""ZIP end-of-central-directory record, once per archive."""

MAX_REPORTED_SKILLS = 32
MAX_REPORTED_SCRIPTS = 20
MAX_REPORTED_TEXT = 500


def _reported(text: str) -> str:
    """Mask credentials in the whole string, then bound it: a cut first could hide the URL that holds them."""
    return report_evidence(text)[:MAX_REPORTED_TEXT]


def _script_uris(entry: dict[str, Any]) -> list[str]:
    """Return the manifest URIs under the skill's ``scripts/`` directory."""
    root = skill_root(entry["uri"]) if isinstance(entry.get("uri"), str) else None
    if root is None:
        return []
    prefix = normalize_uri(root) + "/scripts/"
    return [
        item["uri"]
        for item in manifest(entry) or []
        if isinstance(item, dict) and isinstance(item.get("uri"), str) and normalize_uri(item["uri"]).startswith(prefix)
    ]


def manifest_sizes(entry: dict[str, Any]) -> list[tuple[str, int | None]] | None:
    """Return ``(uri, size)`` for each manifest item with a URI, size None when invalid; None for no manifest."""
    items = manifest(entry)
    if items is None:
        return None
    return [
        (item["uri"], size_value(item.get("size")))
        for item in items
        if isinstance(item, dict) and isinstance(item.get("uri"), str)
    ]


def openai_import_issues(entry: dict[str, Any]) -> list[tuple[str, str, str]] | None:
    """Return ``(pointer, reason, expected)`` for each OpenAI per-skill import limit the manifest exceeds.

    None for a skill without a manifest. Items without a valid size count as empty.
    """
    sizes = manifest_sizes(entry)
    if sizes is None:
        return None
    skill_file = normalize_uri(entry["uri"]) if isinstance(entry.get("uri"), str) else None
    known = [(normalize_uri(uri), size or 0) for uri, size in sizes]
    issues = []
    if len(manifest(entry) or []) > OPENAI_MAX_FILES:
        issues.append(("/resources", "too_many_files", "at most 100 files"))
    if any(uri == skill_file and size > OPENAI_MAX_SKILL_FILE_BYTES for uri, size in known):
        issues.append((f"/{SKILL_FILE}", "skill_file_too_large", "at most 256 KiB"))
    if any(uri != skill_file and size > OPENAI_MAX_FILE_BYTES for uri, size in known):
        issues.append(("/resources", "file_too_large", "at most 1 MiB per supporting file"))
    if sum(size for _, size in known) > OPENAI_MAX_SKILL_BYTES:
        issues.append(("/resources", "skill_too_large", "at most 5 MiB per skill"))
    return issues


def _archive_bytes_at_most(entries: list[dict[str, Any]]) -> int:
    """Return an upper bound on the ZIP archives of these skills: every file stored, never compressed.

    Deflate output can exceed its input by about 0.1%, which the bound includes.
    """
    total = 0
    for entry in entries:
        total += ZIP_ARCHIVE_OVERHEAD_BYTES
        for uri, size in manifest_sizes(entry) or []:
            data = size or 0
            total += data + data // 1000 + 5 + ZIP_FILE_OVERHEAD_BYTES + 2 * len(uri.encode("utf-8"))
    return total


def _manifest_complete(entry: dict[str, Any]) -> bool:
    """Whether every manifest item carries a URI and a valid size."""
    items, sizes = manifest(entry), manifest_sizes(entry)
    return items is not None and sizes is not None and len(sizes) == len(items) and all(s is not None for _, s in sizes)


def _openai_fit(evidence: SkillsEvidence, entries: list[dict[str, Any]]) -> bool | None:
    """Whether the whole catalog fits one OpenAI import: False on a known excess, None when it cannot be known.

    Archive sizes are not observable: the catalog fits when even its uncompressed archives would, and is unknown
    when they would not, since compression may still bring them under the limit.
    """
    if len(entries) > OPENAI_MAX_SKILLS or any(openai_import_issues(entry) for entry in entries):
        return False
    complete = (
        evidence.entries is not None
        and not evidence.list_incomplete
        and not evidence.list_malformed
        and len(entries) == len(evidence.entries)
        and all(_manifest_complete(e) for e in entries)
    )
    return True if complete and _archive_bytes_at_most(entries) <= OPENAI_MAX_SCAN_BYTES else None


def skills_report(evidence: SkillsEvidence) -> dict[str, Any]:
    """Return the skills facts a report shows without scoring them.

    ``allowed-tools`` and bundled scripts are gated by the host (SEP-2640 §Security Implications), and OpenAI's
    catalog limits (five skills, 8 MiB of archives per scan) say nothing wrong about a larger catalog. Lists are
    bounded; the counts are complete for the skills listed.
    """
    entries = [e for e in evidence.entries or [] if isinstance(e, dict) and isinstance(e.get("uri"), str)]
    notable: list[dict[str, Any]] = []
    with_tools = with_scripts = 0
    listed_bytes = 0
    for entry in entries:
        raw = entry.get("frontmatter")
        frontmatter: dict[str, Any] = raw if isinstance(raw, dict) else {}
        tools = frontmatter.get("allowed-tools")
        scripts = _script_uris(entry)
        with_tools += "allowed-tools" in frontmatter
        with_scripts += bool(scripts)
        listed_bytes += sum(size or 0 for _, size in manifest_sizes(entry) or [])
        if ("allowed-tools" in frontmatter or scripts) and len(notable) < MAX_REPORTED_SKILLS:
            notable.append(
                {
                    "uri": _reported(entry["uri"]),
                    "allowed_tools": _reported(tools) if isinstance(tools, str) else None,
                    "scripts": [_reported(uri) for uri in scripts[:MAX_REPORTED_SCRIPTS]],
                    "scripts_total": len(scripts),
                }
            )
    return {
        "skills_listed": len(entries),
        "listing_incomplete": evidence.list_incomplete,
        "skills_with_allowed_tools": with_tools,
        "skills_with_scripts": with_scripts,
        "skills": notable,
        "openai_import": {
            "skills_imported_at_most": OPENAI_MAX_SKILLS,
            "listed_bytes": listed_bytes,
            "scan_archive_limit_bytes": OPENAI_MAX_SCAN_BYTES,
            "fits": _openai_fit(evidence, entries),
        },
    }
