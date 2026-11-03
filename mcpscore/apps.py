"""MCP Apps extension evidence: the UI resources a server's tools point at, read back for the apps rules.

A server delivers an MCP App by pointing a tool at a ``ui://`` resource in ``_meta.ui.resourceUri`` (ext-apps
specification 2026-01-26, §Resource Discovery). Servers MAY omit UI resources from ``resources/list``, so the
collector reads each pointer target with ``resources/read``, the way a host fetches it.
"""

import asyncio
import base64
import binascii
from dataclasses import dataclass, field
from html.parser import HTMLParser
import logging
from typing import Any, Protocol

from mcp_types import Resource, Tool

from .skills import rpc_error

logger = logging.getLogger(__name__)

UI_EXTENSION = "io.modelcontextprotocol/ui"
"""Extension identifier a client declares under ``capabilities.extensions``."""

UI_MIME_TYPE = "text/html;profile=mcp-app"
"""The one MIME type the 2026-01-26 specification allows for UI resource content."""

UI_EXTENSION_SETTINGS: dict[str, Any] = {"mimeTypes": [UI_MIME_TYPE]}
"""What mcpscore declares, so a server that registers UI tools only for supporting hosts shows them."""

UI_SCHEME = "ui://"
FLAT_POINTER_KEY = "ui/resourceUri"
"""The deprecated pointer key, replaced by ``_meta.ui.resourceUri``."""

VISIBILITY_VALUES = frozenset({"model", "app"})

MAX_UI_READS = 16
"""UI resources read per audit; pointers past it are left unread."""

READ_TIMEOUT_S = 20.0
COLLECTION_TIMEOUT_S = 60.0
DOCUMENT_PREFIX_BYTES = 64 * 1024
"""How much of a UI document is parsed: its doctype and root element come first."""


class AppsSession(Protocol):
    """The one session call the collector needs; :class:`mcpscore.mcp_client.MCPClient` provides it."""

    async def read_resource_contents(self, uri: str) -> list[dict[str, Any]]:
        """Read one resource and return its contents as dicts (``uri``, ``mimeType``, ``text`` or ``blob``)."""
        ...


@dataclass
class UiContent:
    """One item of a UI resource's ``resources/read`` contents."""

    mime_type: Any
    has_text: bool
    has_blob: bool
    blob_valid: bool = True
    html_document: bool | None = None
    """Whether the content opens as an HTML document; None when it has no text or decodable blob."""


@dataclass
class UiRead:
    """What one ``resources/read`` of a UI resource returned."""

    uri: str
    contents: list[UiContent] = field(default_factory=list)
    error: dict[str, Any] | None = None


@dataclass
class AppsEvidence:
    """The reads of the UI resources the server's tools point at."""

    reads: dict[str, UiRead] = field(default_factory=dict)
    unread: int = 0
    """Pointer targets not read because of ``MAX_UI_READS`` or the collection deadline."""


def tool_meta(tool: Tool) -> dict[str, Any]:
    """Return a tool's ``_meta`` object, or an empty one."""
    meta = getattr(tool, "meta", None)
    return meta if isinstance(meta, dict) else {}


def ui_meta(tool: Tool) -> Any:
    """Return a tool's ``_meta.ui`` value as served (any JSON type), or None."""
    return tool_meta(tool).get("ui")


def nested_pointer(tool: Tool) -> Any:
    """Return ``_meta.ui.resourceUri`` as served, or None."""
    ui = ui_meta(tool)
    return ui.get("resourceUri") if isinstance(ui, dict) else None


def flat_pointer(tool: Tool) -> Any:
    """Return the deprecated ``_meta["ui/resourceUri"]`` as served, or None."""
    return tool_meta(tool).get(FLAT_POINTER_KEY)


def pointer(tool: Tool) -> Any:
    """Return the tool's UI resource pointer: the nested key, else the deprecated flat one."""
    nested = nested_pointer(tool)
    return nested if nested is not None else flat_pointer(tool)


def ui_tools(tools: list[Tool] | None) -> list[tuple[int, Tool]]:
    """Return the tools carrying any MCP Apps metadata, with their listing index."""
    return [
        (index, tool)
        for index, tool in enumerate(tools or [])
        if ui_meta(tool) is not None or flat_pointer(tool) is not None
    ]


def uses_apps(tools: list[Tool] | None, resources: list[Resource] | None) -> bool:
    """Whether the server exposes MCP Apps: a tool with UI metadata or a listed ``ui://`` resource."""
    return bool(ui_tools(tools)) or any(str(r.uri).startswith(UI_SCHEME) for r in resources or [])


def pointer_targets(tools: list[Tool] | None) -> list[str]:
    """Return the distinct ``ui://`` pointer targets, in listing order."""
    targets: dict[str, None] = {}
    for _, tool in ui_tools(tools):
        uri = pointer(tool)
        if isinstance(uri, str) and uri.startswith(UI_SCHEME):
            targets[uri] = None
    return list(targets)


class _DocumentStart(HTMLParser):
    """Record a document's first declaration and first start tag."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.doctype: str | None = None
        self.first_tag: str | None = None
        self.text_before_root = False

    def handle_decl(self, decl: str) -> None:
        if self.doctype is None and self.first_tag is None:
            self.doctype = decl

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.first_tag is None:
            self.first_tag = tag

    def handle_data(self, data: str) -> None:
        if self.first_tag is None and data.strip():
            self.text_before_root = True


def is_html_document(text: str) -> bool:
    """Whether *text* opens as an HTML document: an ``html`` doctype or an ``html`` root, before any content.

    Only the prefix is parsed. A fragment (``<div>…``) or plain text is not a document.
    """
    parser = _DocumentStart()
    parser.feed(text.removeprefix("﻿")[:DOCUMENT_PREFIX_BYTES])
    if parser.text_before_root:
        return False
    if parser.doctype is not None:
        return parser.doctype.lower().split()[:2] == ["doctype", "html"]
    return parser.first_tag == "html"


def _content(item: dict[str, Any]) -> UiContent:
    text, blob = item.get("text"), item.get("blob")
    content = UiContent(item.get("mimeType"), isinstance(text, str), isinstance(blob, str))
    if isinstance(text, str):
        content.html_document = is_html_document(text)
    elif isinstance(blob, str):
        # Base64 expands 3 bytes to 4 characters; decode just enough for the document prefix.
        head = blob[: (DOCUMENT_PREFIX_BYTES // 3 + 1) * 4]
        try:
            raw = base64.b64decode(head, validate=True)
        except (binascii.Error, ValueError):
            content.blob_valid = False
        else:
            content.html_document = is_html_document(raw.decode("utf-8", errors="replace"))
    return content


async def _read(session: AppsSession, uri: str) -> UiRead:
    try:
        async with asyncio.timeout(READ_TIMEOUT_S):
            contents = await session.read_resource_contents(uri)
    except Exception as exc:  # noqa: BLE001 — a failed read is evidence, not an audit abort
        return UiRead(uri, error=rpc_error(exc))
    return UiRead(uri, [_content(item) for item in contents if isinstance(item, dict)])


async def collect_apps(session: AppsSession, tools: list[Tool] | None) -> AppsEvidence:
    """Read each UI resource the tools point at (up to ``MAX_UI_READS``), one at a time."""
    targets = pointer_targets(tools)
    evidence = AppsEvidence(unread=max(0, len(targets) - MAX_UI_READS))
    try:
        async with asyncio.timeout(COLLECTION_TIMEOUT_S):
            for uri in targets[:MAX_UI_READS]:
                evidence.reads[uri] = await _read(session, uri)
    except TimeoutError:
        evidence.unread = len(targets) - len(evidence.reads)
        logger.warning("Stopped reading MCP Apps UI resources after %.0fs", COLLECTION_TIMEOUT_S)
    return evidence
