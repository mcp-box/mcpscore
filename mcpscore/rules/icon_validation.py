"""Shared validation for MCP catalog icon declarations."""

import base64
import binascii
import re
from typing import Protocol
from urllib.parse import urlsplit

from mcp_types import Icon


class IconOwner(Protocol):
    """Catalog item carrying optional icons."""

    @property
    def icons(self) -> list[Icon] | None:  # pragma: no cover — typing stub, never called
        """Icons declared by the catalog item, if any."""


_URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*$")
_URI_CHARACTER_RE = re.compile(r"^[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$")
_INVALID_PERCENT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_DATA_URI_RE = re.compile(
    r"^data:(image/[A-Za-z0-9!#$&^_.+-]+)"
    r"(?:;[A-Za-z0-9!#$&^_.+-]+=[A-Za-z0-9!#$&^_.+%-]+)*"
    r";base64,([A-Za-z0-9+/]*={0,2})$",
    re.IGNORECASE,
)
_MIME_TYPE_ATOM = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_MIME_TYPE_QUOTED = r'"(?:[\t !#-\[\]-~]|\\[\t -~])*"'
_MIME_TYPE_RE = re.compile(
    rf"^{_MIME_TYPE_ATOM}/{_MIME_TYPE_ATOM}"
    rf"(?:[ \t]*;[ \t]*{_MIME_TYPE_ATOM}=(?:{_MIME_TYPE_ATOM}|{_MIME_TYPE_QUOTED}))*$"
)
_SIZE_RE = re.compile(r"^[1-9][0-9]*x[1-9][0-9]*$")


def find_invalid_icons(items: list[tuple[str, IconOwner]]) -> list[dict[str, object]]:
    """Return compact diagnostics for structurally invalid catalog icons."""
    invalid: list[dict[str, object]] = []
    for owner, item in items:
        for index, icon in enumerate(item.icons or []):
            fields: list[str] = []
            if not _is_absolute_uri(icon.src):
                fields.append("src")
            if icon.mime_type is not None and _MIME_TYPE_RE.fullmatch(icon.mime_type) is None:
                fields.append("mimeType")
            if icon.sizes is not None and any(
                size != "any" and _SIZE_RE.fullmatch(size) is None for size in icon.sizes
            ):
                fields.append("sizes")
            if fields:
                invalid.append({"item": owner, "icon_index": index, "invalid_fields": fields})
    return invalid


def _is_absolute_uri(value: str) -> bool:
    """Return whether *value* is a usable absolute icon URI."""
    if not value or _URI_CHARACTER_RE.fullmatch(value) is None or _INVALID_PERCENT_ESCAPE_RE.search(value) is not None:
        return False
    try:
        parsed = urlsplit(value)
        _ = parsed.port  # urlsplit validates ports lazily.
    except ValueError:
        return False
    if not parsed.scheme or _URI_SCHEME_RE.fullmatch(parsed.scheme) is None:
        return False
    if parsed.scheme.lower() in {"http", "https"}:
        return parsed.hostname is not None
    if parsed.scheme.lower() == "data":
        return _is_base64_image_data_uri(value)
    return True


def _is_base64_image_data_uri(value: str) -> bool:
    """Return whether *value* embeds a base64-encoded image."""
    match = _DATA_URI_RE.fullmatch(value)
    if match is None or not match.group(2):
        return False
    try:
        base64.b64decode(match.group(2), validate=True)
    except (binascii.Error, ValueError):
        return False
    return True
