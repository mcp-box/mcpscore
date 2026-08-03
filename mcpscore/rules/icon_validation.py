"""Shared validation for MCP catalog icon declarations."""

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
    """Return whether *value* has a syntactically valid URI scheme."""
    if not value or any(character.isspace() for character in value):
        return False
    try:
        scheme = urlsplit(value).scheme
    except ValueError:
        return False
    return bool(scheme and _URI_SCHEME_RE.fullmatch(scheme))
