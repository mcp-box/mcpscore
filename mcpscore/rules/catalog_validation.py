"""Shared validators for MCP resource catalog fields."""

from datetime import datetime
import re

_MEDIA_TYPE_ATOM_PATTERN = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_MEDIA_TYPE_QUOTED_VALUE = r'"(?:[\t !#-\[\]-~]|\\[\t -~])*"'
_MEDIA_TYPE_RE = re.compile(
    rf"^{_MEDIA_TYPE_ATOM_PATTERN}/{_MEDIA_TYPE_ATOM_PATTERN}"
    rf"(?:[ \t]*;[ \t]*{_MEDIA_TYPE_ATOM_PATTERN}="
    rf"(?:{_MEDIA_TYPE_ATOM_PATTERN}|{_MEDIA_TYPE_QUOTED_VALUE}))*$"
)


def is_valid_media_type(value: str) -> bool:
    """Return whether *value* is a syntactically valid media type."""
    return _MEDIA_TYPE_RE.fullmatch(value) is not None


def is_iso_8601(value: str) -> bool:
    """Return whether *value* is a non-blank ISO 8601 date or timestamp."""
    if not value or value != value.strip():
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True
