"""Keep useful report evidence while masking narrowly identified credentials."""

import re
from typing import Any
from urllib.parse import unquote_plus

from mcpscore.diagnostics import quoted_preview

_SECRET_QUERY_KEYS = frozenset(
    {
        "access_token",
        "refresh_token",
        "id_token",
        "token",
        "api_key",
        "apikey",
        "client_secret",
        "password",
        "secret",
        "authorization",
        "code",
    }
)
_URL = re.compile(r"[a-z][a-z0-9+.-]*://[^\s\"'<>]+", re.IGNORECASE)
_AUTHORITY = re.compile(r"([a-z][a-z0-9+.-]*://)([^/?#]*)", re.IGNORECASE)


def _mask_url(match: re.Match[str]) -> str:
    """Preserve URL spelling, including public parameters and malformed URL evidence."""
    url = _AUTHORITY.sub(lambda m: m[1] + m[2].rsplit("@", 1)[-1], match[0], count=1)
    base, fragment_separator, fragment = url.partition("#")
    path, query_separator, query = base.partition("?")
    parts = []
    for part in query.split("&"):
        key, separator, value = part.partition("=")
        if separator and unquote_plus(key).casefold().replace("-", "_") in _SECRET_QUERY_KEYS:
            value = "[redacted]"
        parts.append(key + separator + value)
    return path + query_separator + "&".join(parts) + fragment_separator + fragment


def report_evidence(value: Any, *, key: str = "") -> Any:
    """Copy evidence, masking session IDs, URL userinfo and known secret query keys.

    Public challenges and exception reasons remain useful evidence. Apply the
    same URL masking inside their text. This is not a general secret detector;
    raw response bodies still belong in ProbeResult.payload, outside reports.
    """
    if key == "response_session_id":
        return None if value is None else "[redacted]"
    if isinstance(value, dict):
        # Reserve literal names first, so masking cannot overwrite an existing key.
        # Sort source names so parallel summary maps receive the same aliases even
        # if their insertion orders differ. Never include original secrets in aliases.
        names = {k: _URL.sub(_mask_url, k) if isinstance(k, str) else k for k in value}
        reserved = set(names.values())
        used = {k for k, masked in names.items() if k == masked}
        for original in sorted(k for k, masked in names.items() if k != masked):
            masked = names[original]
            candidate = masked
            suffix = 2
            if candidate in used:
                candidate = f"{masked} [masked name {suffix}]"
                while candidate in used or candidate in reserved:
                    suffix += 1
                    candidate = f"{masked} [masked name {suffix}]"
            names[original] = candidate
            used.add(candidate)
        return {names[k]: report_evidence(v, key=k) for k, v in value.items()}
    if isinstance(value, list):
        return [report_evidence(item, key=key) for item in value]
    if isinstance(value, str):
        return _URL.sub(_mask_url, value)
    return value


URL_PREVIEW_LIMIT = 200
"""Well-known discovery URLs routinely exceed 60 characters; a cut URL is useless."""

LIST_PREVIEW_ITEMS = 10


def evidence_preview(value: Any) -> str:
    """Quote a bounded human preview after applying targeted credential masking.

    Lists render item by item (``"a", "b"``) instead of as Python syntax, with
    at most ``LIST_PREVIEW_ITEMS`` shown. A value that is a single URL keeps up
    to ``URL_PREVIEW_LIMIT`` characters so discovery locations stay readable.
    """
    if isinstance(value, (list, tuple)):
        shown = [evidence_preview(item) for item in value[:LIST_PREVIEW_ITEMS]]
        if not shown:
            return "(none)"
        more = len(value) - len(shown)
        return ", ".join(shown) + (f", … {more} more" if more > 0 else "")
    text = str(report_evidence(value))
    limit = URL_PREVIEW_LIMIT if _URL.fullmatch(text) else 60
    return quoted_preview(text, limit)
