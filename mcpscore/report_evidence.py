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
        return {k: report_evidence(v, key=k) for k, v in value.items()}
    if isinstance(value, list):
        return [report_evidence(item, key=key) for item in value]
    if isinstance(value, str):
        return _URL.sub(_mask_url, value)
    return value


def evidence_preview(value: Any) -> str:
    """Quote a bounded human preview after applying targeted credential masking."""
    return quoted_preview(str(report_evidence(value)))
