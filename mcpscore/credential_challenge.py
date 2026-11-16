"""Recognise credential refusals sent as a JSON-RPC error instead of HTTP 401/403, and credential headers.

MCP authorization is optional (2025-11-25 Authorization §Protocol Requirements), so a server may
refuse an anonymous request with HTTP 200 and a JSON-RPC error naming the missing credential.
Such an answer never reached the method handler: it is a gate, like a 401, and never a verdict on
the probed request.
"""

import re
from typing import Any

from mcpscore.diagnostics import quoted_preview

_CREDENTIAL = r"(?:\b(?:x-)?api[-_ ]?key\b|\b(?:access|auth|bearer|api|session)[-_ ]?token\b|\bcredentials?\b)"
_REFUSED = (
    r"(?:\brequired\b|\bmissing\b|\binvalid\b|\bexpired\b|\brevoked\b|\brejected\b|\bnot\ valid\b"
    r"|\bnot\ provided\b|\bincorrect\b|\bconfigure\b|\bmust\ be\ (?:provided|supplied|set)\b)"
)
_CREDENTIAL_PHRASES = re.compile(
    rf"""
    {_CREDENTIAL}[^.;:]{{0,40}}?{_REFUSED}
    | {_REFUSED}[^.;:]{{0,40}}?{_CREDENTIAL}
    | \bunauthori[sz]ed\b
    | \bunauthenticated\b
    | \bnot\ authenticated\b
    | \bauthentication\ (?:is\ )?(?:required|failed|missing)\b
    | \bauthori[sz]ation\ (?:header\ )?(?:is\ )?(?:required|missing)\b
    """,
    re.IGNORECASE | re.VERBOSE,
)
"""A credential named next to a refusal word, or a refusal that is about authentication itself.

A bare "token" never counts: parse and pagination errors talk about tokens too.
"""
_CHALLENGE_HEADER = re.compile(
    r"\b(X-[A-Za-z0-9-]*(?:key|token|auth)[A-Za-z0-9-]*|Authorization|Api-Key)\b", re.IGNORECASE
)
_CREDENTIAL_HEADER_NAME = re.compile(r"api-?key|token|auth|secret", re.IGNORECASE)

MESSAGE_PREVIEW_LIMIT = 160
"""Most code points of the server's own refusal text kept in reports and console lines."""


def challenge_text(error: object) -> str:
    """Return a JSON-RPC error object's ``message`` and ``data`` text (a string, or an object's string values)."""
    if not isinstance(error, dict):
        return ""
    data = error.get("data")
    parts = [error.get("message"), *(data.values() if isinstance(data, dict) else [data])]
    return " ".join(part for part in parts if isinstance(part, str))


def is_credential_challenge(error: object) -> bool:
    """Whether a JSON-RPC error object refuses the request for a missing or invalid credential."""
    return bool(_CREDENTIAL_PHRASES.search(challenge_text(error)))


def challenge_header(error: object) -> str | None:
    """Return the request header a credential challenge names (e.g. ``X-API-Key``), spelled as the server wrote it."""
    match = _CHALLENGE_HEADER.search(challenge_text(error))
    return match[1] if match else None


def is_credential_header(name: str) -> bool:
    """Whether a request header name carries a credential (Authorization, an API key, a token, a secret)."""
    return _CREDENTIAL_HEADER_NAME.search(name) is not None


def has_credential(headers: dict[str, str] | None) -> bool:
    """Whether the header set carries a non-blank credential header."""
    return any(is_credential_header(name) and value.strip() for name, value in (headers or {}).items())


def redact_values(text: str, headers: dict[str, str] | None) -> str:
    """Replace every credential header value the caller supplied that appears in *text* with ``[redacted]``."""
    secrets: set[str] = set()
    for name, value in (headers or {}).items():
        if is_credential_header(name) and value.strip():
            # "Bearer <token>": a server may echo the token without its scheme.
            secrets |= {value.strip(), value.split()[-1]}
    # Longest first across all headers, so a short value never replaces part of a longer one.
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    return text


def challenge_summary(error: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
    """Return the report-safe facts of a credential challenge: code, quoted bounded message, named header.

    The message is the server's own text, escaped and quoted, with supplied credential values redacted.
    """
    message = error.get("message")
    text = redact_values(message, headers) if isinstance(message, str) else ""
    code = error.get("code")
    # The header is read from redacted text: an echoed credential can look like a header name.
    return {
        "error_code": code if isinstance(code, int) else None,
        "message": quoted_preview(text, MESSAGE_PREVIEW_LIMIT) if text else None,
        "header": challenge_header({"message": redact_values(challenge_text(error), headers)}),
    }
