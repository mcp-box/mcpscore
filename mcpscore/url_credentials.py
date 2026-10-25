"""Find credentials carried in a URL's query string.

MCP Authorization (2025-03-26 onward) §Access Token Usage: access tokens MUST NOT be
included in the URI query string. This module decides which query parameters carry a
credential; ``auth_token_not_in_query`` uses it, and so can services that refuse such
URLs before auditing, so both agree on what counts.
"""

import re
from urllib.parse import unquote_plus, urlsplit, urlunsplit

# Parameter names that always carry a credential, after normalising (see _normalise).
_CREDENTIAL_NAMES = frozenset({"token", "access_token", "api_key", "apikey", "secret", "client_secret", "password"})
_CREDENTIAL_SUFFIXES = ("_token", "_secret", "_api_key")
# Names that only sometimes do (`?key=getting-started` is a lookup key): they count when the value looks secret.
_AMBIGUOUS_NAMES = frozenset({"key", "auth", "sig", "signature", "session"})
_AMBIGUOUS_SUFFIXES = ("_key",)
_SECRET_PREFIXES = ("rdme_", "sk_", "rk_", "ghp_", "github_pat_", "xoxb-", "xoxp-")
# Long, random-looking: base64/hex/JWT alphabet, letters and digits mixed.
_SECRET_SHAPE = re.compile(r"(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9._~+/=-]{20,}")


def _normalise(name: str) -> str:
    # apiKey, api-key, API_KEY and serviceAPIKey all end in api_key.
    snake = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", name)
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", snake)
    return re.sub(r"[-.\s]", "_", snake).lower()


def _looks_secret(value: str) -> bool:
    # Form decoding turns a literal "+" in a base64 value into a space; check it as sent too.
    return any(
        candidate.lower().startswith(_SECRET_PREFIXES) or bool(_SECRET_SHAPE.fullmatch(candidate))
        for candidate in (value, value.replace(" ", "+"))
    )


def _is_credential(name: str, value: str) -> bool:
    normalised = _normalise(name)
    if normalised in _CREDENTIAL_NAMES or normalised.endswith(_CREDENTIAL_SUFFIXES):
        return True
    ambiguous = normalised in _AMBIGUOUS_NAMES or normalised.endswith(_AMBIGUOUS_SUFFIXES)
    return ambiguous and _looks_secret(value)


def credential_query_params(query: str | None) -> list[str]:
    """Return the names of the query parameters that carry a credential, in order, without duplicates.

    Names match exactly after normalising, never by substring (``author``, ``keyword`` and
    ``design`` are not credentials). Ambiguous names such as ``key`` count only with a
    secret-shaped value.
    """
    found: list[str] = []
    for name, value in (_decoded(field) for field in (query or "").split("&") if field):
        if _is_credential(name, value) and name not in found:
            found.append(name)
    return found


def without_credential_params(url: str) -> str:
    """Return ``url`` with its credential query parameters removed and every other byte kept as sent."""
    parts = urlsplit(url)
    kept = [field for field in parts.query.split("&") if not _is_credential(*_decoded(field))]
    return urlunsplit(parts._replace(query="&".join(field for field in kept if field)))


def _decoded(field: str) -> tuple[str, str]:
    name, _, value = field.partition("=")
    return unquote_plus(name), unquote_plus(value)
