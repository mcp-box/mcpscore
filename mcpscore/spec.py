"""Registry of MCP specification versions and their normative facts.

This module is the single source of truth for everything mcpscore knows about
each MCP specification revision: its lifecycle model, status, deprecated
features, required HTTP request headers, and JSON Schema dialect handling.
Rules and probes read version facts from here instead of hardcoding them, so
supporting a new spec revision means adding one ``SpecVersion`` entry (plus
any new probes/rules) — never rewriting support for older versions.

Version identifiers are the wire values (``YYYY-MM-DD`` date strings), which
makes lexicographic comparison a total chronological order — see :func:`compare`.

Facts for the ``2026-07-28`` entry were verified against the release candidate
(locked 2026-05-21). The changelog is published under ``/specification/draft/``
until the revision goes final; re-verify the entry against the dated spec URL
on release before flipping its status to ``CURRENT``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import StrEnum

__all__ = [
    "DRAFT",
    "LATEST",
    "SPEC_VERSIONS",
    "Lifecycle",
    "SpecStatus",
    "SpecVersion",
    "allowed_versions",
    "compare",
    "deprecated_versions",
    "get",
]


class Lifecycle(StrEnum):
    """Connection lifecycle model of a spec revision."""

    STATEFUL = "stateful"
    """`initialize`/`initialized` handshake with per-session state ("Legacy",
    all revisions through 2025-11-25)."""

    STATELESS = "stateless"
    """Per-request ``_meta`` context and ``server/discover``; no handshake
    ("Modern", 2026-07-28 and later)."""


class SpecStatus(StrEnum):
    """Publication status of a spec revision."""

    CURRENT = "current"
    """The newest final revision — what `protocol_version_latest` points at."""

    SUPERSEDED = "superseded"
    """A final revision with a newer final revision after it. Still valid to
    negotiate; servers are nudged toward CURRENT by `protocol_version_latest`."""

    DEPRECATED = "deprecated"
    """Formally deprecated by the specification. No revision has this status
    today; `protocol_version_not_deprecated` fails servers negotiating one."""

    DRAFT = "draft"
    """A draft or release candidate. Not yet an allowed version for
    `protocol_version_allowed`; the target of readiness rules."""


@dataclass(frozen=True)
class SpecVersion:
    """Normative facts about one MCP specification revision."""

    version: str
    """Wire identifier, e.g. ``"2025-11-25"``."""

    release_date: date
    """Publication date of the revision (for DRAFT: the expected final date)."""

    lifecycle: Lifecycle
    """Connection lifecycle model this revision mandates."""

    status: SpecStatus
    """Publication status (drives allowed/latest/deprecated version lists)."""

    deprecated_features: frozenset[str]
    """Features the spec's deprecation registry lists as deprecated *as of*
    this revision (cumulative — includes carry-overs from earlier revisions).
    Deprecated features remain functional during their deprecation window."""

    required_request_headers: frozenset[str]
    """HTTP request headers a client MUST send on Streamable HTTP POSTs under
    this revision. Conditionally required headers (e.g. ``Mcp-Name``) are
    covered in ``notes``."""

    tool_schema_default_dialect: str | None
    """JSON Schema dialect assumed when a tool schema has no ``$schema`` field.
    ``None`` for revisions that do not define dialect handling (all revisions
    before 2026-07-28)."""

    notes: str = ""
    """Non-machine-readable caveats about this revision."""


SPEC_VERSIONS: tuple[SpecVersion, ...] = (
    SpecVersion(
        version="2024-11-05",
        release_date=date(2024, 11, 5),
        lifecycle=Lifecycle.STATEFUL,
        status=SpecStatus.SUPERSEDED,
        deprecated_features=frozenset(),
        required_request_headers=frozenset(),
        tool_schema_default_dialect=None,
        notes="Initial release. HTTP transport is HTTP+SSE; no authorization spec.",
    ),
    SpecVersion(
        version="2025-03-26",
        release_date=date(2025, 3, 26),
        lifecycle=Lifecycle.STATEFUL,
        status=SpecStatus.SUPERSEDED,
        deprecated_features=frozenset({"http-sse-transport"}),
        required_request_headers=frozenset(),
        tool_schema_default_dialect=None,
        notes="Introduces Streamable HTTP (deprecates HTTP+SSE) and OAuth-based authorization.",
    ),
    SpecVersion(
        version="2025-06-18",
        release_date=date(2025, 6, 18),
        lifecycle=Lifecycle.STATEFUL,
        status=SpecStatus.SUPERSEDED,
        deprecated_features=frozenset({"http-sse-transport"}),
        required_request_headers=frozenset({"MCP-Protocol-Version"}),
        tool_schema_default_dialect=None,
        notes=(
            "Adds elicitation, structured tool output, the authorization resource-server "
            "split (RFC 9728 protected resource metadata), and the MCP-Protocol-Version "
            "header on HTTP requests."
        ),
    ),
    SpecVersion(
        version="2025-11-25",
        release_date=date(2025, 11, 25),
        lifecycle=Lifecycle.STATEFUL,
        status=SpecStatus.CURRENT,
        deprecated_features=frozenset({"http-sse-transport", "sampling-include-context"}),
        required_request_headers=frozenset({"MCP-Protocol-Version"}),
        tool_schema_default_dialect=None,
        notes="Adds experimental tasks and URL-mode elicitation; deprecates sampling includeContext.",
    ),
    SpecVersion(
        version="2026-07-28",
        release_date=date(2026, 7, 28),
        lifecycle=Lifecycle.STATELESS,
        status=SpecStatus.DRAFT,
        deprecated_features=frozenset(
            {
                "http-sse-transport",
                "sampling-include-context",
                "roots",
                "sampling",
                "logging",
                "dynamic-client-registration",
            }
        ),
        required_request_headers=frozenset({"MCP-Protocol-Version", "Mcp-Method"}),
        tool_schema_default_dialect="2020-12",
        notes=(
            "Release candidate locked 2026-05-21; flip status to CURRENT once final. "
            "Removes the initialize handshake (per-request _meta; mandatory server/discover). "
            "Mcp-Name is additionally required on tools/call, resources/read, and prompts/get. "
            "Deprecated features have earliest removal 2027-07-28 and remain functional."
        ),
    ),
)
"""All known spec revisions, ordered oldest to newest."""


LATEST: SpecVersion = next(v for v in reversed(SPEC_VERSIONS) if v.status is SpecStatus.CURRENT)
"""The newest final revision — the recommendation target for `protocol_version_latest`."""

DRAFT: SpecVersion | None = next(
    (v for v in reversed(SPEC_VERSIONS) if v.status is SpecStatus.DRAFT),
    None,
)
"""The newest draft/release-candidate revision (readiness target), if any."""

_BY_VERSION: dict[str, SpecVersion] = {v.version: v for v in SPEC_VERSIONS}


def get(version: str) -> SpecVersion | None:
    """Look up a spec revision by its wire identifier.

    Args:
        version: Wire identifier, e.g. ``"2025-11-25"``

    Returns:
        The matching SpecVersion, or None for an unknown identifier

    """
    return _BY_VERSION.get(version)


def compare(a: str, b: str) -> int:
    """Chronologically compare two spec version identifiers.

    ``YYYY-MM-DD`` identifiers order chronologically under plain string
    comparison, so this works for unknown-but-well-formed versions too.

    Args:
        a: First version identifier
        b: Second version identifier

    Returns:
        -1 if ``a`` is older than ``b``, 0 if equal, 1 if newer

    """
    if a == b:
        return 0
    return -1 if a < b else 1


def allowed_versions() -> list[str]:
    """Version identifiers a server may negotiate without failing the audit.

    Every registered revision except drafts: draft revisions are readiness
    targets, not yet allowed versions.

    Returns:
        Wire identifiers ordered oldest to newest

    """
    return [v.version for v in SPEC_VERSIONS if v.status is not SpecStatus.DRAFT]


def deprecated_versions() -> list[str]:
    """Version identifiers formally deprecated by the specification.

    Currently empty: the spec deprecates *features*, and supersedes versions,
    but has not deprecated a protocol version outright.

    Returns:
        Wire identifiers ordered oldest to newest

    """
    return [v.version for v in SPEC_VERSIONS if v.status is SpecStatus.DEPRECATED]
