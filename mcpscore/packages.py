"""Package-registry metadata for MCP servers distributed as npm or PyPI packages.

Half the MCP registry — 9,832 of 20,016 active servers in the 2026-08 crawl —
ships as a package and speaks stdio, with no remote endpoint. Those servers are
auditable from the CLI (``mcpscore --stdio npx -y <pkg>``) but not from a public
web service, which must never execute an attacker-chosen package.

This module scores what is *declared* rather than what runs: it fetches the
package's own registry metadata over plain HTTPS GETs and nothing else. No
package is downloaded, no install hook runs, no code executes. That makes it
safe on any surface, including the web service, at the cost of judging the
packaging rather than the server (see ``project/tech-design/design-package-audits.md``).

Nothing here raises for a network or registry failure — like ``probes``, a
failure is data (``PackageOutcome``), because "this package does not exist" is
itself the most important finding the pack can report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
import logging
import re
from typing import Any
from urllib.parse import quote

import httpx2

logger = logging.getLogger(__name__)

FETCH_TIMEOUT_S = 15.0
"""Per-request timeout for a registry metadata fetch."""

MAX_METADATA_BYTES = 5 * 1024 * 1024
"""Cap on a metadata document. npm packuments for long-lived packages carry every
version ever published and can reach megabytes; a registry that streams without
end must not be able to exhaust the auditor's memory."""

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_REGISTRY = "https://pypi.org"


class PackageRegistry(StrEnum):
    """Package registries mcpscore can read metadata from.

    Mirrors the MCP registry's ``registryType`` values for the two that
    dominate: of 1,663 packages across 3,000 servers sampled 2026-08-15, npm had
    991 and PyPI 613 — **96.4% together**. OCI (55) and mcpb (4) are deliberately
    unsupported here, and for different reasons: OCI has a manifest API and would
    slot in much like these two, while mcpb's identifier is a publisher-chosen
    download URL whose metadata lives *inside* a zip, so it needs SSRF and
    archive-safety machinery this module deliberately does not have. See
    ``project/tech-design/design-package-audits.md`` §Other package formats.
    """

    NPM = "npm"
    PYPI = "pypi"


class PackageOutcome(StrEnum):
    """How a metadata fetch ended.

    ``NOT_FOUND`` and ``VERSION_NOT_FOUND`` are findings about the package;
    ``ERROR`` is a finding about the fetch and must not be scored as though the
    package were at fault.
    """

    OK = "ok"
    NOT_FOUND = "not-found"
    VERSION_NOT_FOUND = "version-not-found"
    ERROR = "error"


# npm names: optional @scope/, then a URL-safe name. Deliberately permissive —
# the registry is the authority on whether a name exists, so this only rejects
# inputs that could not address a package at all (path traversal, whitespace).
_NPM_NAME = re.compile(r"^(?:@[^/@\s]+/)?[^/@\s]+$")
# PEP 508 project names.
_PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")


class InvalidCoordinateError(ValueError):
    """The package coordinate could not be parsed into a registry + name."""


@dataclass(frozen=True)
class PackageCoordinate:
    """A package identified well enough to look up, but never to execute.

    This is the shape the web service would accept instead of a command: it
    names something published to a public registry, and cannot express
    ``curl … | sh``. See the design doc for why the CLI's arbitrary-command
    decision does not transfer to a public web surface.
    """

    registry: PackageRegistry
    identifier: str
    version: str | None = None

    @classmethod
    def parse(cls, raw: str) -> PackageCoordinate:
        """Parse ``npm:<name>[@<version>]`` or ``pypi:<name>[==<version>]``.

        The separator is the one each ecosystem already uses, so a coordinate
        can be copied from an install command. npm scopes keep their leading
        ``@`` (``npm:@scope/name@1.2.3``): only an ``@`` after the first
        character separates a version.

        Args:
            raw: The coordinate string.

        Returns:
            The parsed coordinate.

        Raises:
            InvalidCoordinateError: If the registry prefix is missing or
                unknown, or the name is unusable.

        """
        text = raw.strip()
        prefix, separator, remainder = text.partition(":")
        if not separator:
            raise InvalidCoordinateError(f"Missing registry prefix in {raw!r} — expected 'npm:<name>' or 'pypi:<name>'")
        try:
            registry = PackageRegistry(prefix.strip().lower())
        except ValueError:
            supported = ", ".join(sorted(r.value for r in PackageRegistry))
            raise InvalidCoordinateError(f"Unsupported package registry {prefix!r} — supported: {supported}") from None

        remainder = remainder.strip()
        if not remainder:
            raise InvalidCoordinateError(f"Missing package name in {raw!r}")

        if registry is PackageRegistry.NPM:
            # rpartition, not partition: a scope's leading @ is part of the name.
            name, sep, version = remainder.rpartition("@")
            if not sep or not name:  # no version, or the @ was the scope marker
                name, version = remainder, ""
            pattern = _NPM_NAME
        else:
            name, sep, version = remainder.partition("==")
            pattern = _PYPI_NAME

        name, version = name.strip(), version.strip()
        if not pattern.match(name):
            raise InvalidCoordinateError(f"{registry.value} package name {name!r} is not a usable package name")
        return cls(registry=registry, identifier=name, version=version or None)

    @property
    def display(self) -> str:
        """Return the canonical coordinate string (used as the report target)."""
        if self.version is None:
            return f"{self.registry.value}:{self.identifier}"
        joiner = "@" if self.registry is PackageRegistry.NPM else "=="
        return f"{self.registry.value}:{self.identifier}{joiner}{self.version}"


@dataclass
class PackageMetadata:
    """What a package registry says about a package. Purely declared, never run.

    Every field is optional because every field is something a publisher can
    omit — and omitting them is exactly what the rules judge.
    """

    coordinate: PackageCoordinate
    outcome: PackageOutcome
    resolved_version: str | None = None
    """The version the rules judged: the requested one, or the registry's
    latest when the coordinate named none."""
    description: str | None = None
    license: str | None = None
    repository_url: str | None = None
    homepage_url: str | None = None
    published_at: datetime | None = None
    """Publication time of the resolved version, when the registry reports one."""
    yanked: bool = False
    """PyPI only: the release was withdrawn but is still resolvable."""
    available_versions: tuple[str, ...] = ()
    error: str | None = None
    """Exception name or HTTP status when ``outcome`` is ERROR — for the report,
    never a raw response body."""
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def describes_a_release(self) -> bool:
        """Whether the fields below describe a real release the rules can judge.

        Only ``OK`` qualifies. ``VERSION_NOT_FOUND`` deliberately does not: the
        package exists but the requested release does not, so every descriptive
        field is empty because nothing was fetched — not because the publisher
        omitted it. Treating that as "found" once made a missing version fail
        the license, repository and description rules for absent data.
        """
        return self.outcome is PackageOutcome.OK


def _first_url(*candidates: object) -> str | None:
    """Return the first candidate that looks like an http(s) URL."""
    for candidate in candidates:
        if isinstance(candidate, str):
            cleaned = candidate.strip()
            # npm writes git remotes as `git+https://…`, and `git://…` for old
            # packages. Normalize the browsable form; a bare `git://` URL is
            # still a declared repository.
            for prefix in ("git+", "git+ssh://git@", "ssh://git@"):
                cleaned = cleaned.removeprefix(prefix)
            if cleaned.startswith(("https://", "http://", "git://")):
                return cleaned.removesuffix(".git")
    return None


def _parse_timestamp(value: object) -> datetime | None:
    """Parse an ISO-8601 registry timestamp. Both registries send a trailing Z."""
    if not isinstance(value, str) or not value:
        return None
    try:
        # fromisoformat handles the trailing Z natively on Python 3.11+, which
        # is this package's floor — no pre-substitution needed.
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        return parsed
    # Both registries send a zone in practice, but a naive value must be read as
    # UTC rather than as the auditor's local time — otherwise published_at would
    # shift by the offset of whoever ran the audit.
    return parsed.replace(tzinfo=UTC)


def _npm_metadata(coordinate: PackageCoordinate, document: dict[str, Any]) -> PackageMetadata:
    """Build metadata from an npm packument."""
    versions = document.get("versions")
    available = tuple(versions) if isinstance(versions, dict) else ()
    latest = None
    dist_tags = document.get("dist-tags")
    if isinstance(dist_tags, dict):
        latest = dist_tags.get("latest")

    requested = coordinate.version
    resolved = requested or (latest if isinstance(latest, str) else None)
    if requested is not None and requested not in available:
        return PackageMetadata(
            coordinate=coordinate,
            outcome=PackageOutcome.VERSION_NOT_FOUND,
            resolved_version=None,
            available_versions=available,
        )

    # Version-specific fields override the packument-level ones: the top level
    # describes the latest release, which is not necessarily the one requested.
    entry = versions.get(resolved) if isinstance(versions, dict) and isinstance(resolved, str) else None
    entry = entry if isinstance(entry, dict) else {}

    repository = entry.get("repository") or document.get("repository")
    repository_url = None
    if isinstance(repository, dict):
        repository_url = _first_url(repository.get("url"))
    elif isinstance(repository, str):
        repository_url = _first_url(repository)

    times = document.get("time")
    published = _parse_timestamp(times.get(resolved)) if isinstance(times, dict) and resolved else None

    license_value = entry.get("license") or document.get("license")
    if isinstance(license_value, dict):  # legacy npm shape: {"type": "MIT", …}
        license_value = license_value.get("type")

    return PackageMetadata(
        coordinate=coordinate,
        outcome=PackageOutcome.OK,
        resolved_version=resolved,
        description=_clean_text(entry.get("description") or document.get("description")),
        license=_clean_text(license_value),
        repository_url=repository_url,
        homepage_url=_first_url(entry.get("homepage"), document.get("homepage")),
        published_at=published,
        # npm's equivalent of a PyPI yank: `npm deprecate` stamps the version
        # entry with a message. Its presence is the signal, whatever it says.
        yanked="deprecated" in entry,
        available_versions=available,
    )


def _pypi_metadata(coordinate: PackageCoordinate, document: dict[str, Any]) -> PackageMetadata:
    """Build metadata from a PyPI JSON API document."""
    info = document.get("info")
    info = info if isinstance(info, dict) else {}

    project_urls = info.get("project_urls")
    project_urls = project_urls if isinstance(project_urls, dict) else {}
    # PyPI has no dedicated repository field; publishers put it in project_urls
    # under names that are conventional, not standardized.
    repository_url = _first_url(
        *(project_urls.get(key) for key in ("Source", "Source Code", "Repository", "Homepage", "Code", "GitHub"))
    )

    published = None
    urls = document.get("urls")
    if isinstance(urls, list):
        stamps = [_parse_timestamp(u.get("upload_time_iso_8601")) for u in urls if isinstance(u, dict)]
        stamps = [s for s in stamps if s is not None]
        published = min(stamps) if stamps else None

    releases = document.get("releases")
    available = tuple(releases) if isinstance(releases, dict) else ()

    # Modern metadata (PEP 639) puts the SPDX expression in license_expression
    # and leaves the legacy `license` free-text field empty.
    license_value = info.get("license_expression") or info.get("license")

    return PackageMetadata(
        coordinate=coordinate,
        outcome=PackageOutcome.OK,
        resolved_version=_clean_text(info.get("version")) or coordinate.version,
        description=_clean_text(info.get("summary")),
        license=_clean_text(license_value),
        repository_url=repository_url,
        homepage_url=_first_url(info.get("home_page"), project_urls.get("Homepage"), info.get("project_url")),
        published_at=published,
        yanked=info.get("yanked") is True,
        available_versions=available,
    )


def _clean_text(value: object) -> str | None:
    """Return a stripped non-empty string, or None."""
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


def _metadata_url(coordinate: PackageCoordinate) -> str:
    """Build the registry metadata URL for a coordinate.

    ``quote`` with no safe characters percent-encodes the ``/`` in an npm scope,
    which the registry requires, and neutralizes any path traversal a name might
    smuggle in.
    """
    if coordinate.registry is PackageRegistry.NPM:
        return f"{NPM_REGISTRY}/{quote(coordinate.identifier, safe='')}"
    name = quote(coordinate.identifier, safe="")
    if coordinate.version is not None:
        return f"{PYPI_REGISTRY}/pypi/{name}/{quote(coordinate.version, safe='')}/json"
    return f"{PYPI_REGISTRY}/pypi/{name}/json"


async def fetch_package_metadata(
    coordinate: PackageCoordinate,
    client: httpx2.AsyncClient | None = None,
) -> PackageMetadata:
    """Fetch a package's registry metadata. Never raises; failures are data.

    Only a metadata document is requested — no tarball, no wheel, no install.
    No credential is ever sent: these are public documents, and a package audit
    must be reproducible by anyone.

    Args:
        coordinate: The package to look up.
        client: An existing HTTP client to reuse; one is created when omitted.

    Returns:
        Metadata whose ``outcome`` says whether the lookup succeeded, the
        package was absent, the requested version was absent, or the fetch
        itself failed.

    """
    if client is not None:
        return await _fetch(coordinate, client)
    async with httpx2.AsyncClient(follow_redirects=True) as owned:
        return await _fetch(coordinate, owned)


async def _fetch(coordinate: PackageCoordinate, client: httpx2.AsyncClient) -> PackageMetadata:
    url = _metadata_url(coordinate)
    request = client.build_request("GET", url, headers={"Accept": "application/json"}, timeout=FETCH_TIMEOUT_S)
    # These are public documents on a third-party host; a caller credential
    # meant for the audited server must never leak to a package registry.
    request.headers.pop("Authorization", None)
    try:
        response = await client.send(request)
    except (httpx2.HTTPError, httpx2.InvalidURL) as exc:
        logger.info("Could not reach %s for %s: %s", url, coordinate.display, type(exc).__name__)
        return PackageMetadata(coordinate=coordinate, outcome=PackageOutcome.ERROR, error=type(exc).__name__)

    if response.status_code == 404:
        # PyPI answers 404 for both an unknown project and an unknown version of
        # a known one; only a versioned request can mean the latter.
        outcome = (
            PackageOutcome.VERSION_NOT_FOUND
            if coordinate.registry is PackageRegistry.PYPI and coordinate.version is not None
            else PackageOutcome.NOT_FOUND
        )
        return PackageMetadata(coordinate=coordinate, outcome=outcome)
    if response.status_code != 200:
        return PackageMetadata(
            coordinate=coordinate,
            outcome=PackageOutcome.ERROR,
            error=f"HTTP {response.status_code}",
        )

    if len(response.content) > MAX_METADATA_BYTES:
        return PackageMetadata(
            coordinate=coordinate,
            outcome=PackageOutcome.ERROR,
            error=f"metadata larger than {MAX_METADATA_BYTES} bytes",
        )

    try:
        document = response.json()
    except ValueError:
        return PackageMetadata(coordinate=coordinate, outcome=PackageOutcome.ERROR, error="malformed JSON")
    if not isinstance(document, dict):
        return PackageMetadata(coordinate=coordinate, outcome=PackageOutcome.ERROR, error="metadata is not an object")

    if coordinate.registry is PackageRegistry.NPM:
        return _npm_metadata(coordinate, document)
    return _pypi_metadata(coordinate, document)
