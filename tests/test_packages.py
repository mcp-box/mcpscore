"""Tests for package-coordinate parsing and registry metadata fetching.

Every HTTP interaction runs on an httpx MockTransport: these tests must never
touch registry.npmjs.org or pypi.org (a suite that reaches the network is one
that fails in someone else's CI, and slowly).

The fixtures are trimmed copies of documents the real registries served on
2026-08-15, keeping the shapes that actually caused decisions — PyPI's empty
``license`` beside a populated ``license_expression``, npm's ``git+https``
repository URL, and npm's version-specific fields shadowing packument-level ones.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx2
import pytest

from mcpscore.packages import (
    MAX_METADATA_BYTES,
    InvalidCoordinateError,
    PackageCoordinate,
    PackageOutcome,
    PackageRegistry,
    fetch_package_metadata,
)

NPM_PACKUMENT: dict[str, Any] = {
    "name": "@scope/server",
    "description": "packument-level description",
    "dist-tags": {"latest": "2.0.0"},
    "license": "Apache-2.0",
    # npm writes git remotes with a scheme prefix and a .git suffix.
    "repository": {"type": "git", "url": "git+https://github.com/example/server.git"},
    "homepage": "https://example.com/server",
    "time": {
        "created": "2024-01-01T00:00:00.000Z",
        "modified": "2026-08-01T00:00:00.000Z",
        "1.0.0": "2024-01-01T00:00:00.000Z",
        "2.0.0": "2026-08-01T00:00:00.000Z",
    },
    "versions": {
        "1.0.0": {"description": "the old one", "license": "MIT"},
        "2.0.0": {"description": "version-level description"},
    },
}

PYPI_DOCUMENT: dict[str, Any] = {
    "info": {
        "name": "example-server",
        "version": "1.6.0",
        "summary": "An example MCP server",
        # PEP 639: the SPDX expression lives here and `license` stays empty.
        "license": None,
        "license_expression": "MIT",
        "home_page": None,
        "project_urls": {"Source": "https://github.com/example/py-server"},
        "yanked": False,
    },
    "releases": {"1.5.0": [], "1.6.0": []},
    "urls": [{"upload_time_iso_8601": "2026-08-13T20:14:58.123404Z"}],
}


def _client(handler) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(transport=httpx2.MockTransport(handler))


def _json_handler(payload: object, status: int = 200):
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status, json=payload)

    return handler


class TestCoordinateParsing:
    @pytest.mark.parametrize(
        ("raw", "registry", "identifier", "version"),
        [
            ("npm:server", PackageRegistry.NPM, "server", None),
            ("npm:server@1.2.3", PackageRegistry.NPM, "server", "1.2.3"),
            # The scope's leading @ must not be read as a version separator.
            ("npm:@scope/server", PackageRegistry.NPM, "@scope/server", None),
            ("npm:@scope/server@1.2.3", PackageRegistry.NPM, "@scope/server", "1.2.3"),
            ("pypi:example-server", PackageRegistry.PYPI, "example-server", None),
            ("pypi:example-server==1.6.0", PackageRegistry.PYPI, "example-server", "1.6.0"),
            ("  NPM:server  ", PackageRegistry.NPM, "server", None),
        ],
    )
    def test_parses_supported_forms(self, raw, registry, identifier, version):
        coordinate = PackageCoordinate.parse(raw)

        assert coordinate.registry is registry
        assert coordinate.identifier == identifier
        assert coordinate.version == version

    @pytest.mark.parametrize(
        "raw",
        [
            "server",  # no registry prefix
            "cargo:server",  # unsupported registry
            "npm:",  # no name
            "npm:   ",
            "npm:../../etc/passwd",  # path traversal
            "pypi:has spaces",
            # A separator with nothing after it asked for a version; auditing
            # the latest release instead would answer a different question.
            "npm:server@",
            "npm:@scope/server@",
            "pypi:server==",
            "oci:ghcr.io/example/server",  # deliberately unsupported
        ],
    )
    def test_rejects_unusable_coordinates(self, raw):
        with pytest.raises(InvalidCoordinateError):
            PackageCoordinate.parse(raw)

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("npm:@scope/server@1.2.3", "npm:@scope/server@1.2.3"),
            ("npm:@scope/server", "npm:@scope/server"),
            ("pypi:example==1.6.0", "pypi:example==1.6.0"),
            ("pypi:example", "pypi:example"),
        ],
    )
    def test_display_round_trips(self, raw, expected):
        assert PackageCoordinate.parse(raw).display == expected


class TestNpmMetadata:
    async def test_reads_latest_when_no_version_pinned(self):
        async with _client(_json_handler(NPM_PACKUMENT)) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:@scope/server"), client)

        assert meta.outcome is PackageOutcome.OK
        assert meta.resolved_version == "2.0.0"
        # Version-level fields shadow packument-level ones.
        assert meta.description == "version-level description"
        # ...but fall back to the packument when the version omits them.
        assert meta.license == "Apache-2.0"
        assert meta.repository_url == "https://github.com/example/server"
        assert meta.published_at == datetime(2026, 8, 1, tzinfo=UTC)

    async def test_pinned_version_uses_that_versions_fields(self):
        async with _client(_json_handler(NPM_PACKUMENT)) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:@scope/server@1.0.0"), client)

        assert meta.resolved_version == "1.0.0"
        assert meta.description == "the old one"
        assert meta.license == "MIT"
        assert meta.published_at == datetime(2024, 1, 1, tzinfo=UTC)

    async def test_unknown_version_is_reported_without_describing_a_release(self):
        async with _client(_json_handler(NPM_PACKUMENT)) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:@scope/server@9.9.9"), client)

        assert meta.outcome is PackageOutcome.VERSION_NOT_FOUND
        # The regression this pins: a missing version must not present itself as
        # a release with no license/repository/description, which would fail
        # those rules for data that was never fetched.
        assert meta.describes_a_release is False
        assert meta.license is None

    async def test_deprecated_version_is_withdrawn(self):
        document = {**NPM_PACKUMENT, "versions": {"2.0.0": {"deprecated": "use @scope/server-next"}}}
        async with _client(_json_handler(document)) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:@scope/server"), client)

        assert meta.yanked is True

    async def test_scoped_name_is_percent_encoded_in_the_request(self):
        seen: list[str] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            seen.append(str(request.url))
            return httpx2.Response(200, json=NPM_PACKUMENT)

        async with _client(handler) as client:
            await fetch_package_metadata(PackageCoordinate.parse("npm:@scope/server"), client)

        # The registry needs the slash encoded; leaving it raw would address a
        # different path entirely.
        assert seen == ["https://registry.npmjs.org/%40scope%2Fserver"]

    @pytest.mark.parametrize(
        ("declared", "expected"),
        [
            ("git+https://github.com/example/server.git", "https://github.com/example/server"),
            # SSH remotes are declared repositories too. Stripping their scheme
            # left a bare `host/path` that failed the URL check, scoring these
            # packages as having no source at all.
            ("git+ssh://git@github.com/example/server.git", "https://github.com/example/server"),
            ("ssh://git@github.com/example/server.git", "https://github.com/example/server"),
            ("ssh://git@gitlab.com:2222/example/server.git", "https://gitlab.com/example/server"),
            ("git@github.com:example/server.git", "https://github.com/example/server"),
            ("git://github.com/example/server.git", "git://github.com/example/server"),
            ("https://github.com/example/server", "https://github.com/example/server"),
        ],
    )
    async def test_repository_remote_forms_are_all_recognized(self, declared, expected):
        document = {**NPM_PACKUMENT, "repository": {"type": "git", "url": declared}}
        async with _client(_json_handler(document)) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:@scope/server"), client)

        assert meta.repository_url == expected

    @pytest.mark.parametrize(
        "declared",
        [
            "",  # present but empty
            "   ",
            "not-a-url-at-all",
            "mailto:maintainer@example.com",
        ],
    )
    async def test_unusable_repository_values_score_as_absent(self, declared):
        document = {**NPM_PACKUMENT, "repository": {"type": "git", "url": declared}, "homepage": None}
        async with _client(_json_handler(document)) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:@scope/server"), client)

        assert meta.repository_url is None

    async def test_legacy_object_license_shape_is_read(self):
        document = {**NPM_PACKUMENT, "versions": {"2.0.0": {"license": {"type": "BSD-3-Clause"}}}}
        async with _client(_json_handler(document)) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:@scope/server"), client)

        assert meta.license == "BSD-3-Clause"


class TestTolerantParsing:
    """Publisher-supplied metadata is untrusted input; malformed shapes must not raise."""

    @pytest.mark.parametrize(
        "time_value",
        [
            {"2.0.0": "not-a-timestamp"},  # unparsable
            {"2.0.0": None},  # not a string
            {},  # version absent from the time table
            "not-a-mapping",
        ],
    )
    async def test_unusable_publication_times_are_dropped_not_raised(self, time_value):
        document = {**NPM_PACKUMENT, "time": time_value}
        async with _client(_json_handler(document)) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:@scope/server"), client)

        assert meta.outcome is PackageOutcome.OK
        assert meta.published_at is None

    async def test_naive_timestamp_is_read_as_utc(self):
        # Not as the auditor's local time, which would shift published_at by
        # whatever offset the machine running the audit happens to have.
        document = {**NPM_PACKUMENT, "time": {"2.0.0": "2026-08-01T00:00:00"}}
        async with _client(_json_handler(document)) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:@scope/server"), client)

        assert meta.published_at == datetime(2026, 8, 1, tzinfo=UTC)

    async def test_string_repository_shape_is_read(self):
        # npm allows a bare string shorthand instead of {"type", "url"}.
        document = {**NPM_PACKUMENT, "repository": "git://github.com/example/shorthand.git"}
        async with _client(_json_handler(document)) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:@scope/server"), client)

        assert meta.repository_url == "git://github.com/example/shorthand"

    async def test_pypi_document_missing_every_optional_section(self):
        async with _client(_json_handler({"info": {"name": "bare"}})) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("pypi:bare"), client)

        assert meta.outcome is PackageOutcome.OK
        assert (meta.published_at, meta.available_versions, meta.repository_url) == (None, (), None)

    async def test_npm_document_missing_every_optional_section(self):
        async with _client(_json_handler({"name": "bare"})) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:bare"), client)

        assert meta.outcome is PackageOutcome.OK
        assert meta.resolved_version is None
        assert meta.describes_a_release is True


class TestPyPiMetadata:
    async def test_reads_pep639_license_expression(self):
        async with _client(_json_handler(PYPI_DOCUMENT)) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("pypi:example-server"), client)

        assert meta.outcome is PackageOutcome.OK
        # `license` is None here; reading only that field would report an
        # MIT-licensed package as unlicensed.
        assert meta.license == "MIT"
        assert meta.repository_url == "https://github.com/example/py-server"
        assert meta.description == "An example MCP server"
        assert meta.published_at == datetime(2026, 8, 13, 20, 14, 58, 123404, tzinfo=UTC)

    async def test_yanked_release_is_withdrawn(self):
        document = {**PYPI_DOCUMENT, "info": {**PYPI_DOCUMENT["info"], "yanked": True}}
        async with _client(_json_handler(document)) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("pypi:example-server"), client)

        assert meta.yanked is True

    async def test_404_on_a_versioned_request_means_the_version_is_missing(self):
        async with _client(_json_handler(None, status=404)) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("pypi:example-server==9.9.9"), client)

        assert meta.outcome is PackageOutcome.VERSION_NOT_FOUND

    async def test_404_without_a_version_means_the_package_is_missing(self):
        async with _client(_json_handler(None, status=404)) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("pypi:example-server"), client)

        assert meta.outcome is PackageOutcome.NOT_FOUND
        assert meta.describes_a_release is False

    async def test_versioned_request_uses_the_versioned_endpoint(self):
        seen: list[str] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            seen.append(str(request.url))
            return httpx2.Response(200, json=PYPI_DOCUMENT)

        async with _client(handler) as client:
            await fetch_package_metadata(PackageCoordinate.parse("pypi:example-server==1.6.0"), client)

        assert seen == ["https://pypi.org/pypi/example-server/1.6.0/json"]


class TestFetchFailuresAreData:
    async def test_transport_error_is_an_error_outcome_not_an_exception(self):
        def handler(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("boom")

        async with _client(handler) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:server"), client)

        assert meta.outcome is PackageOutcome.ERROR
        assert meta.error == "ConnectError"

    async def test_server_error_status_is_an_error_outcome(self):
        async with _client(_json_handler({}, status=503)) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:server"), client)

        assert meta.outcome is PackageOutcome.ERROR
        assert meta.error == "HTTP 503"

    async def test_malformed_json_is_an_error_outcome(self):
        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(200, content=b"not json")

        async with _client(handler) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:server"), client)

        assert meta.outcome is PackageOutcome.ERROR
        assert meta.error == "malformed JSON"

    async def test_non_object_document_is_an_error_outcome(self):
        async with _client(_json_handler(["not", "an", "object"])) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:server"), client)

        assert meta.outcome is PackageOutcome.ERROR

    async def test_oversized_metadata_is_refused(self):
        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(200, content=b"x" * (MAX_METADATA_BYTES + 1))

        async with _client(handler) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:server"), client)

        assert meta.outcome is PackageOutcome.ERROR
        assert "larger than" in (meta.error or "")

    async def test_no_caller_credential_reaches_a_package_registry(self):
        """Three separate channels, all of which leaked before 2026-08-16.

        Popping Authorization off a `client.build_request` result looked
        sufficient and was not: `build_request` merges the client's default
        headers and cookies, and `client.send` re-applies the client's `auth`.
        A client carrying Basic auth put `Authorization` straight back on the
        wire. The fix is a bare Request plus `auth=None`; this test fails
        against the popping version.
        """
        seen: list[httpx2.Headers] = []

        def handler(request: httpx2.Request) -> httpx2.Response:
            seen.append(request.headers)
            return httpx2.Response(200, json=NPM_PACKUMENT)

        async with httpx2.AsyncClient(
            transport=httpx2.MockTransport(handler),
            headers={"Authorization": "Bearer sekret", "X-Api-Key": "also-secret"},
            auth=("user", "password"),
            cookies={"session": "sekret-cookie"},
        ) as client:
            await fetch_package_metadata(PackageCoordinate.parse("npm:server"), client)

        sent = {name.lower() for name in seen[0]}
        assert not sent & {"authorization", "cookie", "x-api-key"}
        # Only what the fetch itself needs.
        assert sent <= {"accept", "host"}

    async def test_oversized_body_is_refused_without_buffering_it_all(self):
        """The cap must stop the read, not judge it after the fact.

        `response.content` buffers and decompresses the whole body first, so a
        size check afterwards rejects a document the process already paid for.
        This handler yields far more than the cap in chunks and asserts we
        stopped early.
        """
        yielded = 0
        chunk = b"x" * 64 * 1024

        async def stream_body():
            nonlocal yielded
            for _ in range(200):  # 12.8 MB if fully consumed
                yielded += len(chunk)
                yield chunk

        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(200, content=stream_body())

        async with _client(handler) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:server"), client)

        assert meta.outcome is PackageOutcome.ERROR
        assert "larger than" in (meta.error or "")
        # Stopped near the cap rather than consuming all 12.8 MB.
        assert yielded <= MAX_METADATA_BYTES + len(chunk)

    async def test_declared_content_length_is_refused_before_reading(self):
        read = False

        async def stream_body():
            nonlocal read
            read = True
            yield b"{}"

        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(
                200,
                headers={"Content-Length": str(MAX_METADATA_BYTES + 1)},
                content=stream_body(),
            )

        async with _client(handler) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:server"), client)

        assert meta.outcome is PackageOutcome.ERROR
        assert read is False

    async def test_transport_error_midway_through_the_body_is_data(self):
        async def stream_body():
            yield b'{"name":'
            raise httpx2.ReadError("connection dropped")

        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(200, content=stream_body())

        async with _client(handler) as client:
            meta = await fetch_package_metadata(PackageCoordinate.parse("npm:server"), client)

        assert meta.outcome is PackageOutcome.ERROR
        assert meta.error == "ReadError"

    async def test_creates_its_own_client_when_none_is_given(self, monkeypatch):
        transport = httpx2.MockTransport(_json_handler(NPM_PACKUMENT))
        real_client = httpx2.AsyncClient

        def patched(**kwargs):
            kwargs.setdefault("transport", transport)
            return real_client(**kwargs)

        monkeypatch.setattr(httpx2, "AsyncClient", patched)

        meta = await fetch_package_metadata(PackageCoordinate.parse("npm:server"))

        assert meta.outcome is PackageOutcome.OK
