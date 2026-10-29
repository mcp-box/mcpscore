"""Collect Skills extension evidence (SEP-2640): helpers, the bounded collector, client calls and auditor wiring."""

import asyncio
import base64
import hashlib
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from mcp.shared.exceptions import MCPError
from mcp_types import Implementation, InitializeResult, ServerCapabilities, TextResourceContents
import pytest

from mcpscore import skills
from mcpscore.enums import MCPTransportType
from mcpscore.mcp_auditor import MCPAuditor
from mcpscore.mcp_client import ERROR_NO_ACTIVE_SESSION, MCPClient, RawResult
from mcpscore.skills import (
    SKILLS_EXTENSION,
    collect_skills,
    content_bytes,
    declared_settings,
    name_problems,
    parse_frontmatter,
    relative_references,
    resolve_reference,
    skill_path_name,
    skill_root,
    split_frontmatter,
)


def entry(name: str, files: dict[str, str] | None = None) -> dict[str, Any]:
    files = files if files is not None else {"SKILL.md": f"---\nname: {name}\ndescription: d\n---\n"}
    return {
        "uri": f"skill://{name}/SKILL.md",
        "frontmatter": {"name": name, "description": "d"},
        "resources": [
            {
                "uri": f"skill://{name}/{path}",
                "digest": "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
                "size": len(text.encode()),
            }
            for path, text in files.items()
        ],
    }


def _validation_error() -> Exception:
    from pydantic import BaseModel

    class Strict(BaseModel):
        value: int

    try:
        Strict.model_validate({"value": "x"})
    except Exception as exc:  # noqa: BLE001 — building a real ValidationError
        return exc
    raise AssertionError


class FakeSession:
    """Answer skills/list pages, skills/get and resources/read from canned data."""

    def __init__(
        self,
        pages: list[Any],
        files: dict[str, str] | None = None,
        *,
        get: Any = None,
        errors: dict[str, Exception] | None = None,
        directories: dict[str, Any] | None = None,
    ) -> None:
        self.pages = pages
        self.files = files or {}
        self.get = get
        self.directories = directories or {}
        self.errors = errors or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.reads: list[str] = []

    async def request_raw(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((method, params))
        key = f"{method}:{params.get('cursor') or params.get('uri') or ''}"
        if key in self.errors:
            raise self.errors[key]
        if method == "skills/get":
            return self.get if self.get is not None else {"skill": {"uri": params["uri"]}}
        if method == "resources/directory/read":
            return self.directories[f"{params['uri']}|{params.get('cursor', '')}"]
        index = int(params["cursor"]) if "cursor" in params else 0
        return self.pages[index]

    async def read_resource_contents(self, uri: str) -> list[dict[str, Any]]:
        self.reads.append(uri)
        if f"read:{uri}" in self.errors:
            raise self.errors[f"read:{uri}"]
        if uri not in self.files:
            return []
        return [{"uri": uri, "mimeType": "text/markdown", "text": self.files[uri]}]


class TestHelpers:
    def test_declared_settings(self):
        caps = ServerCapabilities.model_validate({"extensions": {SKILLS_EXTENSION: {"directoryRead": True}}})
        assert declared_settings(caps) == {"directoryRead": True}
        assert declared_settings(ServerCapabilities()) is None
        assert declared_settings(None) is None
        odd = MagicMock(extensions={SKILLS_EXTENSION: "yes"})
        assert declared_settings(odd) == {}

    @pytest.mark.parametrize(
        ("uri", "root", "name"),
        [
            ("skill://git-workflow/SKILL.md", "skill://git-workflow", "git-workflow"),
            ("skill://acme/billing/refunds/SKILL.md", "skill://acme/billing/refunds", "refunds"),
            ("github://o/r/skills/refunds/SKILL.md", "github://o/r/skills/refunds", "refunds"),
            ("skill://acme/%E6%95%B0%E6%8D%AE/SKILL.md", "skill://acme/%E6%95%B0%E6%8D%AE", "数据"),
            ("skill://acme/a%2Fb/SKILL.md", "skill://acme/a%2Fb", "a/b"),
            ("skill://x/README.md", None, None),
            ("skill://foo?ignored/SKILL.md", "skill://foo?ignored", None),
            ("skill://foo#ignored/SKILL.md", "skill://foo#ignored", None),
            ("/SKILL.md", None, None),
            ("no-scheme/SKILL.md", "no-scheme", None),
        ],
    )
    def test_skill_paths(self, uri: str, root: str | None, name: str | None):
        assert skill_root(uri) == root
        assert skill_path_name(uri) == name

    @pytest.mark.parametrize(
        ("name", "problems"),
        [
            ("pdf-processing", []),
            ("a" * 64, []),
            ("café", []),
            ("数据分析", []),
            ("", ["length"]),
            ("PDF", ["uppercase"]),
            ("a--b", ["hyphens"]),
            ("a_b", ["characters"]),
        ],
    )
    def test_name_problems(self, name: str, problems: list[str]):
        assert name_problems(name) == problems

    def test_frontmatter_split_and_parse(self):
        assert split_frontmatter("---\na: 1\n---\nbody\n") == ("a: 1\n", "body\n")
        assert split_frontmatter("---\nnever closed\n") is None
        assert split_frontmatter("") is None
        assert parse_frontmatter("---\nname: x\nwhen: 2026-10-18\n---\n") == {"name": "x", "when": "2026-10-18"}
        with pytest.raises(ValueError, match="no frontmatter"):
            parse_frontmatter("body only")
        with pytest.raises(ValueError, match="invalid YAML"):
            parse_frontmatter("---\na: [\n---\n")

    def test_references(self):
        body = "[a](references/A.md) ![b](<assets/b c.png>) [c](https://x.y) [d](#top) [e](/abs) [f](g.md?x=1#h) [](#)"
        assert relative_references(body) == ["references/A.md", "assets/b%20c.png", "g.md"]
        assert resolve_reference("skill://s", "./references/../A.md") == "skill://s/A.md"
        assert resolve_reference("skill://s", "../other/SKILL.md") is None
        assert resolve_reference("skill://s", "..") is None

    def test_content_bytes(self):
        blob = base64.b64encode(b"\x00\x01").decode()
        assert content_bytes([{"uri": "u", "text": "é"}], "u") == ("é".encode(), None)
        assert content_bytes([{"uri": "x", "text": "no"}, {"uri": "u", "blob": blob, "mimeType": "m"}], "u") == (
            b"\x00\x01",
            "m",
        )
        assert content_bytes([], "u") is None
        assert content_bytes([{"uri": "u"}], "u") is None
        assert content_bytes([{"uri": "u", "blob": "!!not base64"}], "u") is None


class TestCollector:
    async def test_lists_gets_and_reads_a_sample(self):
        a = entry("a", {"SKILL.md": "---\nname: a\n---\n", "references/R.md": "r", "x.md": "x"})
        session = FakeSession(
            [{"skills": [a, entry("b")]}],
            {"skill://a/SKILL.md": "---\nname: a\n---\n", "skill://a/references/R.md": "r", "skill://b/SKILL.md": "b"},
        )
        evidence = await collect_skills(session, {"directoryRead": True})
        assert evidence.settings == {"directoryRead": True}
        assert [e["uri"] for e in evidence.entries or []] == ["skill://a/SKILL.md", "skill://b/SKILL.md"]
        assert [(got.uri, got.entry) for got in evidence.gets] == [
            ("skill://a/SKILL.md", {"uri": "skill://a/SKILL.md"}),
            ("skill://b/SKILL.md", {"uri": "skill://b/SKILL.md"}),
        ]
        assert evidence.unknown_get is not None
        assert evidence.unknown_get.uri == "skill://mcpscore-no-such-skill/SKILL.md"
        assert sorted(evidence.files) == ["skill://a/SKILL.md", "skill://a/references/R.md", "skill://b/SKILL.md"]
        skill_file = evidence.files["skill://a/SKILL.md"]
        assert skill_file.text == "---\nname: a\n---\n"
        assert skill_file.digest == a["resources"][0]["digest"]
        assert skill_file.size == a["resources"][0]["size"]
        assert evidence.files["skill://a/references/R.md"].text is None

    async def test_paginates_and_stops_on_a_repeated_cursor(self):
        session = FakeSession(
            [
                {"skills": [entry("a")], "nextCursor": "1"},
                {"skills": [entry("b")], "nextCursor": "1"},
            ]
        )
        evidence = await collect_skills(session, {})
        assert len(evidence.entries or []) == 2
        assert evidence.list_incomplete

    async def test_page_limit_marks_the_listing_incomplete(self, monkeypatch):
        monkeypatch.setattr(skills, "MAX_LIST_PAGES", 2)
        session = FakeSession([{"skills": [], "nextCursor": "1"}, {"skills": [], "nextCursor": "2"}])
        evidence = await collect_skills(session, {})
        assert evidence.entries == []
        assert evidence.list_incomplete

    @pytest.mark.parametrize(
        ("error", "expected"),
        [
            (MCPError(code=-32601, message="nope"), {"outcome": "rpc_error", "error_code": -32601}),
            (MCPError(code=-32001, message="slow"), {"outcome": "timeout"}),
            (TimeoutError(), {"outcome": "timeout"}),
            (RuntimeError("boom"), {"outcome": "transport", "exception": "RuntimeError"}),
            (_validation_error(), {"outcome": "malformed"}),
        ],
    )
    async def test_failed_listing_is_evidence(self, error: Exception, expected: dict[str, Any]):
        evidence = await collect_skills(FakeSession([], errors={"skills/list:": error}), {})
        assert evidence.entries is None
        assert evidence.list_error == expected
        assert evidence.gets == []
        assert evidence.files == {}

    async def test_failure_after_the_first_page_keeps_entries(self):
        session = FakeSession(
            [{"skills": [entry("a")], "nextCursor": "1"}],
            errors={"skills/list:1": MCPError(code=-32603, message="x")},
        )
        evidence = await collect_skills(session, {})
        assert len(evidence.entries or []) == 1
        assert evidence.list_incomplete
        assert evidence.list_error is None

    @pytest.mark.parametrize("result", [{}, {"skills": "x"}, ["not", "an", "object"]])
    async def test_malformed_listing(self, result: Any):
        evidence = await collect_skills(FakeSession([result]), {})
        assert evidence.list_malformed
        assert evidence.entries is None

    async def test_get_failure_and_odd_result(self):
        error = FakeSession([{"skills": [entry("a")]}], errors={"skills/get:skill://a/SKILL.md": MCPError(-32602, "x")})
        evidence = await collect_skills(error, {})
        assert evidence.gets[0].error == {"outcome": "rpc_error", "error_code": -32602}
        odd = await collect_skills(FakeSession([{"skills": [entry("a")]}], get={"other": 1}), {})
        assert odd.gets[0].entry is None

    async def test_gets_every_listed_skill_once_up_to_the_cap(self, monkeypatch):
        monkeypatch.setattr(skills, "MAX_SKILL_FILES", 2)
        same = entry("a")
        same["uri"] = "skill://a/%53KILL.md"
        session = FakeSession([{"skills": [entry("a"), same, entry("b"), entry("c")]}])
        evidence = await collect_skills(session, {})
        assert [got.uri for got in evidence.gets] == ["skill://a/SKILL.md", "skill://b/SKILL.md"]
        asked = [params["uri"] for method, params in session.calls if method == "skills/get"]
        assert asked == ["skill://a/SKILL.md", "skill://b/SKILL.md", "skill://mcpscore-no-such-skill/SKILL.md"]

    @pytest.mark.parametrize(
        ("listed", "unknown"),
        [
            ("skill://acme/billing/refunds/SKILL.md", "skill://acme/billing/mcpscore-no-such-skill/SKILL.md"),
            ("https://example.test/skills/a/SKILL.md", "https://example.test/skills/mcpscore-no-such-skill/SKILL.md"),
            ("not-a-skill-file", "skill://mcpscore-no-such-skill/SKILL.md"),
        ],
    )
    def test_unknown_skill_uri_sits_beside_a_listed_skill(self, listed: str, unknown: str):
        assert skills.unknown_skill_uri([{"uri": listed}]) == unknown

    def test_unknown_skill_uri_avoids_every_listed_skill(self, monkeypatch):
        monkeypatch.setattr(skills, "MAX_SKILL_FILES", 1)
        listed = [
            {"uri": "skill://acme/review/SKILL.md"},
            {"uri": "skill://acme/mcpscore-no-such-skill/SKILL.md"},
            {"uri": "skill://acme/mcpscore-no-such-skill-%32/SKILL.md"},
        ]
        assert skills.unknown_skill_uri(listed) == "skill://acme/mcpscore-no-such-skill-3/SKILL.md"

    async def test_unknown_directory_avoids_the_root_listing_and_the_manifest(self):
        root = "skill://a"
        a = entry("a")
        a["resources"].append({"uri": f"{root}/mcpscore-no-such-directory/GUIDE.md", "digest": "x", "size": 1})
        listing = {"resources": [{"uri": f"{root}/mcpscore-no-such-directory-2", "mimeType": "inode/directory"}]}
        session = FakeSession(
            [{"skills": [a]}],
            directories={f"{root}|": listing, f"{root}/mcpscore-no-such-directory-3|": {"resources": []}},
        )
        evidence = await collect_skills(session, {"directoryRead": True})
        assert evidence.directory_reads[1].uri == f"{root}/mcpscore-no-such-directory-3"

    async def test_truncated_root_listing_skips_the_unknown_directory_probe(self, monkeypatch):
        monkeypatch.setattr(skills, "MAX_LIST_PAGES", 1)
        root = "skill://a"
        session = FakeSession(
            [{"skills": [entry("a")]}], directories={f"{root}|": {"resources": [], "nextCursor": "1"}}
        )
        evidence = await collect_skills(session, {"directoryRead": True})
        assert [(read.kind, read.incomplete) for read in evidence.directory_reads] == [("skill_root", True)]

    async def test_malformed_later_directory_page_is_recorded(self):
        root = "skill://a"
        first = {"resources": [{"uri": f"{root}/SKILL.md", "name": "SKILL.md"}], "nextCursor": "1"}
        session = FakeSession([{"skills": [entry("a")]}], directories={f"{root}|": first, f"{root}|1": {"items": []}})
        (root_read,) = (await collect_skills(session, {"directoryRead": True})).directory_reads
        assert (root_read.error, root_read.incomplete, len(root_read.resources or [])) == (
            {"outcome": "malformed"},
            True,
            1,
        )

    @pytest.mark.parametrize("error", [MCPError(code=-32001, message="slow"), RuntimeError("gone")])
    async def test_unknown_directory_needs_a_whole_root_listing(self, error: Exception):
        root = "skill://a"
        session = FakeSession([{"skills": [entry("a")]}], errors={f"resources/directory/read:{root}": error})
        reads = (await collect_skills(session, {"directoryRead": True})).directory_reads
        assert [read.kind for read in reads] == ["skill_root"]

    async def test_negative_directory_probes_judge_their_first_answer(self):
        root = "skill://a"
        listing = {"resources": [{"uri": f"{root}/SKILL.md", "name": "SKILL.md"}]}
        answered = {"resources": [], "nextCursor": "1"}
        session = FakeSession(
            [{"skills": [entry("a")]}],
            errors={"resources/directory/read:1": MCPError(-32602, "bad cursor")},
            directories={
                f"{root}|": listing,
                f"{root}/mcpscore-no-such-directory|": answered,
                f"{root}/SKILL.md|": answered,
            },
        )
        _, unknown, file = (await collect_skills(session, {"directoryRead": True})).directory_reads
        assert (unknown.error, unknown.resources) == (None, [])
        assert (file.error, file.resources) == (None, [])

    async def test_cursor_that_is_not_a_string(self):
        root = "skill://a"
        listing = {"resources": [{"uri": f"{root}/SKILL.md", "name": "SKILL.md"}], "nextCursor": 7}
        session = FakeSession([{"skills": [entry("a")], "nextCursor": 7}], directories={f"{root}|": listing})
        evidence = await collect_skills(session, {"directoryRead": True})
        assert evidence.list_incomplete
        (root_read,) = evidence.directory_reads
        assert (root_read.error, root_read.incomplete, len(root_read.resources or [])) == (
            {"outcome": "malformed"},
            True,
            1,
        )

    async def test_directory_reads_only_when_declared(self):
        root = "skill://a"
        directories = {
            f"{root}|": {"resources": [{"uri": f"{root}/SKILL.md"}], "nextCursor": "1"},
            f"{root}|1": {"resources": [{"uri": f"{root}/refs", "mimeType": "inode/directory"}]},
        }
        errors = {
            f"resources/directory/read:{root}/mcpscore-no-such-directory": MCPError(-32602, "unknown"),
            f"resources/directory/read:{root}/SKILL.md": MCPError(-32602, "not a directory"),
        }
        session = FakeSession([{"skills": [entry("a")]}], errors=errors, directories=directories)
        assert (await collect_skills(session, {})).directory_reads == []
        evidence = await collect_skills(session, {"directoryRead": True})
        root_read, unknown, file = evidence.directory_reads
        assert (root_read.kind, root_read.incomplete) == ("skill_root", False)
        assert [child["uri"] for child in root_read.resources or []] == [f"{root}/SKILL.md", f"{root}/refs"]
        assert unknown.error == file.error == {"outcome": "rpc_error", "error_code": -32602}

    async def test_directory_read_failures_and_odd_pages(self):
        root = "skill://a"
        later_failure = FakeSession(
            [{"skills": [entry("a")]}],
            errors={"resources/directory/read:1": MCPError(-32603, "x")},
            directories={f"{root}|": {"resources": [{"uri": f"{root}/SKILL.md"}], "nextCursor": "1"}},
        )
        root_read = (await collect_skills(later_failure, {"directoryRead": True})).directory_reads[0]
        assert (len(root_read.resources or []), root_read.incomplete) == (1, True)
        assert root_read.error == {"outcome": "rpc_error", "error_code": -32603}
        later_timeout = FakeSession(
            [{"skills": [entry("a")]}],
            errors={"resources/directory/read:1": TimeoutError()},
            directories={f"{root}|": {"resources": [{"uri": f"{root}/SKILL.md"}], "nextCursor": "1"}},
        )
        root_read = (await collect_skills(later_timeout, {"directoryRead": True})).directory_reads[0]
        assert (len(root_read.resources or []), root_read.incomplete, root_read.error) == (1, True, None)
        odd = FakeSession(
            [{"skills": [entry("a")]}],
            directories={f"{root}|": {"resources": [], "nextCursor": "1"}, f"{root}|1": {"items": []}},
        )
        root_read = (await collect_skills(odd, {"directoryRead": True})).directory_reads[0]
        assert (root_read.resources, root_read.incomplete) == ([], True)
        malformed = FakeSession([{"skills": [entry("a")]}], directories={f"{root}|": ["no", "object"]})
        assert (await collect_skills(malformed, {"directoryRead": True})).directory_reads[0].resources is None

    async def test_directory_read_page_limit_and_repeated_cursor(self, monkeypatch):
        monkeypatch.setattr(skills, "MAX_LIST_PAGES", 2)
        root = "skill://a"
        looping = FakeSession(
            [{"skills": [entry("a")]}],
            directories={
                f"{root}|": {"resources": [], "nextCursor": "1"},
                f"{root}|1": {"resources": [], "nextCursor": "1"},
            },
        )
        assert (await collect_skills(looping, {"directoryRead": True})).directory_reads[0].incomplete
        endless = FakeSession(
            [{"skills": [entry("a")]}],
            directories={
                f"{root}|": {"resources": [], "nextCursor": "1"},
                f"{root}|1": {"resources": [], "nextCursor": "2"},
            },
        )
        assert (await collect_skills(endless, {"directoryRead": True})).directory_reads[0].incomplete

    async def test_no_directory_reads_without_a_skill_root(self):
        session = FakeSession([{"skills": [{"uri": "skill://a/README.md"}]}])
        assert (await collect_skills(session, {"directoryRead": True})).directory_reads == []

    async def test_entries_without_uris_are_not_requested(self):
        session = FakeSession([{"skills": ["junk", {"frontmatter": {}}]}])
        evidence = await collect_skills(session, {})
        assert evidence.gets == []
        assert session.reads == []

    async def test_read_errors_and_empty_contents(self):
        session = FakeSession(
            [{"skills": [entry("a"), entry("b")]}],
            errors={"read:skill://a/SKILL.md": MCPError(code=-32602, message="gone")},
        )
        evidence = await collect_skills(session, {})
        assert evidence.files["skill://a/SKILL.md"].error == "rpc_error"
        assert evidence.files["skill://a/SKILL.md"].error_code == -32602
        assert evidence.files["skill://b/SKILL.md"].error == "empty"

    async def test_byte_budget_skips_large_files(self, monkeypatch):
        big = entry("big", {"SKILL.md": "s", "large.bin": "x" * 50})
        monkeypatch.setattr(skills, "MAX_FILE_BYTES", 10)
        session = FakeSession([{"skills": [big]}], {"skill://big/SKILL.md": "s"})
        evidence = await collect_skills(session, {})
        assert "skill://big/large.bin" not in session.reads
        assert list(evidence.files) == ["skill://big/SKILL.md"]
        monkeypatch.setattr(skills, "MAX_TOTAL_BYTES", 0)
        exhausted = await collect_skills(FakeSession([{"skills": [big]}]), {})
        assert exhausted.budget_exhausted
        assert exhausted.files == {}

    async def test_file_count_caps(self, monkeypatch):
        monkeypatch.setattr(skills, "MAX_SKILL_FILES", 1)
        monkeypatch.setattr(skills, "MAX_SUPPORTING_FILES", 1)
        listed = [entry(n, {"SKILL.md": n, "a.md": "a", "b.md": "b"}) for n in ("p", "q")]
        session = FakeSession([{"skills": listed}])
        await collect_skills(session, {})
        assert sorted(session.reads) == ["skill://p/SKILL.md", "skill://p/a.md"]

    async def test_dynamic_skills_read_only_skill_md(self):
        dynamic = {**entry("d"), "resources": "dynamic"}
        session = FakeSession([{"skills": [dynamic]}])
        await collect_skills(session, {})
        assert session.reads == ["skill://d/SKILL.md"]

    async def test_timeout_keeps_reads_already_made(self, monkeypatch):
        monkeypatch.setattr(skills, "COLLECTION_TIMEOUT_S", 0.2)
        monkeypatch.setattr(skills, "READ_CONCURRENCY", 1)

        class Slow(FakeSession):
            async def read_resource_contents(self, uri: str) -> list[dict[str, Any]]:
                if uri.endswith("b/SKILL.md"):
                    await asyncio.sleep(5)
                return await super().read_resource_contents(uri)

        session = Slow([{"skills": [entry("a"), entry("b")]}], {"skill://a/SKILL.md": "a"})
        evidence = await collect_skills(session, {})
        assert evidence.budget_exhausted
        assert list(evidence.files) == ["skill://a/SKILL.md"]


class TestClientCalls:
    async def test_no_session(self):
        client = MCPClient()
        with pytest.raises(RuntimeError, match=ERROR_NO_ACTIVE_SESSION):
            await client.request_raw("skills/list", {})
        with pytest.raises(RuntimeError, match=ERROR_NO_ACTIVE_SESSION):
            await client.read_resource_contents("skill://a/SKILL.md")

    async def test_raw_request_keeps_params_and_result_fields(self):
        client = MCPClient()
        client.session = AsyncMock()
        client.session.send_request.return_value = RawResult(skills=[{"uri": "u"}], nextCursor="c")
        result = await client.request_raw("skills/get", {"uri": "skill://a/SKILL.md"})
        assert result == {"skills": [{"uri": "u"}], "nextCursor": "c"}
        request = client.session.send_request.await_args.args[0]
        assert request.model_dump(by_alias=True, mode="json") == {
            "method": "skills/get",
            "params": {"uri": "skill://a/SKILL.md"},
        }

    async def test_read_resource_contents_are_wire_shaped(self):
        client = MCPClient()
        client.session = AsyncMock()
        client.session.read_resource.return_value = MagicMock(
            contents=[TextResourceContents(uri="skill://a/SKILL.md", mime_type="text/markdown", text="t")]
        )
        assert await client.read_resource_contents("skill://a/SKILL.md") == [
            {"uri": "skill://a/SKILL.md", "mimeType": "text/markdown", "text": "t"}
        ]

    async def test_handshake_declares_the_skills_extension(self):
        client = MCPClient()
        session = AsyncMock()
        session.initialize.return_value = MagicMock()
        with (
            patch("mcpscore.mcp_client.streamable_http_client") as transport,
            patch("mcpscore.mcp_client.ClientSession", return_value=session) as constructor,
        ):
            transport.return_value.__aenter__.return_value = (AsyncMock(), AsyncMock(), MagicMock())
            session.__aenter__.return_value = session
            assert await client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, "https://example.com/mcp")
        assert constructor.call_args.kwargs["extensions"] == {SKILLS_EXTENSION: {}}


class SkillsClient(MCPClient):
    def __init__(self, capabilities: dict[str, Any], session: FakeSession) -> None:
        super().__init__()
        self._init_result = InitializeResult(
            protocol_version="2025-11-25",
            capabilities=ServerCapabilities.model_validate(capabilities),
            server_info=Implementation(name="s", version="1"),
        )
        self.fake = session
        self.transport_type = MCPTransportType.STREAMABLE_HTTP

    async def initialize(self):
        return self._init_result

    async def list_resources(self):
        return []

    async def list_resource_templates(self):
        return []

    async def request_raw(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return await self.fake.request_raw(method, params)

    async def read_resource_contents(self, uri: str) -> list[dict[str, Any]]:
        return await self.fake.read_resource_contents(uri)


class TestAuditorWiring:
    async def test_declared_extension_is_collected_and_scored(self):
        a = entry("a")
        session = FakeSession([{"skills": [a]}], {"skill://a/SKILL.md": "---\nname: a\ndescription: d\n---\n"})
        auditor = MCPAuditor()
        await auditor.audit(SkillsClient({"resources": {}, "extensions": {SKILLS_EXTENSION: {}}}, session))
        assert auditor.audit_data.skills is not None
        results = {r.rule_id: r for r in auditor.results}
        assert results["skills_digest_integrity"].passed
        assert results["skills_frontmatter_matches"].passed
        assert auditor.get_audit_report()["skills"]["skills_listed"] == 1

    async def test_undeclared_extension_is_not_collected(self):
        session = FakeSession([{"skills": []}])
        auditor = MCPAuditor()
        await auditor.audit(SkillsClient({"resources": {}}, session))
        assert auditor.audit_data.skills is None
        assert session.calls == []
        skipped = {s.rule_id: s.reason for s in auditor.skipped_rules}
        assert skipped["skills_list_supported"] == "not-applicable"
        assert auditor.get_audit_report()["skills"] is None


class TestRobustness:
    def test_yaml_aliases_and_deep_nesting_are_refused(self):
        bomb = "---\na: &a [x, x]\nb: &b [*a, *a]\nc: &c [*b, *b]\n---\n"
        with pytest.raises(ValueError, match="YAML aliases"):
            parse_frontmatter(bomb)
        deep = "---\nk: " + "[" * 40 + "]" * 40 + "\n---\n"
        with pytest.raises(ValueError, match="YAML nesting"):
            parse_frontmatter(deep)

    @pytest.mark.parametrize("text", ["---\n2026-10-18: release\n---\n", "---\n? [a, b]\n: x\n---\n"])
    def test_keys_json_cannot_hold_are_invalid_frontmatter(self, text: str):
        with pytest.raises(ValueError, match="invalid YAML"):
            parse_frontmatter(text)

    def test_malformed_authority_has_no_name(self):
        assert skill_path_name("skill://[/SKILL.md") is None

    def test_links_in_code_and_malformed_urls_are_not_references(self):
        body = (
            "Write links like `[label](example.md)`.\n\n"
            "```markdown\n[label](inside.md)\n```\n\n"
            "[bad](https://[invalid) and [real](real.md)\n"
        )
        assert relative_references(body) == ["real.md"]

    async def test_nested_skill_md_is_read_once_with_its_text(self):
        parent = entry("parent", {"SKILL.md": "p", "child/SKILL.md": "c"})
        child = {**entry("child"), "uri": "skill://parent/child/SKILL.md"}
        session = FakeSession(
            [{"skills": [parent, child]}],
            {"skill://parent/SKILL.md": "p", "skill://parent/child/SKILL.md": "---\nname: child\n---\n"},
        )
        evidence = await collect_skills(session, {})
        assert session.reads.count("skill://parent/child/SKILL.md") == 1
        assert evidence.files["skill://parent/child/SKILL.md"].text == "---\nname: child\n---\n"

    async def test_actual_bytes_are_bounded(self, monkeypatch):
        monkeypatch.setattr(skills, "MAX_FILE_BYTES", 8)
        monkeypatch.setattr(skills, "MAX_TOTAL_BYTES", 8)
        monkeypatch.setattr(skills, "READ_CONCURRENCY", 1)
        dynamic = [{**entry(n), "resources": "dynamic"} for n in ("a", "b")]
        session = FakeSession([{"skills": dynamic}], {"skill://a/SKILL.md": "x" * 9, "skill://b/SKILL.md": "y"})
        evidence = await collect_skills(session, {})
        oversized = evidence.files["skill://a/SKILL.md"]
        assert oversized.error == "too_large"
        assert oversized.text is None
        assert "skill://b/SKILL.md" not in evidence.files
        assert evidence.budget_exhausted

    @pytest.mark.parametrize("hang", ["skills/list", "skills/get"])
    async def test_deadline_records_the_interrupted_call_as_a_timeout(self, monkeypatch, hang: str):
        monkeypatch.setattr(skills, "COLLECTION_TIMEOUT_S", 0.2)

        class Hanging(FakeSession):
            async def request_raw(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
                if method == hang:
                    await asyncio.sleep(5)
                return await super().request_raw(method, params)

        evidence = await collect_skills(Hanging([{"skills": [entry("a")]}]), {})
        if hang == "skills/list":
            assert evidence.list_error == {"outcome": "timeout"}
            assert evidence.entries is None
        else:
            assert [(got.uri, got.error) for got in evidence.gets] == [("skill://a/SKILL.md", {"outcome": "timeout"})]
            assert evidence.unknown_get is None

    @pytest.mark.parametrize("hang_page", [0, 1])
    async def test_deadline_keeps_directory_pages_already_received(self, monkeypatch, hang_page: int):
        monkeypatch.setattr(skills, "COLLECTION_TIMEOUT_S", 0.2)
        root = "skill://a"

        class HangingPage(FakeSession):
            async def request_raw(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
                if method == "resources/directory/read" and params.get("cursor", "") == ("1" if hang_page else ""):
                    await asyncio.sleep(5)
                return await super().request_raw(method, params)

        first_page = {"resources": [{"uri": f"{root}/x/y.md", "name": "y.md"}], "nextCursor": "1"}
        session = HangingPage([{"skills": [entry("a")]}], directories={f"{root}|": first_page})
        evidence = await collect_skills(session, {"directoryRead": True})
        (read,) = evidence.directory_reads
        if hang_page:
            assert (read.error, read.incomplete, len(read.resources or [])) == (None, True, 1)
        else:
            assert (read.error, read.resources) == ({"outcome": "timeout"}, None)

    @pytest.mark.parametrize("stall", ["skills/get", "resources/directory/read"])
    async def test_stalled_calls_do_not_starve_file_reads(self, monkeypatch, stall: str):
        monkeypatch.setattr(skills, "COLLECTION_TIMEOUT_S", 0.3)

        class Stalling(FakeSession):
            async def request_raw(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
                if method == stall:
                    await asyncio.sleep(5)
                return await super().request_raw(method, params)

        session = Stalling(
            [{"skills": [entry("a")]}],
            {"skill://a/SKILL.md": "---\nname: a\ndescription: d\n---\n"},
            directories={"skill://a|": {"resources": [{"uri": "skill://a/SKILL.md", "name": "SKILL.md"}]}},
        )
        evidence = await collect_skills(session, {"directoryRead": True})
        assert evidence.budget_exhausted
        assert evidence.files["skill://a/SKILL.md"].text is not None

    def test_link_extraction_is_linear_on_unmatched_brackets(self):
        import time

        for attack in ["[" * 400_000, "[a](" * 100_000, '[a](b "' * 60_000, "`" + "a`" * 200_000]:
            started = time.perf_counter()
            relative_references(attack)
            assert time.perf_counter() - started < 1.0

    async def test_empty_cursor_continues_pagination(self):
        class Paged(FakeSession):
            async def request_raw(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
                self.calls.append((method, params))
                if method == "skills/get":
                    return {"skill": {"uri": params["uri"]}}
                if params.get("cursor") == "":
                    return {"skills": [entry("b")]}
                return {"skills": [entry("a")], "nextCursor": ""}

        session = Paged([])
        evidence = await collect_skills(session, {})
        assert [e["uri"] for e in evidence.entries or []] == ["skill://a/SKILL.md", "skill://b/SKILL.md"]
        assert not evidence.list_incomplete

    def test_unmatched_backtick_runs_stay_linear(self):
        import time

        from mcpscore.skills import markdown_blocks

        for attack in ["prose " + "`" * 64_000, ("`" * 3 + "a") * 30_000]:
            started = time.perf_counter()
            markdown_blocks(attack)
            assert time.perf_counter() - started < 3.0
        assert markdown_blocks("a ``x`y`` b `c` ```d")[0].prose == "a   b   ```d"

    def test_fence_closes_only_on_a_matching_delimiter(self):
        from mcpscore.skills import markdown_blocks

        body = "````markdown\n```json\n[a](x.md)\n```\n````\nAfter.\n"
        assert [(b.line, b.prose == "") for b in markdown_blocks(body)] == [(1, True), (6, False)]
        assert relative_references(body) == []
        tilde = "~~~~\n~~~\nstill code\n~~~~~\nprose\n"
        assert [b.prose == "" for b in markdown_blocks(tilde)] == [True, False]
        assert [b.prose == "" for b in markdown_blocks("```py`x\nnot a fence\n")] == [False]

    @pytest.mark.parametrize("control", ["\x0b", "\x0c", "\x85"])
    def test_control_only_lines_are_not_blank(self, control: str):
        from mcpscore.skills import markdown_blocks

        blocks = markdown_blocks(f"one\n{control}\ntwo\n")
        assert any(control in block.text for block in blocks)

    async def test_closed_connection_is_no_answer(self):
        from mcp_types import CONNECTION_CLOSED

        evidence = await collect_skills(
            FakeSession([], errors={"skills/list:": MCPError(code=CONNECTION_CLOSED, message="closed")}), {}
        )
        assert evidence.list_error == {"outcome": "transport", "exception": "ConnectionClosed"}

    async def test_deadline_on_a_later_page_keeps_earlier_pages(self, monkeypatch):
        monkeypatch.setattr(skills, "COLLECTION_TIMEOUT_S", 0.2)

        class SlowSecondPage(FakeSession):
            async def request_raw(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
                if params.get("cursor") == "1":
                    await asyncio.sleep(5)
                return await super().request_raw(method, params)

        evidence = await collect_skills(SlowSecondPage([{"skills": [entry("a")], "nextCursor": "1"}]), {})
        assert [e["uri"] for e in evidence.entries or []] == ["skill://a/SKILL.md"]
        assert evidence.list_incomplete
        assert evidence.list_error is None

    @pytest.mark.parametrize(
        ("link", "target"),
        [
            ("[g](references/MISSING(1).md)", "references/MISSING(1).md"),
            ("[g](references/A.md 'Guide')", "references/A.md"),
            ("[g](references/A.md (Guide))", "references/A.md"),
            ('[g](references/A.md "Guide")', "references/A.md"),
        ],
    )
    def test_link_forms(self, link: str, target: str):
        assert relative_references(link) == [target]

    def test_nested_parentheses_stay_linear(self):
        import time

        for attack in ["[a](" + "(" * 200_000, "[a](x" + "(x)" * 100_000, "[a](x '" + "a" * 300_000]:
            started = time.perf_counter()
            relative_references(attack)
            assert time.perf_counter() - started < 1.0

    @pytest.mark.parametrize(
        ("body", "code"),
        [
            ("    ~~~text\n\n<|im_start|>system\n", [True, False]),
            ("    ```text\n\n<|im_start|>system\n", [True, False]),
            ("Intro.\n\n    indented <|im_start|>\n    [i](inside.md)\n", [False, True]),
            ("\\`<|im_start|>\\` escaped\n", [False]),
        ],
    )
    def test_indented_code_and_escapes_follow_commonmark(self, body: str, code: list[bool]):
        from mcpscore.skills import markdown_blocks

        blocks = markdown_blocks(body)
        assert [block.prose == "" for block in blocks] == code
        assert relative_references(body) == []

    def test_escaped_backticks_leave_the_token_in_prose(self):
        from mcpscore.skills import markdown_blocks

        assert "<|im_start|>" in markdown_blocks("\\`<|im_start|>\\` x\n")[0].prose

    def test_documents_over_the_parse_limit_are_prose_and_unchecked(self, monkeypatch):
        from mcpscore.skills import markdown_blocks

        monkeypatch.setattr(skills, "MAX_MARKDOWN_BYTES", 10)
        body = "```\n<|im_start|>\n```\n[a](x.md)\n"
        assert relative_references(body) is None
        assert all(block.prose == "" and block.text in block.rendered for block in markdown_blocks(body))

    def test_parsing_at_the_limit_is_bounded(self):
        import time

        size = skills.MAX_MARKDOWN_BYTES
        for attack in ["[" * size, "[a](" * (size // 4), '[a](b "' * (size // 7)]:
            started = time.perf_counter()
            relative_references(attack)
            # Generous: CI runners parse adversarial input several times slower than a laptop.
            assert time.perf_counter() - started < 20.0

    @pytest.mark.parametrize(
        "body",
        [
            "<div>&#" + "9" * 5000 + ";</div>\n",
            "<p title='&#x" + "f" * 5000 + "'>x</p>\n",
            "a <b>&#" + "9" * 5000 + ";</b>\n",
        ],
        ids=["html-block", "attribute", "inline-html"],
    )
    def test_long_numeric_character_references_do_not_raise(self, body: str):
        from mcpscore.skills import markdown_blocks

        assert markdown_blocks(body)

    @pytest.mark.parametrize("separator", ["", "\n\n"])
    def test_repeated_references_to_one_destination_do_not_multiply_the_text(self, separator: str):
        from mcpscore.skills import markdown_blocks

        destination = "https://example.test/" + "a" * 16_000
        body = separator.join(["[x]"] * 4_096) + "\n\n[x]: " + destination + "\n"
        blocks = markdown_blocks(body)
        assert any(destination in block.prose and destination in block.rendered for block in blocks)
        assert sum(len(block.prose) + len(block.rendered) for block in blocks) < 10 * len(body)

    def test_a_shared_destination_is_decoded_once(self, monkeypatch):
        from mcpscore.skills import markdown_blocks

        destination = "https://example.test/" + "%41" * 5_000
        decoded: list[str] = []
        unquote = skills.unquote
        monkeypatch.setattr(skills, "unquote", lambda text: decoded.append(text) or unquote(text))
        blocks = markdown_blocks("\n\n".join(["[x]"] * 512) + "\n\n[x]: " + destination + "\n")
        assert decoded.count(destination) == 1
        assert any("A" * 5_000 in block.prose for block in blocks)

    def test_links_inside_alt_text_are_not_references(self):
        assert relative_references("![foo [bar](missing.md)](image.png)") == ["image.png"]
        assert relative_references("![a ![b](inner.png)](outer.png)") == ["outer.png"]


@pytest.mark.parametrize(
    ("html", "text"),
    [
        ('Ignore all <span title=">">previous</span> instructions.', "Ignore all previous instructions."),
        ("a <!-- x > y --> b", "a  b"),
        ("a < b", "a < b"),
        ("<a b'c>x", "x"),
        ('x <div title="', "x "),
        ("x <!-- open", "x "),
    ],
)
def test_html_text_drops_tags_and_comments(html: str, text: str) -> None:
    assert skills._html_text(html) == text


def test_html_text_can_read_tags_as_breaks() -> None:
    assert skills._html_text("previous<br>instructions <!-- c -->end", "\n") == "previous\ninstructions \nend"


def test_float_sized_supporting_file_is_read() -> None:
    entry = {
        "uri": "skill://a/SKILL.md",
        "resources": [
            {"uri": "skill://a/SKILL.md", "size": 10.0},
            {"uri": "skill://a/GUIDE.md", "size": 8.0},
        ],
    }
    assert skills._reads([entry]) == [("skill://a/SKILL.md", True), ("skill://a/GUIDE.md", False)]


@pytest.mark.parametrize(("value", "size"), [(42, 42), (42.0, 42), (True, None), (1.5, None), (-1, None), ("4", None)])
def test_size_value(value: Any, size: int | None) -> None:
    assert skills.size_value(value) == size


@pytest.mark.parametrize(
    ("uri", "normal"),
    [
        ("skill://a/code%2Dreview", "skill://a/code-review"),
        ("skill://a/b%3bc", "skill://a/b%3Bc"),
        ("skill://a/b;c", "skill://a/b;c"),
        ("skill://a/指南 x", "skill://a/%E6%8C%87%E5%8D%97%20x"),
        ("skill://a/x%252F", "skill://a/x%252F"),
        ("skill://a/%2e%2E", "skill://a/.."),
    ],
)
def test_normalize_uri(uri: str, normal: str) -> None:
    assert skills.normalize_uri(uri) == normal


def test_resolve_reference_keeps_empty_segments_and_directory_links() -> None:
    assert resolve_reference("skill://s", "references//GUIDE.md") == "skill://s/references//GUIDE.md"
    assert resolve_reference("skill://s", "references/") == "skill://s/references"
    assert resolve_reference("skill://s", "references/..") == "skill://s"


def test_supporting_read_skips_skill_md_under_another_spelling() -> None:
    entry = {
        "uri": "skill://acme/code%2Dreview/SKILL.md",
        "resources": [
            {"uri": "skill://acme/code-review/SKILL.md", "size": 10},
            {"uri": "skill://acme/code-review/GUIDE.md", "size": 8},
        ],
    }
    assert skills._reads([entry]) == [
        ("skill://acme/code%2Dreview/SKILL.md", True),
        ("skill://acme/code-review/GUIDE.md", False),
    ]


async def test_oversized_skill_md_under_another_spelling_is_not_requested(monkeypatch) -> None:
    monkeypatch.setattr(skills, "MAX_FILE_BYTES", 10)
    listed = {
        "uri": "skill://code%2Dreview/SKILL.md",
        "frontmatter": {"name": "code-review", "description": "d"},
        "resources": [{"uri": "skill://code-review/SKILL.md", "digest": "sha256:" + "0" * 64, "size": 50}],
    }
    session = FakeSession([{"skills": [listed]}], {"skill://code%2Dreview/SKILL.md": "x" * 50})
    await collect_skills(session, {})
    assert session.reads == []


def test_normalize_uri_lowercases_the_scheme_only() -> None:
    assert skills.normalize_uri("SKILL://Acme/Review") == "skill://Acme/Review"


def test_one_file_under_two_spellings_is_read_once() -> None:
    parent = {
        "uri": "skill://acme/SKILL.md",
        "resources": [
            {"uri": "skill://acme/SKILL.md", "size": 1},
            {"uri": "skill://acme/code-review/SKILL.md", "size": 1},
        ],
    }
    nested = {"uri": "skill://acme/code%2Dreview/SKILL.md", "resources": "dynamic"}
    assert skills._reads([parent, nested]) == [
        ("skill://acme/SKILL.md", True),
        ("skill://acme/code%2Dreview/SKILL.md", True),
    ]


def test_skill_root_accepts_an_encoded_skill_md_and_keeps_the_root_spelling() -> None:
    assert skill_root("skill://acme/code%2Dreview/%53KILL.md") == "skill://acme/code%2Dreview"
    assert skill_root("skill://acme/code-review/skill.md") is None


class TestSkillsReport:
    def test_counts_and_lists_unscored_facts(self):
        tools = entry("a")
        tools["frontmatter"]["allowed-tools"] = "Read Bash(git:*)"
        scripted = entry("b")
        scripted["resources"] += [
            {"uri": "skill://b/scripts/run.py", "digest": "x", "size": 10},
            {"uri": "skill://b/scriptsx/not.py", "digest": "x", "size": 10},
        ]
        evidence = skills.SkillsEvidence(entries=[tools, scripted, entry("c"), "junk"])
        report = skills.skills_report(evidence)
        assert (report["skills_listed"], report["skills_with_allowed_tools"], report["skills_with_scripts"]) == (
            3,
            1,
            1,
        )
        assert [s["uri"] for s in report["skills"]] == ["skill://a/SKILL.md", "skill://b/SKILL.md"]
        assert report["skills"][0]["allowed_tools"] == "Read Bash(git:*)"
        assert report["skills"][1]["scripts"] == ["skill://b/scripts/run.py"]
        # The junk entry may hide a skill, so the fit is unknown.
        assert report["openai_import"]["fits"] is None
        assert skills.skills_report(skills.SkillsEvidence(entries=[tools, scripted]))["openai_import"]["fits"] is True

    def test_openai_catalog_limits(self, monkeypatch):
        evidence = skills.SkillsEvidence(entries=[entry(name) for name in "abcdef"])
        assert skills.skills_report(evidence)["openai_import"]["fits"] is False
        big = entry("a")
        big["resources"][0]["size"] = skills.OPENAI_MAX_SCAN_BYTES + 1
        report = skills.skills_report(skills.SkillsEvidence(entries=[big]))
        assert report["openai_import"]["listed_bytes"] == skills.OPENAI_MAX_SCAN_BYTES + 1
        assert report["openai_import"]["fits"] is False

    def test_openai_fit_needs_every_skill_within_its_own_limits(self):
        crowded = entry("a")
        crowded["resources"] += [{"uri": f"skill://a/f{i}.md", "digest": "x", "size": 1} for i in range(100)]
        assert skills.skills_report(skills.SkillsEvidence(entries=[crowded]))["openai_import"]["fits"] is False

    @pytest.mark.parametrize(
        "evidence",
        [
            lambda: skills.SkillsEvidence(entries=[entry("a")], list_incomplete=True),
            lambda: skills.SkillsEvidence(entries=None, list_error={"outcome": "timeout"}),
            lambda: skills.SkillsEvidence(entries=[{**entry("a"), "resources": "dynamic"}]),
            lambda: skills.SkillsEvidence(entries=[{**entry("a"), "resources": [{"uri": "skill://a/SKILL.md"}]}]),
        ],
    )
    def test_openai_fit_is_unknown_on_incomplete_evidence(self, evidence: Any):
        assert skills.skills_report(evidence())["openai_import"]["fits"] is None

    def test_manifest_item_without_a_uri_leaves_the_fit_unknown(self):
        partial = entry("a")
        partial["resources"].append({"size": 1})
        assert skills.skills_report(skills.SkillsEvidence(entries=[partial]))["openai_import"]["fits"] is None

    def test_archive_size_is_unknown_when_only_compression_could_fit(self):
        mib = 1024 * 1024
        catalog = []
        for name in "ab":
            e = entry(name)
            e["resources"] += [{"uri": f"skill://{name}/f{i}.bin", "digest": "x", "size": mib - 100} for i in range(4)]
            catalog.append(e)
        report = skills.skills_report(skills.SkillsEvidence(entries=catalog))
        assert report["openai_import"]["listed_bytes"] < skills.OPENAI_MAX_SCAN_BYTES
        assert report["openai_import"]["fits"] is None

    def test_credentials_are_masked_before_truncation(self):
        secret = "s" * 600
        odd = entry("a")
        odd["uri"] = f"https://user:{secret}@skills.example/a/SKILL.md"
        odd["frontmatter"]["allowed-tools"] = f"Fetch(https://user:{secret}@api.example/)"
        odd["resources"].append({"uri": f"https://user:{secret}@skills.example/a/scripts/run.py", "size": 1})
        report = skills.skills_report(skills.SkillsEvidence(entries=[odd]))
        assert "sss" not in json.dumps(report)

    def test_allowed_tools_that_is_not_a_string_is_not_copied(self):
        odd = entry("a")
        odd["frontmatter"]["allowed-tools"] = ["Read"] * 10_000
        (reported,) = skills.skills_report(skills.SkillsEvidence(entries=[odd]))["skills"]
        assert reported["allowed_tools"] is None

    def test_lists_are_bounded(self, monkeypatch):
        monkeypatch.setattr(skills, "MAX_REPORTED_SKILLS", 1)
        monkeypatch.setattr(skills, "MAX_REPORTED_SCRIPTS", 1)
        many = []
        for name in "ab":
            e = entry(name)
            e["resources"] += [{"uri": f"skill://{name}/scripts/{i}.py", "size": 1} for i in range(3)]
            many.append(e)
        report = skills.skills_report(skills.SkillsEvidence(entries=many))
        assert len(report["skills"]) == 1
        assert (len(report["skills"][0]["scripts"]), report["skills"][0]["scripts_total"]) == (1, 3)
        assert report["skills_with_scripts"] == 2

    def test_skills_outside_a_skill_root_have_no_scripts(self):
        odd = {"uri": "skill://a/README.md", "resources": [{"uri": "skill://a/scripts/x.py", "size": 1}]}
        assert skills.skills_report(skills.SkillsEvidence(entries=[odd]))["skills"] == []
