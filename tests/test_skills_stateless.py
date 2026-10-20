"""Skills collected on the 2026-07-28 stateless lifecycle, and the skills/list caching-hints readiness rule."""

import asyncio
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
import json
import logging
from typing import Any

import anyio
import httpx2
from mcp.shared.exceptions import MCPError
from mcp.shared.message import SessionMessage
from mcp_types import JSONRPCNotification, JSONRPCResponse
import pytest

from mcpscore import mcp_auditor, probes, skills
from mcpscore.mcp_auditor import MCPAuditor
from mcpscore.probes import (
    PROBE_DISCOVER,
    StatelessSession,
    _HttpTarget,
    _StdioTarget,
    stateless_session,
)
from mcpscore.rules.base import (
    SKIP_REASON_INSUFFICIENT_DATA,
    SKIP_REASON_NOT_APPLICABLE,
    SKIP_REASON_REQUIRES_MODERN_SUPPORT,
    AuditData,
)
from mcpscore.rules.readiness import SkillsListCacheHintsReadinessRule
from mcpscore.skills import SkillsEvidence, collect_skills, stateless_list_hints
from mcpscore.spec import Era

from .test_modern_only_audit import DISCOVER_PAYLOAD, URL, _fake_tls, _modern_probe_results
from .test_readiness_rules import legacy_probes, modern_probes
from .test_skills import FakeSession, entry


def _http_session(reply: Any, seen: list[httpx2.Request] | None = None) -> StatelessSession:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if seen is not None:
            seen.append(request)
        return httpx2.Response(200, json=reply)

    return StatelessSession(_HttpTarget(httpx2.AsyncClient(transport=httpx2.MockTransport(handler)), URL))


class TestStatelessSession:
    async def test_request_declares_the_extension_and_returns_the_result(self):
        seen: list[httpx2.Request] = []
        session = _http_session({"jsonrpc": "2.0", "id": 1001, "result": {"skills": []}}, seen)
        assert await session.request_raw("skills/list", {}) == {"skills": []}
        body = json.loads(seen[0].content)
        meta = body["params"]["_meta"]
        assert meta["io.modelcontextprotocol/clientCapabilities"] == {
            "extensions": {"io.modelcontextprotocol/skills": {}}
        }
        assert seen[0].headers["Mcp-Method"] == "skills/list"
        assert "Mcp-Name" not in seen[0].headers

    async def test_resource_read_names_the_resource(self):
        seen: list[httpx2.Request] = []
        contents = {"contents": [{"uri": "skill://a/SKILL.md", "text": "x"}, "junk"]}
        session = _http_session({"jsonrpc": "2.0", "id": 1001, "result": contents}, seen)
        assert await session.read_resource_contents("skill://a/SKILL.md") == [
            {"uri": "skill://a/SKILL.md", "text": "x"}
        ]
        assert seen[0].headers["Mcp-Name"] == "skill://a/SKILL.md"

    async def test_contents_that_are_not_a_list_read_as_empty(self):
        session = _http_session({"jsonrpc": "2.0", "id": 1001, "result": {"contents": "x"}})
        assert await session.read_resource_contents("skill://a/SKILL.md") == []

    @pytest.mark.parametrize(
        ("error", "code"),
        [({"code": -32602, "message": "unknown"}, -32602), ({"message": 7}, 0)],
    )
    async def test_error_raises_with_its_code(self, error: dict[str, Any], code: int):
        session = _http_session({"jsonrpc": "2.0", "id": 1001, "error": error})
        with pytest.raises(MCPError) as raised:
            await session.request_raw("skills/get", {"uri": "skill://x/SKILL.md"})
        assert raised.value.error.code == code

    @pytest.mark.parametrize("result", [[], "x", None])
    async def test_result_that_is_not_an_object_is_malformed(self, result: Any):
        session = _http_session({"jsonrpc": "2.0", "id": 1001, "result": result})
        evidence = await collect_skills(session, {}, stateless=True)
        assert evidence.list_error == {"outcome": "malformed"}

    async def test_reply_without_result_is_no_answer(self):
        session = _http_session({"jsonrpc": "2.0", "id": 1001})
        with pytest.raises(ConnectionError):
            await session.request_raw("skills/list", {})

    async def test_http_and_stdio_targets(self, monkeypatch):
        monkeypatch.setattr(probes, "async_client", lambda **_: httpx2.AsyncClient())
        async with stateless_session(URL, {"Authorization": "Bearer x"}) as session:
            assert isinstance(session._target, _HttpTarget)

        @asynccontextmanager
        async def fake_stdio(params: Any, errlog: Any) -> AsyncGenerator[tuple[Any, Any]]:
            yield "read", "write"

        monkeypatch.setattr(probes, "stdio_client", fake_stdio)
        async with stateless_session(object()) as session:  # type: ignore[arg-type]
            assert isinstance(session._target, _StdioTarget)


class TestCollectorHints:
    async def test_hints_that_are_not_scalars_are_summarized(self):
        page = {"skills": [], "ttlMs": list(range(10_000)), "cacheScope": {"a": 1}, "resultType": "x" * 10_000}
        hints = await stateless_list_hints(FakeSession([page]))
        assert hints == {"result_type": "x" * 200, "ttl_ms": {"type": "array"}, "cache_scope": {"type": "object"}}

    async def test_stateless_collection_records_the_first_page_hints(self):
        page = {"skills": [entry("a")], "resultType": "complete", "ttlMs": 0, "cacheScope": "private"}
        evidence = await collect_skills(FakeSession([page]), {}, stateless=True)
        assert evidence.stateless_list == {"result_type": "complete", "ttl_ms": 0, "cache_scope": "private"}
        session_evidence = await collect_skills(FakeSession([page]), {})
        assert session_evidence.stateless_list is None

    async def test_stateless_listing_failure_is_recorded(self):
        session = FakeSession([], errors={"skills/list:": MCPError(-32601, "no")})
        evidence = await collect_skills(session, {}, stateless=True)
        assert evidence.stateless_list == {"error": {"outcome": "rpc_error", "error_code": -32601}}

    async def test_hints_call(self):
        page = {"skills": [], "ttlMs": 5, "cacheScope": "public"}
        assert await stateless_list_hints(FakeSession([page])) == {
            "result_type": None,
            "ttl_ms": 5,
            "cache_scope": "public",
        }
        failing = FakeSession([], errors={"skills/list:": MCPError(-32601, "no")})
        assert await stateless_list_hints(failing) == {"error": {"outcome": "rpc_error", "error_code": -32601}}


def _fake_stateless(session: Any):
    @asynccontextmanager
    async def opener(target: Any, headers: Any = None) -> AsyncGenerator[Any]:
        yield session

    return opener


class TestAuditorWiring:
    async def test_modern_only_server_is_audited_for_skills(self, monkeypatch):
        payload = {
            **DISCOVER_PAYLOAD,
            "capabilities": {"tools": {}, "resources": {}, "extensions": {"io.modelcontextprotocol/skills": {}}},
        }
        results = _modern_probe_results(payload)

        async def fake_run_all_probes(url: str, client=None, headers=None):
            return results

        monkeypatch.setattr(mcp_auditor, "run_all_probes", fake_run_all_probes)
        monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(_fake_tls))
        a = entry("a")
        page = {"skills": [a], "resultType": "complete", "ttlMs": 0, "cacheScope": "private"}
        session = FakeSession([page], {"skill://a/SKILL.md": "---\nname: a\ndescription: d\n---\n"})
        monkeypatch.setattr(mcp_auditor, "stateless_session", _fake_stateless(session))

        auditor = MCPAuditor()
        assert await auditor.audit_modern_only(URL) is True
        assert auditor.era is Era.MODERN
        assert auditor.audit_data.skills is not None
        results_by_id = {r.rule_id: r for r in [*auditor.results, *auditor.readiness_results]}
        assert results_by_id["skills_digest_integrity"].passed
        assert results_by_id["readiness_2026_skills_list_cache_hints"].passed

    async def test_modern_only_without_the_extension_collects_nothing(self, monkeypatch):
        async def fake_run_all_probes(url: str, client=None, headers=None):
            return _modern_probe_results()

        monkeypatch.setattr(mcp_auditor, "run_all_probes", fake_run_all_probes)
        monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(_fake_tls))
        monkeypatch.setattr(mcp_auditor, "stateless_session", None)
        auditor = MCPAuditor()
        assert await auditor.audit_modern_only(URL) is True
        assert auditor.audit_data.skills is None

    async def test_lost_stateless_connection_is_logged(self, monkeypatch, caplog):
        @asynccontextmanager
        async def broken(target: Any, headers: Any = None) -> AsyncGenerator[Any]:
            raise OSError("refused")
            yield

        monkeypatch.setattr(mcp_auditor, "stateless_session", broken)
        auditor = MCPAuditor()
        auditor.audit_data.capabilities = probes_capabilities()
        with caplog.at_level(logging.WARNING):
            await auditor._collect_skills_stateless(URL)
        assert auditor.audit_data.skills is None
        assert "Could not collect skills on the stateless lifecycle (OSError)" in caplog.text

        auditor.audit_data.skills, auditor.audit_data.url, auditor.era = SkillsEvidence(), URL, Era.DUAL
        with caplog.at_level(logging.WARNING):
            await auditor._collect_stateless_skills_listing()
        assert "Could not list skills on the stateless lifecycle (OSError)" in caplog.text

    @pytest.mark.parametrize(
        ("era", "url", "listed"),
        [(Era.DUAL, URL, True), (Era.LEGACY, URL, False), (Era.DUAL, None, False), (Era.DUAL, "stdio", False)],
    )
    async def test_dual_era_http_server_gets_one_stateless_listing(self, monkeypatch, era, url, listed):
        page = {"skills": [], "resultType": "complete", "ttlMs": 0, "cacheScope": "public"}
        monkeypatch.setattr(mcp_auditor, "stateless_session", _fake_stateless(FakeSession([page])))
        auditor = MCPAuditor()
        auditor.audit_data.skills, auditor.audit_data.url, auditor.era = SkillsEvidence(), url, era
        await auditor._collect_stateless_skills_listing()
        assert (auditor.audit_data.skills.stateless_list is not None) is listed

    async def test_no_skills_evidence_means_no_listing(self, monkeypatch):
        monkeypatch.setattr(mcp_auditor, "stateless_session", None)
        auditor = MCPAuditor()
        auditor.audit_data.url, auditor.era = URL, Era.DUAL
        await auditor._collect_stateless_skills_listing()
        assert auditor.audit_data.skills is None


def probes_capabilities() -> Any:
    from mcp_types import ServerCapabilities

    return ServerCapabilities.model_validate({"resources": {}, "extensions": {"io.modelcontextprotocol/skills": {}}})


def _sse(*messages: dict[str, Any]) -> bytes:
    return b"".join(b"data: " + json.dumps(m).encode() + b"\n\n" for m in messages)


class TestStatelessTransport:
    async def test_sse_reply_after_a_notification_is_found(self):
        def handler(request: httpx2.Request) -> httpx2.Response:
            body = _sse(
                {"jsonrpc": "2.0", "method": "notifications/message", "params": {}},
                {"jsonrpc": "2.0", "id": 1001, "result": {"skills": []}},
            )
            return httpx2.Response(200, headers={"content-type": "text/event-stream"}, content=body)

        client = httpx2.AsyncClient(transport=httpx2.MockTransport(handler))
        assert await StatelessSession(_HttpTarget(client, URL)).request_raw("skills/list", {}) == {"skills": []}

    async def test_open_stream_without_a_reply_times_out(self, monkeypatch):
        monkeypatch.setattr(probes, "PROBE_TIMEOUT_S", 0.2)

        async def heartbeats() -> AsyncIterator[bytes]:
            while True:
                yield b": ping\n\n"
                await asyncio.sleep(0.01)

        def handler(request: httpx2.Request) -> httpx2.Response:
            return httpx2.Response(200, headers={"content-type": "text/event-stream"}, content=heartbeats())

        session = StatelessSession(_HttpTarget(httpx2.AsyncClient(transport=httpx2.MockTransport(handler)), URL))
        async with asyncio.timeout(5):
            with pytest.raises(TimeoutError):
                await session.request_raw("skills/list", {})

    async def test_skill_sized_answer_is_read_whole(self):
        text = "x" * (512 * 1024)
        reply = {"jsonrpc": "2.0", "id": 1001, "result": {"contents": [{"uri": "skill://a/SKILL.md", "text": text}]}}
        contents = await _http_session(reply).read_resource_contents("skill://a/SKILL.md")
        assert contents[0]["text"] == text

    async def test_concurrent_stdio_calls_each_get_their_reply(self, monkeypatch):
        monkeypatch.setattr(probes, "PROBE_TIMEOUT_S", 1.0)
        to_server, server_in = anyio.create_memory_object_stream[Any](10)
        server_out, from_server = anyio.create_memory_object_stream[Any](10)

        async def server() -> None:
            async for incoming in server_in:
                request = incoming.message
                # A notification ahead of each reply hands the stream to the other waiting call.
                note = {"jsonrpc": "2.0", "method": "notifications/message", "params": {}}
                await server_out.send(SessionMessage(JSONRPCNotification.model_validate(note)))
                reply = {"jsonrpc": "2.0", "id": request.id, "result": {"method": request.method}}
                await server_out.send(SessionMessage(JSONRPCResponse.model_validate(reply)))

        session = StatelessSession(_StdioTarget(from_server, to_server))
        async with to_server, server_in, server_out, from_server, anyio.create_task_group() as group:
            group.start_soon(server)
            results = await asyncio.gather(
                session.request_raw("skills/get", {"uri": "skill://a/SKILL.md"}),
                session.request_raw("skills/list", {}),
            )
            group.cancel_scope.cancel()
        assert results == [{"method": "skills/get"}, {"method": "skills/list"}]


class TestCacheHintsRule:
    rule = SkillsListCacheHintsReadinessRule()

    def audit(self, stateless_list: dict[str, Any] | None, probes: Any = None) -> AuditData:
        return AuditData(
            probes=modern_probes() if probes is None else probes,
            skills=SkillsEvidence(stateless_list=stateless_list),
        )

    def test_skips(self):
        assert self.rule.skip_reason(AuditData(probes=modern_probes())) == SKIP_REASON_NOT_APPLICABLE
        legacy = self.audit({"ttl_ms": 0, "cache_scope": "public"}, legacy_probes())
        assert self.rule.skip_reason(legacy) == SKIP_REASON_REQUIRES_MODERN_SUPPORT
        assert self.rule.skip_reason(self.audit(None)) == SKIP_REASON_INSUFFICIENT_DATA
        timed_out = self.audit({"error": {"outcome": "timeout"}})
        assert self.rule.skip_reason(timed_out) == SKIP_REASON_INSUFFICIENT_DATA

    @pytest.mark.parametrize(
        ("observed", "passed", "paths"),
        [
            ({"ttl_ms": 0, "cache_scope": "private"}, True, []),
            ({"ttl_ms": True, "cache_scope": "public"}, False, ["/ttlMs"]),
            ({"ttl_ms": -1, "cache_scope": "shared"}, False, ["/ttlMs", "/cacheScope"]),
            ({"ttl_ms": 0, "cache_scope": []}, False, ["/cacheScope"]),
            ({"ttl_ms": 0, "cache_scope": {}}, False, ["/cacheScope"]),
        ],
    )
    def test_hints(self, observed: dict[str, Any], passed: bool, paths: list[str]):
        result = self.rule.check(self.audit(observed))
        assert result.passed is passed
        assert [issue["path"] for issue in (result.details or {}).get("issues", [])] == paths

    @pytest.mark.parametrize(
        ("error", "phrase"),
        [
            ({"outcome": "rpc_error", "error_code": -32601}, "with JSON-RPC error -32601"),
            ({"outcome": "malformed"}, "failed on the stateless lifecycle."),
        ],
    )
    def test_listing_refused_on_the_stateless_lifecycle(self, error: dict[str, Any], phrase: str):
        result = self.rule.check(self.audit({"error": error}))
        assert not result.passed
        assert phrase in result.message


def test_discover_probe_is_what_marks_modern_support():
    assert PROBE_DISCOVER in modern_probes()
    assert skills.SKILLS_EXTENSION == probes.SKILLS_EXTENSION_ID
