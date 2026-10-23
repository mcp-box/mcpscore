"""A dual-era server that declares the Skills extension only in server/discover still has its skills audited."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
import logging
from typing import Any

from mcp.shared.exceptions import MCPError
from mcp_types import InitializeResult
import pytest

from mcpscore import mcp_auditor
from mcpscore.mcp_auditor import MCPAuditor
from mcpscore.mcp_client import MCPClient
from mcpscore.probes import PROBE_DISCOVER, ProbeOutcome, ProbeResult, not_applicable_results
from mcpscore.rules.base import SKIP_REASON_NOT_APPLICABLE
from mcpscore.spec import Era

from .test_skills import FakeSession, entry

URL = "https://skills.example/mcp"
SKILLS = {"io.modelcontextprotocol/skills": {"directoryRead": False}}

# The 2025-11-25 initialize result has no extensions field, so the session declares nothing.
INIT_RESULT = InitializeResult.model_validate(
    {"protocolVersion": "2025-11-25", "capabilities": {}, "serverInfo": {"name": "skills-demo", "version": "1.0"}}
)


class SessionClient(MCPClient):
    """A connected legacy session that answers skills requests from a FakeSession."""

    def __init__(self, session: FakeSession) -> None:
        super().__init__()
        self.skills = session
        self.url = URL
        self.transport_type = "streamable-http"  # type: ignore[assignment]
        self.connection_time_ms = 10

    async def initialize(self) -> InitializeResult:
        return INIT_RESULT

    async def request_raw(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        return await self.skills.request_raw(method, params)

    async def read_resource_contents(self, uri: str) -> list[dict[str, Any]]:
        return await self.skills.read_resource_contents(uri)


def _page(*entries: dict[str, Any]) -> dict[str, Any]:
    return {"skills": list(entries), "resultType": "complete", "ttlMs": 0, "cacheScope": "public"}


def _files(name: str) -> dict[str, str]:
    return {f"skill://{name}/SKILL.md": f"---\nname: {name}\ndescription: d\n---\n"}


@pytest.fixture
def discover(monkeypatch: pytest.MonkeyPatch):
    """Install probes whose server/discover declares the given capabilities."""

    def install(capabilities: dict[str, Any]) -> None:
        results = not_applicable_results(reason="unset")
        payload = {"supportedVersions": ["2025-11-25", "2026-07-28"], "capabilities": capabilities}
        results[PROBE_DISCOVER] = ProbeResult(PROBE_DISCOVER, ProbeOutcome.SUPPORTED, {}, payload=payload)

        async def run_all_probes(url: str, client: Any = None, headers: Any = None) -> dict:
            return results

        monkeypatch.setattr(mcp_auditor, "run_all_probes", run_all_probes)

    async def tls_version(url: str) -> str:
        return "TLSv1.3"

    monkeypatch.setattr(MCPAuditor, "_probe_tls_version", staticmethod(tls_version))
    return install


def _stateless(monkeypatch: pytest.MonkeyPatch, session: Any) -> None:
    @asynccontextmanager
    async def opener(target: Any, headers: Any = None) -> AsyncGenerator[Any]:
        if isinstance(session, Exception):
            raise session
        yield session

    monkeypatch.setattr(mcp_auditor, "stateless_session", opener)


async def test_skills_declared_only_in_discover_are_collected_and_judged(discover, monkeypatch) -> None:
    discover({"extensions": SKILLS})
    _stateless(monkeypatch, FakeSession([_page()]))
    auditor = MCPAuditor()

    await auditor.audit(SessionClient(FakeSession([_page(entry("pdf"))], _files("pdf"))))

    assert auditor.era is Era.DUAL
    evidence = auditor.audit_data.skills
    assert evidence is not None
    assert evidence.declared_in_discover
    assert evidence.settings == SKILLS["io.modelcontextprotocol/skills"]
    assert [item["uri"] for item in evidence.entries or []] == ["skill://pdf/SKILL.md"]
    results = {result.rule_id: result for result in auditor.results}
    assert results["skills_list_supported"].passed
    assert results["skills_digest_integrity"].passed
    assert results["server_exposes_primitive"].passed


async def test_session_refusal_falls_back_to_the_stateless_lifecycle(discover, monkeypatch) -> None:
    discover({"extensions": SKILLS})
    stateless = FakeSession([_page(entry("pdf"))], _files("pdf"))
    _stateless(monkeypatch, stateless)
    refusing = FakeSession([], errors={"skills/list:": MCPError(-32601, "Method not found")})
    auditor = MCPAuditor()

    await auditor.audit(SessionClient(refusing))

    evidence = auditor.audit_data.skills
    assert evidence is not None
    assert [item["uri"] for item in evidence.entries or []] == ["skill://pdf/SKILL.md"]
    assert ("skills/list", {}) in stateless.calls
    assert {result.rule_id: result for result in auditor.results}["server_exposes_primitive"].passed


async def test_lost_stateless_connection_keeps_the_session_evidence(discover, monkeypatch, caplog) -> None:
    discover({"extensions": SKILLS})
    _stateless(monkeypatch, OSError("refused"))
    refusing = FakeSession([], errors={"skills/list:": MCPError(-32601, "Method not found")})
    auditor = MCPAuditor()

    with caplog.at_level(logging.WARNING):
        await auditor.audit(SessionClient(refusing))

    evidence = auditor.audit_data.skills
    assert evidence is not None
    assert evidence.entries is None
    assert evidence.list_error is not None
    assert "Could not collect skills on the stateless lifecycle (OSError)" in caplog.text
    assert "server_exposes_primitive" in {rule.rule_id for rule in auditor.skipped_rules}


async def test_no_declaration_anywhere_collects_nothing(discover, monkeypatch) -> None:
    discover({})
    monkeypatch.setattr(mcp_auditor, "stateless_session", None)
    session = FakeSession([_page(entry("pdf"))])
    auditor = MCPAuditor()

    await auditor.audit(SessionClient(session))

    assert auditor.audit_data.skills is None
    assert session.calls == []
    skipped = {rule.rule_id: rule.reason for rule in auditor.skipped_rules}
    assert skipped["skills_list_supported"] == SKIP_REASON_NOT_APPLICABLE
    assert not {result.rule_id: result for result in auditor.results}["server_exposes_primitive"].passed


async def test_empty_session_catalog_falls_back_to_the_stateless_catalog(discover, monkeypatch) -> None:
    discover({"resources": {}, "extensions": SKILLS})
    _stateless(monkeypatch, FakeSession([_page(entry("pdf"))], _files("pdf")))
    auditor = MCPAuditor()

    await auditor.audit(SessionClient(FakeSession([_page()])))

    evidence = auditor.audit_data.skills
    assert evidence is not None
    assert [item["uri"] for item in evidence.entries or []] == ["skill://pdf/SKILL.md"]
    results = {result.rule_id: result for result in auditor.results}
    assert results["server_exposes_primitive"].passed
    assert "skills_digest_integrity" in results


async def test_both_catalogs_empty_keeps_the_session_listing(discover, monkeypatch) -> None:
    discover({"extensions": SKILLS})
    stateless = FakeSession([_page()])
    _stateless(monkeypatch, stateless)
    auditor = MCPAuditor()

    await auditor.audit(SessionClient(FakeSession([_page()])))

    evidence = auditor.audit_data.skills
    assert evidence is not None
    assert evidence.entries == []
    assert not evidence.list_incomplete
    assert not {result.rule_id: result for result in auditor.results}["server_exposes_primitive"].passed


@pytest.mark.parametrize(
    ("discovered", "passed"),
    [({"resources": {}, "extensions": SKILLS}, True), ({"extensions": SKILLS}, False)],
    ids=["discover-declares-resources", "discover-omits-resources"],
)
async def test_resources_capability_is_judged_on_the_declaring_lifecycle(
    discover, monkeypatch, discovered: dict[str, Any], passed: bool
) -> None:
    discover(discovered)
    _stateless(monkeypatch, FakeSession([_page()]))
    auditor = MCPAuditor()

    await auditor.audit(SessionClient(FakeSession([_page(entry("pdf"))], _files("pdf"))))

    assert auditor.audit_data.capabilities is not None
    assert auditor.audit_data.capabilities.resources is None
    assert {result.rule_id: result for result in auditor.results}["skills_resources_capability"].passed is passed


@pytest.mark.parametrize(
    "stateless",
    [
        FakeSession([{"skills": [], "resultType": "incomplete"}]),
        FakeSession([], errors={"skills/list:": MCPError(-32601, "Method not found")}),
        OSError("refused"),
    ],
    ids=["stateless-incomplete", "stateless-refused", "stateless-unreachable"],
)
async def test_empty_session_listing_needs_a_whole_stateless_listing(discover, monkeypatch, stateless: Any) -> None:
    discover({"extensions": SKILLS})
    _stateless(monkeypatch, stateless)
    auditor = MCPAuditor()

    await auditor.audit(SessionClient(FakeSession([_page()])))

    evidence = auditor.audit_data.skills
    assert evidence is not None
    assert evidence.entries == []
    assert evidence.list_incomplete
    assert "server_exposes_primitive" in {rule.rule_id for rule in auditor.skipped_rules}
