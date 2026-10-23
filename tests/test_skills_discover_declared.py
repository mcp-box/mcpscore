"""Skills of a dual-era server are judged on the lifecycle that declared the extension."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
import logging
from typing import Any

from mcp.shared.exceptions import MCPError
from mcp_types import InitializeResult, Resource, ResourceTemplate
import pytest

from mcpscore import mcp_auditor
from mcpscore.mcp_auditor import MCPAuditor
from mcpscore.mcp_client import MCPClient
from mcpscore.probes import PROBE_DISCOVER, ProbeOutcome, ProbeResult, not_applicable_results
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE
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


def _outcomes(auditor: MCPAuditor) -> dict[str, bool | str]:
    """Map each rule to whether it passed, or to its skip reason."""
    outcomes: dict[str, bool | str] = {result.rule_id: result.passed for result in auditor.results}
    outcomes.update({rule.rule_id: rule.reason for rule in auditor.skipped_rules})
    return outcomes


class BothDeclareClient(SessionClient):
    """A session whose initialize result declares the Skills extension too."""

    async def initialize(self) -> InitializeResult:
        return InitializeResult.model_validate(
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {"resources": {}, "extensions": SKILLS},
                "serverInfo": {"name": "skills-demo", "version": "1.0"},
            }
        )

    async def list_resources(self) -> list[Resource]:
        return []

    async def list_resource_templates(self) -> list[ResourceTemplate]:
        return []


async def test_discover_only_skills_are_collected_and_judged_on_the_stateless_lifecycle(discover, monkeypatch) -> None:
    discover({"resources": {}, "extensions": SKILLS})
    _stateless(monkeypatch, FakeSession([_page(entry("pdf"))], _files("pdf")))
    session = FakeSession([_page(entry("other"))])
    auditor = MCPAuditor()

    await auditor.audit(SessionClient(session))

    assert auditor.era is Era.DUAL
    evidence = auditor.audit_data.skills
    assert evidence is not None
    assert evidence.stateless
    assert evidence.settings == SKILLS["io.modelcontextprotocol/skills"]
    assert [item["uri"] for item in evidence.entries or []] == ["skill://pdf/SKILL.md"]
    assert session.calls == []
    outcomes = _outcomes(auditor)
    assert outcomes["skills_list_supported"] is True
    assert outcomes["skills_digest_integrity"] is True
    assert outcomes["skills_resources_capability"] is True
    assert outcomes["server_exposes_primitive"] is True


async def test_directory_reads_are_checked_where_they_were_advertised(discover, monkeypatch) -> None:
    discover({"resources": {}, "extensions": {"io.modelcontextprotocol/skills": {"directoryRead": True}}})
    stateless = FakeSession([_page(entry("pdf"))], _files("pdf"))
    _stateless(monkeypatch, stateless)
    session = FakeSession([_page(entry("pdf"))], _files("pdf"))
    auditor = MCPAuditor()

    await auditor.audit(SessionClient(session))

    assert auditor.audit_data.skills is not None
    assert auditor.audit_data.skills.settings == {"directoryRead": True}
    assert session.calls == []
    assert "resources/directory/read" in {method for method, _ in stateless.calls}


async def test_stateless_refusal_fails_the_listing_rule_whatever_the_session_serves(discover, monkeypatch) -> None:
    discover({"resources": {}, "extensions": SKILLS})
    _stateless(monkeypatch, FakeSession([], errors={"skills/list:": MCPError(-32601, "Method not found")}))
    auditor = MCPAuditor()

    await auditor.audit(SessionClient(FakeSession([_page(entry("pdf"))], _files("pdf"))))

    evidence = auditor.audit_data.skills
    assert evidence is not None
    assert evidence.entries is None
    outcomes = _outcomes(auditor)
    assert outcomes["skills_list_supported"] is False
    assert outcomes["server_exposes_primitive"] == SKIP_REASON_INSUFFICIENT_DATA


async def test_unreachable_stateless_lifecycle_leaves_the_skills_unjudged(discover, monkeypatch, caplog) -> None:
    discover({"resources": {}, "extensions": SKILLS})
    _stateless(monkeypatch, OSError("refused"))
    auditor = MCPAuditor()

    with caplog.at_level(logging.WARNING):
        await auditor.audit(SessionClient(FakeSession([_page(entry("pdf"))])))

    assert auditor.audit_data.skills is None
    assert "Could not collect skills on the stateless lifecycle (OSError)" in caplog.text
    outcomes = _outcomes(auditor)
    assert outcomes["skills_list_supported"] == SKIP_REASON_INSUFFICIENT_DATA
    assert outcomes["server_exposes_primitive"] == SKIP_REASON_INSUFFICIENT_DATA


async def test_no_declaration_anywhere_collects_nothing(discover, monkeypatch) -> None:
    discover({})
    monkeypatch.setattr(mcp_auditor, "stateless_session", None)
    session = FakeSession([_page(entry("pdf"))])
    auditor = MCPAuditor()

    await auditor.audit(SessionClient(session))

    assert auditor.audit_data.skills is None
    assert session.calls == []
    outcomes = _outcomes(auditor)
    assert outcomes["skills_list_supported"] == SKIP_REASON_NOT_APPLICABLE
    assert outcomes["server_exposes_primitive"] is False


@pytest.mark.parametrize(
    ("page", "expected"),
    [
        (_page(), False),
        ({"skills": [], "resultType": "incomplete"}, SKIP_REASON_INSUFFICIENT_DATA),
    ],
    ids=["whole-empty", "unfinished"],
)
async def test_empty_stateless_catalog_proves_emptiness_only_when_whole(
    discover, monkeypatch, page: dict[str, Any], expected: bool | str
) -> None:
    discover({"extensions": SKILLS})
    _stateless(monkeypatch, FakeSession([page]))
    auditor = MCPAuditor()

    await auditor.audit(SessionClient(FakeSession([])))

    assert _outcomes(auditor)["server_exposes_primitive"] == expected


@pytest.mark.parametrize(
    ("discovered", "passed"),
    [({"resources": {}, "extensions": SKILLS}, True), ({"extensions": SKILLS}, False)],
    ids=["discover-declares-resources", "discover-omits-resources"],
)
async def test_resources_capability_is_judged_on_the_declaring_lifecycle(
    discover, monkeypatch, discovered: dict[str, Any], passed: bool
) -> None:
    discover(discovered)
    _stateless(monkeypatch, FakeSession([_page(entry("pdf"))], _files("pdf")))
    auditor = MCPAuditor()

    await auditor.audit(SessionClient(FakeSession([])))

    assert auditor.audit_data.capabilities is not None
    assert auditor.audit_data.capabilities.resources is None
    assert _outcomes(auditor)["skills_resources_capability"] is passed


class ListingResourcesClient(SessionClient):
    """A session that declares resources and lists the skill file with its own description."""

    async def initialize(self) -> InitializeResult:
        return InitializeResult.model_validate(
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {"resources": {}},
                "serverInfo": {"name": "skills-demo", "version": "1.0"},
            }
        )

    async def list_resources(self) -> list[Resource]:
        return [Resource(name="pdf", uri="skill://pdf/SKILL.md", description="Another lifecycle's text")]

    async def list_resource_templates(self) -> list[ResourceTemplate]:
        return []


async def test_stateless_skills_are_not_compared_with_the_session_resource_catalog(discover, monkeypatch) -> None:
    discover({"resources": {}, "extensions": SKILLS})
    _stateless(monkeypatch, FakeSession([_page(entry("pdf"))], _files("pdf")))
    auditor = MCPAuditor()

    await auditor.audit(ListingResourcesClient(FakeSession([])))

    assert auditor.audit_data.resources
    assert _outcomes(auditor)["skills_skill_file_metadata"] is True


async def test_both_declared_session_evidence_stands_and_stateless_skills_count(discover, monkeypatch) -> None:
    discover({"resources": {}, "extensions": SKILLS})
    _stateless(monkeypatch, FakeSession([_page(entry("pdf"))]))
    auditor = MCPAuditor()

    await auditor.audit(BothDeclareClient(FakeSession([_page()])))

    evidence = auditor.audit_data.skills
    assert evidence is not None
    assert not evidence.stateless
    assert evidence.entries == []
    assert evidence.stateless_count == 1
    outcomes = _outcomes(auditor)
    assert outcomes["skills_list_supported"] is True
    assert outcomes["server_exposes_primitive"] is True


async def test_both_declared_session_failure_is_not_hidden(discover, monkeypatch) -> None:
    discover({"resources": {}, "extensions": SKILLS})
    _stateless(monkeypatch, FakeSession([_page(entry("pdf"))], _files("pdf")))
    refusing = FakeSession([], errors={"skills/list:": MCPError(-32601, "Method not found")})
    auditor = MCPAuditor()

    await auditor.audit(BothDeclareClient(refusing))

    evidence = auditor.audit_data.skills
    assert evidence is not None
    assert evidence.list_error is not None
    outcomes = _outcomes(auditor)
    assert outcomes["skills_list_supported"] is False
    assert outcomes["server_exposes_primitive"] is True


@pytest.mark.parametrize(
    ("page", "expected"),
    [
        (_page(), False),
        ({"skills": [], "resultType": "complete", "nextCursor": "2"}, SKIP_REASON_INSUFFICIENT_DATA),
        ({"skills": []}, SKIP_REASON_INSUFFICIENT_DATA),
    ],
    ids=["stateless-whole-empty", "stateless-more-pages", "stateless-no-result-type"],
)
async def test_both_declared_empty_catalog_needs_both_lifecycles_whole(
    discover, monkeypatch, page: dict[str, Any], expected: bool | str
) -> None:
    # Discover leaves resources out: a resources catalog it declared would stay unproven on its own.
    discover({"extensions": SKILLS})
    _stateless(monkeypatch, FakeSession([page]))
    auditor = MCPAuditor()

    await auditor.audit(BothDeclareClient(FakeSession([_page()])))

    assert _outcomes(auditor)["server_exposes_primitive"] == expected


async def test_malformed_session_listing_never_proves_emptiness(discover, monkeypatch) -> None:
    discover({"resources": {}, "extensions": SKILLS})
    _stateless(monkeypatch, FakeSession([_page()]))
    pages = [{"skills": [], "nextCursor": "1", "resultType": "complete"}, {"resultType": "complete"}]
    auditor = MCPAuditor()

    await auditor.audit(BothDeclareClient(FakeSession(pages)))

    evidence = auditor.audit_data.skills
    assert evidence is not None
    assert evidence.list_malformed
    outcomes = _outcomes(auditor)
    assert outcomes["skills_list_supported"] is False
    assert outcomes["server_exposes_primitive"] == SKIP_REASON_INSUFFICIENT_DATA
