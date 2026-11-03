"""Exercise MCP Apps evidence collection and the apps rules (ext-apps specification 2026-01-26)."""

import asyncio
import base64
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from mcp.shared.exceptions import MCPError
from mcp_types import (
    Implementation,
    InitializeResult,
    Resource,
    ServerCapabilities,
    Tool,
)
import pytest

from mcpscore import apps
from mcpscore.apps import (
    UI_EXTENSION,
    UI_EXTENSION_SETTINGS,
    UI_MIME_TYPE,
    AppsEvidence,
    UiContent,
    UiRead,
    collect_apps,
    is_html_document,
    pointer_targets,
    uses_apps,
)
from mcpscore.enums import MCPTransportType
from mcpscore.mcp_auditor import MCPAuditor
from mcpscore.mcp_client import MCPClient
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE, AuditData, RuleSeverity
from mcpscore.rules.registry import create_all_rules

RULES = {rule.rule_id: rule for rule in create_all_rules()}
APPS_RULE_IDS = {rule_id for rule_id in RULES if rule_id.startswith("apps_")}
HTML = "<!DOCTYPE html>\n<html lang='en'><head><title>App</title></head><body></body></html>"
URI = "ui://server/app.html"


def tool(name: str = "show", meta: Any = None) -> Tool:
    return Tool.model_validate({"name": name, "inputSchema": {"type": "object"}, **({"_meta": meta} if meta else {})})


def ui_tool(name: str = "show", uri: Any = URI, **ui: Any) -> Tool:
    return tool(name, {"ui": {"resourceUri": uri, **ui}})


def read(uri: str = URI, *contents: UiContent, error: dict[str, Any] | None = None) -> UiRead:
    return UiRead(uri, list(contents) if contents else ([] if error else [html_content()]), error)


def html_content(mime_type: Any = UI_MIME_TYPE) -> UiContent:
    return UiContent(mime_type, has_text=True, has_blob=False, html_document=True)


def data(tools: list[Tool] | None, reads: list[UiRead] | None = None, **kwargs: Any) -> AuditData:
    evidence = AppsEvidence({r.uri: r for r in reads}) if reads is not None else None
    return AuditData(
        capabilities=ServerCapabilities.model_validate({"tools": {}, "resources": {}}),
        tools=tools,
        apps=evidence,
        **kwargs,
    )


def outcome(rule_id: str, audit_data: AuditData) -> str | bool:
    """Return the rule's skip reason, or whether it passed."""
    rule = RULES[rule_id]
    reason = rule.skip_reason(audit_data)
    return reason if reason is not None else rule.check(audit_data).passed


def issues(rule_id: str, audit_data: AuditData) -> list[dict[str, Any]]:
    return RULES[rule_id].check(audit_data).details.get("issues", [])


class TestHelpers:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            (HTML, True),
            ("﻿<!doctype html><title>t</title>", True),
            ("<!-- built --> <!DOCTYPE HTML>", True),
            ("<html><body></body></html>", True),
            ("  \n<html>", True),
            ("<div>fragment</div>", False),
            ("plain text", False),
            ("text <!DOCTYPE html>", False),
            ('<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN"><svg/>', False),
            ("", False),
            ("<!DOCTYPE html><!DOCTYPE other><html>", True),
        ],
    )
    def test_is_html_document(self, text: str, expected: bool) -> None:
        assert is_html_document(text) is expected

    def test_uses_apps_and_pointer_targets(self) -> None:
        flat = tool("flat", {"ui/resourceUri": "ui://flat"})
        both = tool("both", {"ui": {"resourceUri": URI}, "ui/resourceUri": "ui://old"})
        tools = [tool("plain"), ui_tool(), flat, both, ui_tool("http", "https://example.com/app"), ui_tool("n", 3)]
        assert pointer_targets(tools) == [URI, "ui://flat"]
        assert not uses_apps([tool("plain")], [])
        assert uses_apps(None, [Resource(uri="ui://listed", name="l")])
        assert uses_apps([tool("vis", {"ui": {"visibility": ["app"]}})], None)

    def test_tool_meta_ignores_a_non_object(self) -> None:
        odd = tool()
        odd.meta = "x"  # type: ignore[assignment]
        assert apps.tool_meta(odd) == {}


class FakeSession:
    def __init__(self, contents: dict[str, list[dict[str, Any]]], errors: dict[str, Exception] | None = None) -> None:
        self.contents = contents
        self.errors = errors or {}
        self.reads: list[str] = []

    async def read_resource_contents(self, uri: str) -> list[dict[str, Any]]:
        self.reads.append(uri)
        if uri in self.errors:
            raise self.errors[uri]
        return self.contents.get(uri, [])


class TestCollector:
    async def test_reads_text_and_blob_contents(self) -> None:
        blob = base64.b64encode(HTML.encode("utf-8")).decode("ascii")
        session = FakeSession(
            {
                URI: [{"uri": URI, "mimeType": UI_MIME_TYPE, "text": HTML}],
                "ui://b": [{"uri": "ui://b", "mimeType": UI_MIME_TYPE, "blob": blob}, "not an object"],
                "ui://c": [{"uri": "ui://c", "mimeType": UI_MIME_TYPE, "blob": "!!not base64!!"}],
                "ui://d": [{"uri": "ui://d", "mimeType": UI_MIME_TYPE}],
            }
        )
        tools = [ui_tool(), ui_tool("b", "ui://b"), ui_tool("c", "ui://c"), ui_tool("d", "ui://d")]
        evidence = await collect_apps(session, tools)  # type: ignore[arg-type]
        assert evidence.reads[URI].contents == [
            UiContent(UI_MIME_TYPE, has_text=True, has_blob=False, html_document=True)
        ]
        assert evidence.reads["ui://b"].contents == [
            UiContent(UI_MIME_TYPE, has_text=False, has_blob=True, html_document=True)
        ]
        assert evidence.reads["ui://c"].contents == [
            UiContent(UI_MIME_TYPE, has_text=False, has_blob=True, blob_valid=False)
        ]
        assert evidence.reads["ui://d"].contents == [UiContent(UI_MIME_TYPE, has_text=False, has_blob=False)]
        assert evidence.unread == 0

    async def test_failed_read_is_evidence(self) -> None:
        error = MCPError(code=-32002, message="Resource not found")
        session = FakeSession({}, {URI: error})
        evidence = await collect_apps(session, [ui_tool()])  # type: ignore[arg-type]
        assert evidence.reads[URI].error == {"outcome": "rpc_error", "error_code": -32002}

    async def test_reads_are_capped(self) -> None:
        tools = [ui_tool(f"t{i}", f"ui://{i}") for i in range(apps.MAX_UI_READS + 3)]
        session = FakeSession({})
        evidence = await collect_apps(session, tools)  # type: ignore[arg-type]
        assert len(session.reads) == apps.MAX_UI_READS
        assert evidence.unread == 3

    async def test_collection_deadline_keeps_answers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class Slow(FakeSession):
            async def read_resource_contents(self, uri: str) -> list[dict[str, Any]]:
                if uri == "ui://slow":
                    await asyncio.sleep(10)
                return await super().read_resource_contents(uri)

        monkeypatch.setattr(apps, "COLLECTION_TIMEOUT_S", 0.2)
        session = Slow({URI: [{"uri": URI, "mimeType": UI_MIME_TYPE, "text": HTML}]})
        evidence = await collect_apps(session, [ui_tool(), ui_tool("s", "ui://slow")])  # type: ignore[arg-type]
        assert list(evidence.reads) == [URI]
        assert evidence.unread == 1

    async def test_slow_read_times_out_alone(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class Stalled(FakeSession):
            async def read_resource_contents(self, uri: str) -> list[dict[str, Any]]:
                await asyncio.sleep(10)
                return []

        monkeypatch.setattr(apps, "READ_TIMEOUT_S", 0.05)
        evidence = await collect_apps(Stalled({}), [ui_tool()])  # type: ignore[arg-type]
        assert evidence.reads[URI].error == {"outcome": "timeout"}


class TestGating:
    def test_every_apps_rule_is_registered_in_its_group(self) -> None:
        assert {
            "apps_tool_ui_meta_well_formed",
            "apps_ui_resource_uri_scheme",
            "apps_ui_resource_resolves",
            "apps_ui_resource_mime_type",
            "apps_ui_resource_html_document",
            "apps_tool_ui_pointer_nested",
        } == APPS_RULE_IDS
        assert {RULES[r].group_name for r in APPS_RULE_IDS} == {"apps"}
        assert all(RULES[r].basis for r in APPS_RULE_IDS)

    @pytest.mark.parametrize("rule_id", sorted(APPS_RULE_IDS))
    def test_server_without_apps_skips(self, rule_id: str) -> None:
        assert outcome(rule_id, data([tool()])) == SKIP_REASON_NOT_APPLICABLE
        assert outcome(rule_id, data(None)) == SKIP_REASON_NOT_APPLICABLE

    @pytest.mark.parametrize("rule_id", sorted(APPS_RULE_IDS))
    def test_partial_audit_skips(self, rule_id: str) -> None:
        assert outcome(rule_id, AuditData(tools=[ui_tool()])) == SKIP_REASON_INSUFFICIENT_DATA

    @pytest.mark.parametrize("rule_id", sorted(APPS_RULE_IDS))
    def test_listed_ui_resource_without_ui_tools_skips(self, rule_id: str) -> None:
        audit_data = data([tool()], resources=[Resource(uri="ui://listed", name="l")])
        assert outcome(rule_id, audit_data) == SKIP_REASON_NOT_APPLICABLE

    @pytest.mark.parametrize(
        "rule_id", ["apps_ui_resource_resolves", "apps_ui_resource_mime_type", "apps_ui_resource_html_document"]
    )
    def test_read_rules_skip_without_reads(self, rule_id: str) -> None:
        assert outcome(rule_id, data([ui_tool()])) == SKIP_REASON_INSUFFICIENT_DATA
        assert outcome(rule_id, data([ui_tool()], [])) == SKIP_REASON_INSUFFICIENT_DATA
        assert outcome(rule_id, data([ui_tool("v", None, visibility=["app"])], [])) == SKIP_REASON_NOT_APPLICABLE

    @pytest.mark.parametrize("rule_id", ["apps_ui_resource_mime_type", "apps_ui_resource_html_document"])
    def test_content_rules_skip_when_every_read_failed(self, rule_id: str) -> None:
        audit_data = data([ui_tool()], [read(error={"outcome": "timeout"})])
        assert outcome(rule_id, audit_data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_official_example_shape_passes_everything(self) -> None:
        example = tool("show", {"ui": {"resourceUri": URI, "visibility": ["model", "app"]}, "ui/resourceUri": URI})
        audit_data = data([example, tool("plain")], [read()])
        assert {rule_id: outcome(rule_id, audit_data) for rule_id in APPS_RULE_IDS} == dict.fromkeys(
            APPS_RULE_IDS, True
        )


class TestRules:
    def test_ui_meta_well_formed(self) -> None:
        rule_id = "apps_tool_ui_meta_well_formed"
        assert outcome(rule_id, data([ui_tool(visibility=[])])) is True
        assert outcome(rule_id, data([tool("flat", {"ui/resourceUri": URI})])) is True
        bad = [
            tool("a", {"ui": "ui://x"}),
            ui_tool("b", 7),
            ui_tool("c", visibility="model"),
            ui_tool("d", visibility=["model", "agent"]),
            tool("e", {"ui": {"resourceUri": URI}, "ui/resourceUri": ["ui://x"]}),
        ]
        found = issues(rule_id, data(bad))
        assert [(i["entity_index"], i["reason"]) for i in found] == [
            (0, "not_an_object"),
            (1, "not_a_string"),
            (2, "invalid_visibility"),
            (3, "invalid_visibility"),
            (4, "not_a_string"),
        ]
        assert RULES[rule_id].severity is RuleSeverity.MEDIUM

    def test_uri_scheme(self) -> None:
        rule_id = "apps_ui_resource_uri_scheme"
        assert outcome(rule_id, data([ui_tool("v", None, visibility=["app"])])) == SKIP_REASON_NOT_APPLICABLE
        assert outcome(rule_id, data([ui_tool()])) is True
        audit_data = data([ui_tool("a", "https://example.com/app.html"), tool("b", {"ui/resourceUri": "file:///x"})])
        assert [(i["entity_index"], i["path"]) for i in issues(rule_id, audit_data)] == [
            (0, "/_meta/ui/resourceUri"),
            (1, "/_meta/ui~1resourceUri"),
        ]

    def test_resolves(self) -> None:
        rule_id = "apps_ui_resource_resolves"
        assert outcome(rule_id, data([ui_tool()], [read()])) is True
        failed = data(
            [ui_tool(), ui_tool("b", "ui://b"), ui_tool("c", "ui://c")],
            [
                read(),
                read("ui://b", error={"outcome": "rpc_error", "error_code": -32002}),
                UiRead("ui://c"),
            ],
        )
        result = RULES[rule_id].check(failed)
        assert not result.passed
        assert [(i["entity_index"], i["reason"]) for i in result.details["issues"]] == [
            (1, "read_failed"),
            (2, "empty"),
        ]
        assert result.details["issues"][0]["error_code"] == -32002

    def test_mime_type(self) -> None:
        rule_id = "apps_ui_resource_mime_type"
        assert outcome(rule_id, data([ui_tool()], [read()])) is True
        for wrong in ("text/html", "text/html+mcp", "text/html; profile=mcp-app", None):
            assert outcome(rule_id, data([ui_tool()], [read(URI, html_content(wrong))])) is False

    def test_html_document(self) -> None:
        rule_id = "apps_ui_resource_html_document"
        assert outcome(rule_id, data([ui_tool()], [read()])) is True
        contents = [
            UiContent(UI_MIME_TYPE, has_text=False, has_blob=False),
            UiContent(UI_MIME_TYPE, has_text=False, has_blob=True, blob_valid=False),
            UiContent(UI_MIME_TYPE, has_text=True, has_blob=False, html_document=False),
        ]
        found = issues(rule_id, data([ui_tool()], [read(URI, *contents)]))
        assert [i["reason"] for i in found] == ["no_text_or_blob", "invalid_base64", "not_html_document"]

    def test_pointer_nested(self) -> None:
        rule_id = "apps_tool_ui_pointer_nested"
        assert outcome(rule_id, data([ui_tool()])) == SKIP_REASON_NOT_APPLICABLE
        both = tool("both", {"ui": {"resourceUri": URI}, "ui/resourceUri": URI})
        assert outcome(rule_id, data([both])) is True
        flat = tool("flat", {"ui/resourceUri": URI})
        assert [i["entity_index"] for i in issues(rule_id, data([both, flat]))] == [1]
        assert RULES[rule_id].severity is RuleSeverity.LOW


class AppsClient(MCPClient):
    def __init__(self, tools: list[Tool], session: FakeSession) -> None:
        super().__init__()
        self._init_result = InitializeResult(
            protocol_version="2025-11-25",
            capabilities=ServerCapabilities.model_validate({"tools": {}, "resources": {}}),
            server_info=Implementation(name="s", version="1"),
        )
        self.fake = session
        self._tools = tools
        self.transport_type = MCPTransportType.STREAMABLE_HTTP

    async def initialize(self):
        return self._init_result

    async def list_tools(self):
        return self._tools

    async def list_resources(self):
        return []

    async def list_resource_templates(self):
        return []

    async def read_resource_contents(self, uri: str) -> list[dict[str, Any]]:
        return await self.fake.read_resource_contents(uri)


class TestAuditorWiring:
    async def test_ui_pointers_are_read_and_scored(self) -> None:
        session = FakeSession({URI: [{"uri": URI, "mimeType": "text/html", "text": HTML}]})
        auditor = MCPAuditor()
        await auditor.audit(AppsClient([ui_tool()], session))
        assert session.reads == [URI]
        results = {r.rule_id: r for r in auditor.results}
        assert results["apps_ui_resource_resolves"].passed
        assert not results["apps_ui_resource_mime_type"].passed

    async def test_server_without_ui_tools_is_not_read(self) -> None:
        session = FakeSession({})
        auditor = MCPAuditor()
        await auditor.audit(AppsClient([tool()], session))
        assert auditor.audit_data.apps is None
        assert session.reads == []
        skipped = {s.rule_id: s.reason for s in auditor.skipped_rules}
        assert {skipped[r] for r in APPS_RULE_IDS} == {SKIP_REASON_NOT_APPLICABLE}

    async def test_modern_only_path_reads_on_a_stateless_session(self) -> None:
        session = FakeSession({URI: [{"uri": URI, "mimeType": UI_MIME_TYPE, "text": HTML}]})
        auditor = MCPAuditor()
        auditor.audit_data.tools = [ui_tool()]

        class Opened:
            async def __aenter__(self) -> FakeSession:
                return session

            async def __aexit__(self, *exc: object) -> None:
                return None

        with patch("mcpscore.mcp_auditor.stateless_session", return_value=Opened()):
            await auditor._collect_apps_stateless("https://example.com/mcp")
        assert auditor.audit_data.apps is not None
        assert session.reads == [URI]

    async def test_modern_only_path_survives_a_lost_connection(self) -> None:
        auditor = MCPAuditor()
        auditor.audit_data.tools = [ui_tool()]
        with patch("mcpscore.mcp_auditor.stateless_session", side_effect=ConnectionError("gone")):
            await auditor._collect_apps_stateless("https://example.com/mcp")
        assert auditor.audit_data.apps is None

    async def test_modern_only_path_skips_without_pointers(self) -> None:
        auditor = MCPAuditor()
        auditor.audit_data.tools = [tool()]
        with patch("mcpscore.mcp_auditor.stateless_session") as opened:
            await auditor._collect_apps_stateless("https://example.com/mcp")
        opened.assert_not_called()


async def test_handshake_declares_the_ui_extension() -> None:
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
    assert constructor.call_args.kwargs["extensions"][UI_EXTENSION] == UI_EXTENSION_SETTINGS
    assert UI_EXTENSION_SETTINGS == {"mimeTypes": [UI_MIME_TYPE]}


def failure_cases() -> list[tuple[str, AuditData, str, str]]:
    """One failure per apps rule, with the expected evidence path and a phrase from the repair."""
    return [
        ("apps_tool_ui_meta_well_formed", data([ui_tool(visibility="model")]), "/_meta/ui/visibility",
         '"model" and/or "app"'),
        ("apps_ui_resource_uri_scheme", data([ui_tool(uri="https://example.com/app")]), "/_meta/ui/resourceUri",
         "starts with `ui://`"),
        ("apps_ui_resource_resolves", data([ui_tool()], [read(error={"outcome": "rpc_error", "error_code": -32002})]),
         "", "from `resources/read`"),
        ("apps_ui_resource_mime_type", data([ui_tool()], [read(URI, html_content("text/html"))]),
         "/contents/0/mimeType", UI_MIME_TYPE),
        ("apps_ui_resource_html_document",
         data([ui_tool()], [read(URI, UiContent(UI_MIME_TYPE, has_text=True, has_blob=False, html_document=False))]),
         "/contents/0", "<!DOCTYPE html>"),
        ("apps_tool_ui_pointer_nested", data([tool("flat", {"ui/resourceUri": URI})]), "/_meta/ui/resourceUri",
         "Add `_meta.ui.resourceUri`"),
    ]  # fmt: skip


@pytest.mark.parametrize(
    ("rule_id", "audit", "path", "action"), failure_cases(), ids=lambda v: v if isinstance(v, str) else None
)
def test_failure_has_location_and_repair(rule_id: str, audit: AuditData, path: str, action: str) -> None:
    rule = RULES[rule_id]
    assert rule.skip_reason(audit) is None
    result = rule.check(audit)
    assert not result.passed
    assert result.details is not None
    assert result.details["issues"][0].get("path", "") == path
    assert result.suggested_fix is not None
    assert action in result.suggested_fix
    assert 0 < len(result.suggested_fix) <= 255
    assert result.message.endswith(".")


def test_failure_inventory_covers_every_apps_rule() -> None:
    assert {case[0] for case in failure_cases()} == APPS_RULE_IDS
