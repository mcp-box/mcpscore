import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from mcpscore import MCPAuditor, MCPClient
from mcpscore.rules import AuditData, BaseRule, RuleResult, RuleSeverity


class DummyClient(MCPClient):
    def __init__(
        self,
        init_result: Any | None,
        tools: list[Any] | None = None,
        resources: list[Any] | None = None,
        prompts: list[Any] | None = None,
        url: str | None = None,
        transport_type: str = "streamable-http",
    ) -> None:
        super().__init__()
        self._init_result = init_result
        self._tools = tools
        self._resources = resources
        self._prompts = prompts
        self.url = url
        self.transport_type = transport_type  # type: ignore[assignment]
        self.connection_time_ms = 100

    async def initialize(self):
        return self._init_result

    async def list_tools(self):
        return self._tools

    async def list_resources(self):
        return self._resources

    async def list_prompts(self):
        return self._prompts


class DummyRule(BaseRule):
    rule_id = "dummy_rule"
    group_order = 0
    rule_order = 0

    def __init__(self, passed: bool, severity: RuleSeverity) -> None:
        super().__init__()
        self._passed = passed
        self._severity = severity

    @property
    def sort_order(self) -> int:
        return 0

    @property
    def rule_name(self) -> str:
        return "dummy"

    @property
    def severity(self) -> RuleSeverity:
        return self._severity

    def check(self, audit_data: AuditData) -> RuleResult:
        return RuleResult(
            rule_name=self.rule_name,
            severity=self.severity,
            passed=self._passed,
            message="msg",
        )


async def test_auditor_collects_data_and_scores():
    """Test that the auditor properly collects server data and calculates audit scores.

    This test verifies that:
    - The auditor can process initialization results from MCP servers
    - Rule execution affects the final audit score correctly
    - Passed rules add points, failed rules subtract points
    - The audit summary provides accurate counts of passed/failed rules
    """

    class InitResult:
        def __init__(self) -> None:
            super().__init__()
            self.protocolVersion = "2025-06-18"
            self.serverInfo = type("Impl", (), {"name": "n", "title": "t", "version": "1"})()
            self.capabilities = type(
                "Caps",
                (),
                {"tools": None, "resources": None, "prompts": None, "logging": None, "sampling": None},
            )()
            self.instructions = "instr"

    auditor = MCPAuditor()
    auditor.rules = [
        DummyRule(passed=True, severity=RuleSeverity.HIGH),
        DummyRule(passed=False, severity=RuleSeverity.MEDIUM),
    ]

    score, max_score = await auditor.audit(DummyClient(InitResult()))
    # Score is sum of passed rules' severity values
    assert score == RuleSeverity.HIGH
    # Max score is sum of all rules' severity values
    assert max_score == (RuleSeverity.HIGH + RuleSeverity.MEDIUM)

    summary = auditor.get_audit_summary()
    assert summary["total"] == 2
    assert summary["passed"] == 1
    assert summary["failed"] == 1


async def test_auditor_with_tools_capability():
    """Test that auditor collects tools when tools capability is present.

    Verifies that:
    - When capabilities.tools is not None, _collect_tools() is called
    - Tools data is collected and stored in audit_data
    """

    class InitResult:
        def __init__(self) -> None:
            super().__init__()
            self.protocolVersion = "2025-06-18"
            self.serverInfo = type("Impl", (), {"name": "n", "title": "t", "version": "1"})()
            # Tools capability is present (empty dict signals capability exists)
            self.capabilities = type(
                "Caps",
                (),
                {"tools": {}, "resources": None, "prompts": None, "logging": None, "sampling": None},
            )()
            self.instructions = "instr"

    class Tool:
        def __init__(self) -> None:
            super().__init__()
            self.name = "test_tool"
            self.description = "A test tool"

    tools = [Tool()]
    auditor = MCPAuditor()
    auditor.rules = []

    await auditor.audit(DummyClient(InitResult(), tools=tools))

    assert auditor.audit_data.tools == tools


async def test_auditor_with_resources_capability():
    """Test that auditor collects resources when resources capability is present.

    Verifies that:
    - When capabilities.resources is not None, _collect_resources() is called
    - Resources data is collected and stored in audit_data
    """

    class InitResult:
        def __init__(self) -> None:
            super().__init__()
            self.protocolVersion = "2025-06-18"
            self.serverInfo = type("Impl", (), {"name": "n", "title": "t", "version": "1"})()
            # Resources capability is present
            self.capabilities = type(
                "Caps",
                (),
                {"tools": None, "resources": {}, "prompts": None, "logging": None, "sampling": None},
            )()
            self.instructions = "instr"

    class Resource:
        def __init__(self) -> None:
            super().__init__()
            self.uri = "test://resource"
            self.name = "Test Resource"

    resources = [Resource()]
    auditor = MCPAuditor()
    auditor.rules = []

    await auditor.audit(DummyClient(InitResult(), resources=resources))

    assert auditor.audit_data.resources == resources


async def test_auditor_with_prompts_capability():
    """Test that auditor collects prompts when prompts capability is present.

    Verifies that:
    - When capabilities.prompts is not None, _collect_prompts() is called
    - Prompts data is collected and stored in audit_data
    """

    class InitResult:
        def __init__(self) -> None:
            super().__init__()
            self.protocolVersion = "2025-06-18"
            self.serverInfo = type("Impl", (), {"name": "n", "title": "t", "version": "1"})()
            # Prompts capability is present
            self.capabilities = type(
                "Caps",
                (),
                {"tools": None, "resources": None, "prompts": {}, "logging": None, "sampling": None},
            )()
            self.instructions = "instr"

    class Prompt:
        def __init__(self) -> None:
            super().__init__()
            self.name = "test_prompt"
            self.description = "A test prompt"

    prompts = [Prompt()]
    auditor = MCPAuditor()
    auditor.rules = []

    await auditor.audit(DummyClient(InitResult(), prompts=prompts))

    assert auditor.audit_data.prompts == prompts


async def test_auditor_with_all_capabilities():
    """Test that auditor collects all data when all capabilities are present.

    Verifies that:
    - All collection methods are called when all capabilities are present
    - All data types are properly collected and stored
    """

    class InitResult:
        def __init__(self) -> None:
            super().__init__()
            self.protocolVersion = "2025-06-18"
            self.serverInfo = type("Impl", (), {"name": "n", "title": "t", "version": "1"})()
            # All capabilities present
            self.capabilities = type(
                "Caps",
                (),
                {"tools": {}, "resources": {}, "prompts": {}, "logging": None, "sampling": None},
            )()
            self.instructions = "instr"

    class Tool:
        def __init__(self) -> None:
            super().__init__()
            self.name = "test_tool"

    class Resource:
        def __init__(self) -> None:
            super().__init__()
            self.uri = "test://resource"

    class Prompt:
        def __init__(self) -> None:
            super().__init__()
            self.name = "test_prompt"

    tools = [Tool()]
    resources = [Resource()]
    prompts = [Prompt()]

    auditor = MCPAuditor()
    auditor.rules = []

    await auditor.audit(DummyClient(InitResult(), tools=tools, resources=resources, prompts=prompts))

    assert auditor.audit_data.tools == tools
    assert auditor.audit_data.resources == resources
    assert auditor.audit_data.prompts == prompts


async def test_auditor_with_no_capabilities():
    """Test that auditor handles minimal server with no capabilities.

    Verifies that:
    - auditor works with servers that have None capabilities
    - No collection methods are called
    - Audit completes successfully
    """

    class InitResult:
        def __init__(self) -> None:
            super().__init__()
            self.protocolVersion = "2025-06-18"
            self.serverInfo = type("Impl", (), {"name": "n", "title": "t", "version": "1"})()
            self.capabilities = None  # No capabilities
            self.instructions = None

    auditor = MCPAuditor()
    auditor.rules = []

    score, max_score = await auditor.audit(DummyClient(InitResult()))

    assert score == 0
    assert max_score == 0
    # When capabilities is None, collection methods are not called, so fields remain None
    assert auditor.audit_data.tools is None
    assert auditor.audit_data.resources is None
    assert auditor.audit_data.prompts is None


async def test_auditor_https_tls_detection():
    """Test that auditor properly detects TLS for HTTPS URLs.

    Verifies that:
    - HTTPS URLs are detected
    - TLS verification is marked as True
    - TLS version is probed and populated
    """

    class InitResult:
        def __init__(self) -> None:
            super().__init__()
            self.protocolVersion = "2025-06-18"
            self.serverInfo = type("Impl", (), {"name": "n", "title": "t", "version": "1"})()
            self.capabilities = None
            self.instructions = None

    auditor = MCPAuditor()
    auditor.rules = []

    with patch.object(MCPAuditor, "_probe_tls_version", AsyncMock(return_value="TLSv1.3")) as mock_probe:
        await auditor.audit(DummyClient(InitResult(), url="https://example.com/mcp"))

    mock_probe.assert_awaited_once_with("https://example.com/mcp")
    assert auditor.audit_data.tls_verified is True
    assert auditor.audit_data.tls_version == "TLSv1.3"


async def test_auditor_http_no_tls():
    """Test that auditor properly handles HTTP URLs without TLS.

    Verifies that:
    - HTTP URLs are detected
    - TLS verification is marked as False
    - TLS version is None
    """

    class InitResult:
        def __init__(self) -> None:
            super().__init__()
            self.protocolVersion = "2025-06-18"
            self.serverInfo = type("Impl", (), {"name": "n", "title": "t", "version": "1"})()
            self.capabilities = None
            self.instructions = None

    auditor = MCPAuditor()
    auditor.rules = []

    await auditor.audit(DummyClient(InitResult(), url="http://example.com/mcp"))

    assert auditor.audit_data.tls_verified is False
    assert auditor.audit_data.tls_version is None


async def test_auditor_stdio_no_tls_detection():
    """Test that auditor handles STDIO transport without TLS detection.

    Verifies that:
    - STDIO transport (no URL) is handled correctly
    - TLS fields remain at default values
    """

    class InitResult:
        def __init__(self) -> None:
            super().__init__()
            self.protocolVersion = "2025-06-18"
            self.serverInfo = type("Impl", (), {"name": "n", "title": "t", "version": "1"})()
            self.capabilities = None
            self.instructions = None

    auditor = MCPAuditor()
    auditor.rules = []

    await auditor.audit(DummyClient(InitResult(), url=None, transport_type="stdio"))

    # TLS fields should remain None for STDIO transport
    assert auditor.audit_data.tls_verified is None
    assert auditor.audit_data.tls_version is None


async def test_collect_init_result_with_none_client(caplog):
    """Test error handling when client is None in _collect_init_result.

    Verifies that:
    - Error is logged when mcp_client is None
    - Method returns early without crashing
    """
    auditor = MCPAuditor()
    auditor.mcp_client = None

    await auditor._collect_init_result()

    assert "No MCP client to audit" in caplog.text


async def test_collect_init_result_with_none_result(caplog):
    """Test error handling when initialize() returns None.

    Verifies that:
    - Error is logged when init_result is None
    - Method returns early without populating audit data
    """

    class NoneClient(MCPClient):
        async def initialize(self):
            return None

    auditor = MCPAuditor()
    auditor.mcp_client = NoneClient()

    await auditor._collect_init_result()

    assert "No Init Result to audit" in caplog.text
    assert auditor.audit_data.protocol_version is None


async def test_collect_tools_with_none_client(caplog):
    """Test error handling when client is None in _collect_tools.

    Verifies that:
    - Error is logged when mcp_client is None
    - Method returns early without crashing
    """
    auditor = MCPAuditor()
    auditor.mcp_client = None

    await auditor._collect_tools()

    assert "No MCP client to audit" in caplog.text


async def test_collect_tools_with_none_response(caplog):
    """Test error handling when list_tools() returns None.

    Verifies that:
    - Error is logged when tools response is None
    - Method returns early without populating tools data
    """

    class NoneToolsClient(MCPClient):
        async def list_tools(self):
            return None

    auditor = MCPAuditor()
    auditor.mcp_client = NoneToolsClient()

    await auditor._collect_tools()

    assert "No Tools to audit" in caplog.text
    # When list_tools() returns None, the field remains None (default value)
    assert auditor.audit_data.tools is None


async def test_collect_resources_with_none_client(caplog):
    """Test error handling when client is None in _collect_resources.

    Verifies that:
    - Error is logged when mcp_client is None
    - Method returns early without crashing
    """
    auditor = MCPAuditor()
    auditor.mcp_client = None

    await auditor._collect_resources()

    assert "No MCP client to audit" in caplog.text


async def test_collect_resources_with_none_response(caplog):
    """Test error handling when list_resources() returns None.

    Verifies that:
    - Error is logged when resources response is None
    - Method returns early without populating resources data
    """

    class NoneResourcesClient(MCPClient):
        async def list_resources(self):
            return None

    auditor = MCPAuditor()
    auditor.mcp_client = NoneResourcesClient()

    await auditor._collect_resources()

    assert "No Resources to audit" in caplog.text
    # When list_resources() returns None, the field remains None (default value)
    assert auditor.audit_data.resources is None


async def test_collect_prompts_with_none_client(caplog):
    """Test error handling when client is None in _collect_prompts.

    Verifies that:
    - Error is logged when mcp_client is None
    - Method returns early without crashing
    """
    auditor = MCPAuditor()
    auditor.mcp_client = None

    await auditor._collect_prompts()

    assert "No MCP client to audit" in caplog.text


async def test_collect_prompts_with_none_response(caplog):
    """Test error handling when list_prompts() returns None.

    Verifies that:
    - Error is logged when prompts response is None
    - Method returns early without populating prompts data
    """

    class NonePromptsClient(MCPClient):
        async def list_prompts(self):
            return None

    auditor = MCPAuditor()
    auditor.mcp_client = NonePromptsClient()

    await auditor._collect_prompts()

    assert "No prompts to audit" in caplog.text
    # When list_prompts() returns None, the field remains None (default value)
    assert auditor.audit_data.prompts is None


async def test_get_audit_summary_with_mixed_results():
    """Test audit summary generation with mixed pass/fail results.

    Verifies that:
    - Summary correctly counts total, passed, and failed rules
    - By-severity breakdown is accurate
    """
    auditor = MCPAuditor()
    auditor.results = [
        RuleResult(rule_name="rule1", severity=RuleSeverity.CRITICAL, passed=True, message="pass"),
        RuleResult(rule_name="rule2", severity=RuleSeverity.HIGH, passed=False, message="fail"),
        RuleResult(rule_name="rule3", severity=RuleSeverity.MEDIUM, passed=True, message="pass"),
        RuleResult(rule_name="rule4", severity=RuleSeverity.LOW, passed=False, message="fail"),
    ]

    summary = auditor.get_audit_summary()

    assert summary["total"] == 4
    assert summary["passed"] == 2
    assert summary["failed"] == 2
    assert summary["by_severity"][RuleSeverity.CRITICAL.name]["passed"] == 1
    assert summary["by_severity"][RuleSeverity.HIGH.name]["failed"] == 1
    assert summary["by_severity"][RuleSeverity.MEDIUM.name]["passed"] == 1
    assert summary["by_severity"][RuleSeverity.LOW.name]["failed"] == 1


async def test_get_audit_summary_all_passed():
    """Test audit summary when all rules pass.

    Verifies that:
    - All rules are counted as passed
    - Failed count is zero
    """
    auditor = MCPAuditor()
    auditor.results = [
        RuleResult(rule_name="rule1", severity=RuleSeverity.HIGH, passed=True, message="pass"),
        RuleResult(rule_name="rule2", severity=RuleSeverity.MEDIUM, passed=True, message="pass"),
    ]

    summary = auditor.get_audit_summary()

    assert summary["total"] == 2
    assert summary["passed"] == 2
    assert summary["failed"] == 0


async def test_get_audit_summary_all_failed():
    """Test audit summary when all rules fail.

    Verifies that:
    - All rules are counted as failed
    - Passed count is zero
    """
    auditor = MCPAuditor()
    auditor.results = [
        RuleResult(rule_name="rule1", severity=RuleSeverity.HIGH, passed=False, message="fail"),
        RuleResult(rule_name="rule2", severity=RuleSeverity.MEDIUM, passed=False, message="fail"),
    ]

    summary = auditor.get_audit_summary()

    assert summary["total"] == 2
    assert summary["passed"] == 0
    assert summary["failed"] == 2


async def test_collect_transport_metadata_with_none_client(caplog):
    """Test error handling when client is None in _collect_transport_metadata.

    Verifies that:
    - Error is logged when mcp_client is None
    - Method returns early without crashing
    """
    auditor = MCPAuditor()
    auditor.mcp_client = None

    await auditor._collect_transport_metadata()

    assert "No MCP client to audit" in caplog.text


async def test_auditor_transport_metadata_collection():
    """Test that transport metadata is properly collected.

    Verifies that:
    - Transport type is collected from client
    - URL is collected
    - Connection time is collected
    """

    class InitResult:
        def __init__(self) -> None:
            super().__init__()
            self.protocolVersion = "2025-06-18"
            self.serverInfo = type("Impl", (), {"name": "n", "title": "t", "version": "1"})()
            self.capabilities = None
            self.instructions = None

    auditor = MCPAuditor()
    auditor.rules = []

    with patch.object(MCPAuditor, "_probe_tls_version", AsyncMock(return_value="TLSv1.3")):
        await auditor.audit(DummyClient(InitResult(), url="https://example.com/mcp", transport_type="sse"))

    assert auditor.audit_data.transport_type == "sse"
    assert auditor.audit_data.url == "https://example.com/mcp"
    assert auditor.audit_data.connection_time_ms == 100


async def test_probe_tls_version_returns_negotiated_version():
    """Probe returns the version negotiated on the TLS connection."""
    ssl_object = MagicMock()
    ssl_object.version.return_value = "TLSv1.3"
    writer = MagicMock()
    writer.get_extra_info.return_value = ssl_object

    with patch("mcpscore.mcp_auditor.asyncio.open_connection", AsyncMock(return_value=(MagicMock(), writer))):
        version = await MCPAuditor._probe_tls_version("https://example.com/mcp")

    assert version == "TLSv1.3"
    writer.get_extra_info.assert_called_once_with("ssl_object")
    writer.close.assert_called_once()


async def test_probe_tls_version_no_ssl_object():
    """Probe returns None when the transport exposes no ssl_object."""
    writer = MagicMock()
    writer.get_extra_info.return_value = None

    with patch("mcpscore.mcp_auditor.asyncio.open_connection", AsyncMock(return_value=(MagicMock(), writer))):
        version = await MCPAuditor._probe_tls_version("https://example.com/mcp")

    assert version is None
    writer.close.assert_called_once()


async def test_probe_tls_version_connection_error_returns_none(caplog):
    """Probe failures are logged and yield None instead of raising."""
    with (
        caplog.at_level(logging.INFO),
        patch("mcpscore.mcp_auditor.asyncio.open_connection", AsyncMock(side_effect=OSError("refused"))),
    ):
        version = await MCPAuditor._probe_tls_version("https://example.com/mcp")

    assert version is None
    assert "Could not probe TLS version" in caplog.text


async def test_probe_tls_version_invalid_url_returns_none():
    """Probe returns None for URLs without a hostname."""
    version = await MCPAuditor._probe_tls_version("https://")
    assert version is None


async def test_auditor_stamps_rule_id_on_results():
    """Every result carries the stable rule_id of the rule that produced it.

    Rules construct RuleResult without a rule_id; the auditor stamps it so
    machine consumers (JSON reports, acceptance snapshots) can key on it.
    """
    auditor = MCPAuditor()
    auditor.rules = [DummyRule(passed=True, severity=RuleSeverity.HIGH)]

    await auditor.audit(DummyClient(None))

    assert len(auditor.results) == 1
    assert auditor.results[0].rule_id == "dummy_rule"


def test_rule_result_to_dict():
    """RuleResult.to_dict() serializes all fields with severity name and value."""
    result = RuleResult(
        rule_name="dummy",
        severity=RuleSeverity.MEDIUM,
        passed=False,
        message="msg",
        details={"key": "value"},
        rule_id="dummy_rule",
    )

    assert result.to_dict() == {
        "rule_id": "dummy_rule",
        "rule_name": "dummy",
        "severity": "MEDIUM",
        "severity_value": 2,
        "passed": False,
        "message": "msg",
        "details": {"key": "value"},
    }


async def test_get_audit_report():
    """get_audit_report() bundles score, summary, and per-rule results."""
    auditor = MCPAuditor()
    auditor.rules = [
        DummyRule(passed=True, severity=RuleSeverity.HIGH),
        DummyRule(passed=False, severity=RuleSeverity.MEDIUM),
    ]

    score, max_score = await auditor.audit(DummyClient(None))
    report = auditor.get_audit_report()

    assert report["score"] == score
    assert report["max_score"] == max_score
    assert report["summary"] == auditor.get_audit_summary()
    assert len(report["results"]) == 2
    assert all(res["rule_id"] == "dummy_rule" for res in report["results"])
    assert report["results"][0]["passed"] is True
    assert report["results"][1]["passed"] is False
