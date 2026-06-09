import asyncio
import logging
import ssl
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from mcp.types import InitializeResult, Prompt, Resource, Tool

from .mcp_client import MCPClient
from .rules import AuditData, BaseRule, RuleResult, RuleSeverity, create_all_rules

logger = logging.getLogger(__name__)

TLS_PROBE_TIMEOUT_S = 10
"""Timeout for probing the negotiated TLS version of an HTTPS server."""


class MCPAuditor:
    """Orchestrates the MCP server audit process.

    This class manages the complete audit workflow:
    - Collects initialization data from the MCP server
    - Executes all registered audit rules
    - Tracks audit results and scoring
    - Provides audit summary and reporting

    The auditor uses a rule-based system where each rule checks specific
    aspects of MCP compliance and contributes to an overall audit score.
    """

    def __init__(self) -> None:
        """Initialize a new MCPAuditor instance.

        Sets up the auditor with:
        - Empty audit data container
        - All registered audit rules
        - Zero initial score
        - Empty results list
        """
        super().__init__()
        self.mcp_client: MCPClient | None = None
        self.audit_data: AuditData = AuditData()
        self.score: int = 0
        self.max_score: int = 0
        self.rules: list[BaseRule] = list(create_all_rules())
        self.results: list[RuleResult] = []

    async def audit(self, client: MCPClient) -> tuple[int, int]:
        """Execute the complete audit process for an MCP server.

        Args:
            client: Connected MCPClient instance to audit

        Returns:
            Final audit score (positive for passed rules, negative for failed rules)

        The audit process:
        1. Collects server initialization data
        2. Runs all registered audit rules
        3. Calculates and returns the final score

        """
        self.mcp_client = client
        self.score = 0
        self.max_score = 0

        await self._collect_transport_metadata()
        await self._collect_init_result()
        if self.audit_data.capabilities is not None:
            if self.audit_data.capabilities.tools is not None:
                await self._collect_tools()
            if self.audit_data.capabilities.resources is not None:
                await self._collect_resources()
            if self.audit_data.capabilities.prompts is not None:
                await self._collect_prompts()
        self._run_all_rules()

        return self.score, self.max_score

    def _run_all_rules(self) -> None:
        """Execute all registered audit rules and update the audit score.

        Iterates through all rules, executes each one, logs the results,
        and updates the overall audit score based on rule severity and pass/fail status.
        """
        for rule in sorted(self.rules, key=lambda r: r.sort_order):
            res: RuleResult = rule.check(self.audit_data)
            logger.info(res.message)

            self.max_score += res.severity.value
            if res.passed:
                self.score += res.severity.value

            self.results.append(res)

    async def _collect_transport_metadata(self) -> None:
        """Collect transport and connection metadata from the MCP client.

        Populates audit data with:
        - Transport type (STDIO, HTTP, SSE)
        - URL (for HTTP/SSE connections)
        - TLS information (for HTTPS connections)
        - Connection timing

        This data is used by security and transport audit rules.
        """
        if self.mcp_client is None:
            logger.error("No MCP client to audit")
            return

        # Collect transport metadata from client
        self.audit_data.transport_type = self.mcp_client.transport_type
        self.audit_data.url = self.mcp_client.url
        self.audit_data.connection_time_ms = self.mcp_client.connection_time_ms

        # For HTTPS connections, check TLS
        if self.mcp_client.url and self.mcp_client.url.startswith("https://"):
            # If we successfully connected via HTTPS, TLS is verified
            # (httpx would have failed the connection if cert validation failed)
            self.audit_data.tls_verified = True
            self.audit_data.tls_version = await self._probe_tls_version(self.mcp_client.url)
        elif self.mcp_client.url and self.mcp_client.url.startswith("http://"):
            self.audit_data.tls_verified = False
            self.audit_data.tls_version = None

    @staticmethod
    async def _probe_tls_version(url: str) -> str | None:
        """Probe the TLS version negotiated with an HTTPS server.

        Opens a short-lived TLS connection to the server and reads the
        negotiated protocol version (e.g. "TLSv1.3") from the SSL object.

        Returns:
            The negotiated TLS version string, or None if it could not be
            determined (the TLS rules treat an unknown version leniently).

        """
        parsed = urlparse(url)
        host = parsed.hostname
        if host is None:
            return None
        port = parsed.port or 443

        writer = None
        try:
            context = ssl.create_default_context()
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context),
                timeout=TLS_PROBE_TIMEOUT_S,
            )
            ssl_object = writer.get_extra_info("ssl_object")
            return ssl_object.version() if ssl_object is not None else None
        except Exception as e:  # noqa: BLE001 — probe failure must not abort the audit
            logger.info("Could not probe TLS version for %s: %s", url, e)
            return None
        finally:
            if writer is not None:
                writer.close()

    async def _collect_init_result(self) -> None:
        """Collect initialization data from the MCP server.

        Retrieves the server's initialization result and populates the audit data
        with protocol version, server info, capabilities, and instructions.

        This data is then used by all audit rules to perform their checks.
        """
        if self.mcp_client is None:
            logger.error("No MCP client to audit")
            return

        init_result: InitializeResult | None = await self.mcp_client.initialize()
        if init_result is None:
            logger.error("No Init Result to audit")
            return
        else:
            self.audit_data.protocol_version = str(init_result.protocolVersion)
            self.audit_data.server_info = init_result.serverInfo
            self.audit_data.capabilities = init_result.capabilities
            self.audit_data.instructions = init_result.instructions

    async def _collect_tools(self) -> None:
        """Collect the list of Tools from the MCP server.

        Retrieves the server's Tools and populates the audit data with
        information about them.

        This data is then used by all audit rules to perform their checks.
        """
        if self.mcp_client is None:
            logger.error("No MCP client to audit")
            return

        tools: list[Tool] | None = await self.mcp_client.list_tools()
        if tools is None:
            logger.error("No Tools to audit")
            return
        else:
            self.audit_data.tools = tools

    async def _collect_resources(self) -> None:
        """Collect the list of Resources from the MCP server.

        Retrieves the server's Resources and populates the audit data with
        information about them.

        This data is then used by all audit rules to perform their checks.
        """
        if self.mcp_client is None:
            logger.error("No MCP client to audit")
            return

        resources: list[Resource] | None = await self.mcp_client.list_resources()
        if resources is None:
            logger.error("No Resources to audit")
            return
        else:
            self.audit_data.resources = resources

    async def _collect_prompts(self) -> None:
        """Collect the list of Prompts from the MCP server.

        Retrieves the server's Prompts and populates the audit data with
        information about them.

        This data is then used by all audit rules to perform their checks.
        """
        if self.mcp_client is None:
            logger.error("No MCP client to audit")
            return

        prompts: list[Prompt] | None = await self.mcp_client.list_prompts()
        if prompts is None:
            logger.error("No prompts to audit")
            return
        else:
            self.audit_data.prompts = prompts

    def get_audit_summary(self) -> dict:
        """Generate a comprehensive summary of the audit results.

        Returns:
            Dictionary containing:
            - total: Total number of rules executed
            - passed: Number of rules that passed
            - failed: Number of rules that failed
            - by_severity: Breakdown by severity level (CRITICAL, HIGH, MEDIUM, LOW)
              with counts for total, passed, and failed rules in each category

        """
        return {
            "total": len(self.results),
            "passed": sum(1 for r in self.results if r.passed),
            "failed": sum(1 for r in self.results if not r.passed),
            "by_severity": {
                severity.value: {
                    "total": sum(1 for r in self.results if r.severity == severity),
                    "passed": sum(1 for r in self.results if r.severity == severity and r.passed),
                    "failed": sum(1 for r in self.results if r.severity == severity and not r.passed),
                }
                for severity in RuleSeverity
            },
        }
