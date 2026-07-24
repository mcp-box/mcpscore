import asyncio
import logging
import ssl
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from mcp_types import InitializeResult, Prompt, Resource, Tool

from pydantic import ValidationError

from .enums import MCPTransportType
from .mcp_client import MCPClient
from .probes import (
    PROBE_DISCOVER,
    PROBE_STATELESS_LIST,
    detect_era,
    has_modern_support,
    not_applicable_results,
    run_all_probes,
)
from .rules import AuditData, BaseRule, RuleResult, RuleSeverity, SkippedRule, create_all_rules
from .rules.base import READINESS_GROUP, SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE
from .spec import DRAFT, LATEST, Era

logger = logging.getLogger(__name__)

TLS_PROBE_TIMEOUT_S = 10
"""Timeout for probing the negotiated TLS version of an HTTPS server."""


def has_authorization_credential(headers: dict[str, str] | None) -> bool:
    """Whether the header set carries a non-blank Authorization credential.

    The single predicate behind both the report's ``authenticated`` flag and
    the CLI's rejected-credentials messaging — other custom headers (tracing,
    API keys we cannot classify) never count as an auth credential, and a
    blank value (e.g. ``--header 'Authorization:'``) is no credential either.
    """
    return any(name.lower() == "authorization" and value.strip() for name, value in (headers or {}).items())


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

    def __init__(self, headers: dict[str, str] | None = None) -> None:
        """Initialize a new MCPAuditor instance.

        Args:
            headers: Extra HTTP headers for the sessionless probe phase, e.g.
                an ``Authorization`` bearer to probe an auth-gated server.
                Should match the headers passed to the MCPClient. Sensitive —
                never logged or included in the report (only the boolean
                ``authenticated`` flag is reported).

        Sets up the auditor with:
        - Empty audit data container
        - All registered audit rules
        - Zero initial score
        - Empty results list

        """
        super().__init__()
        self.headers: dict[str, str] | None = headers or None
        self.mcp_client: MCPClient | None = None
        self.audit_data: AuditData = AuditData()
        self.score: int = 0
        self.max_score: int = 0
        self.rules: list[BaseRule] = list(create_all_rules())
        self.results: list[RuleResult] = []
        self.skipped_rules: list[SkippedRule] = []

        # Readiness axis: rules in the READINESS_GROUP score here. For
        # legacy servers this stays informative, not punitive; for
        # modern-lifecycle full audits the same points are ALSO counted in
        # the main score (readiness promotion — see _run_all_rules).
        self.readiness_score: int = 0
        self.readiness_max: int = 0
        self.readiness_results: list[RuleResult] = []

        self.era: Era | None = None
        """Lifecycle era(s) the server was observed to support (set during audit)."""

        self.readiness_promoted: bool = False
        """Whether this run counted readiness in the main score (modern-lifecycle
        server, full audit). Recomputed per run in _run_all_rules."""

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
        self._reset_run_state()

        await self._collect_transport_metadata()
        await self._collect_init_result()
        if self.audit_data.capabilities is not None:
            if self.audit_data.capabilities.tools is not None:
                await self._collect_tools()
            if self.audit_data.capabilities.resources is not None:
                await self._collect_resources()
            if self.audit_data.capabilities.prompts is not None:
                await self._collect_prompts()
        await self._collect_probes()
        self.era = detect_era(self.audit_data.protocol_version, self.audit_data.probes)
        self._run_all_rules()

        return self.score, self.max_score

    def _reset_run_state(self) -> None:
        """Reset all per-run state so a reused auditor never leaks a prior run.

        Both audit entry points call this first: scores, results, skipped
        rules, the readiness axis, the detected era, and the collected audit
        data are all per-run.
        """
        self.audit_data = AuditData()
        self.score = 0
        self.max_score = 0
        self.results = []
        self.skipped_rules = []
        self.readiness_score = 0
        self.readiness_max = 0
        self.readiness_results = []
        self.era = None
        self.readiness_promoted = False

    async def audit_modern_only(self, url: str) -> bool:
        """Audit a modern-only HTTP server via probes, without a legacy session.

        A server speaking only the 2026-07-28 stateless lifecycle rejects the
        legacy initialize handshake, so the SDK session cannot connect at all.
        This path probes the URL directly: when the server shows modern
        support, the audit proceeds with session-equivalent data extracted
        from probe payloads (server info and capabilities from
        server/discover, tools from the stateless tools/list).

        Args:
            url: The MCP endpoint URL (http:// or https://)

        Returns:
            True when modern support was observed and the audit ran; False
            when it was not (the caller should treat the original connection
            failure as genuine)

        """
        if not url.startswith(("http://", "https://")):
            return False

        probes = await run_all_probes(url, headers=self.headers)
        if not has_modern_support(probes):
            return False

        self._reset_run_state()

        self.audit_data.probes = probes
        self.audit_data.url = url
        self.audit_data.transport_type = MCPTransportType.STREAMABLE_HTTP
        if url.startswith("https://"):
            # The probes completed over HTTPS with certificate verification
            # (httpx default) — an invalid certificate would have failed them.
            self.audit_data.tls_verified = True
            self.audit_data.tls_version = await self._probe_tls_version(url)
        else:
            self.audit_data.tls_verified = False
            self.audit_data.tls_version = None

        self._populate_from_probe_payloads()
        self.era = detect_era(None, probes)
        self._run_all_rules()
        return True

    async def audit_partial(self, url: str, reason: str) -> bool:
        """Run a partial audit of an HTTP server without a server session.

        For a server that could not be connected to and shows no modern
        support (typically because it is auth-gated), this still scores the
        rules observable without a session: the auth-posture, TLS, transport,
        and discovery rules. Session-dependent rules (server info,
        capabilities, tools, resources, prompts) are skipped as
        insufficient-data rather than failed — the report is marked partial and
        its score is NOT comparable to a full audit's.

        Args:
            url: The MCP endpoint URL (http:// or https://)
            reason: Human-readable reason the full audit was not possible
                (e.g. the connection failure message), recorded in the report.

        Returns:
            True when the partial audit ran; False for a non-HTTP url.

        """
        if not url.startswith(("http://", "https://")):
            return False

        self._reset_run_state()
        self.audit_data.partial = True
        self.audit_data.partial_reason = reason
        self.audit_data.url = url
        # No session connected, so the transport is not verified — leave it
        # None. The transport rule skips rather than claiming a transport we
        # could not confirm (see StreamableHTTPTransportRule.skip_reason).
        self.audit_data.probes = await run_all_probes(url, headers=self.headers)
        if url.startswith("https://"):
            # The probes reached the server over HTTPS with certificate
            # verification (httpx default), so TLS is verified even though no
            # MCP session was established.
            self.audit_data.tls_verified = True
            self.audit_data.tls_version = await self._probe_tls_version(url)
        else:
            self.audit_data.tls_verified = False
            self.audit_data.tls_version = None

        self.era = detect_era(None, self.audit_data.probes)
        self._run_all_rules()
        return True

    def _populate_from_probe_payloads(self) -> None:
        """Extract session-equivalent audit data from probe payloads (best-effort).

        server/discover carries serverInfo, capabilities, and instructions;
        the stateless tools/list carries the tools. Anything that fails to
        parse stays None — the corresponding rules then report it missing,
        which is accurate from the client's perspective.
        """
        from mcp_types import Implementation, ServerCapabilities, Tool

        probes = self.audit_data.probes or {}

        discover = probes.get(PROBE_DISCOVER)
        if discover is not None and discover.payload is not None:
            payload = discover.payload
            supported = discover.details.get("supported_versions")
            if isinstance(supported, list) and supported and all(isinstance(v, str) for v in supported):
                self.audit_data.protocol_version = max(supported)
            else:
                self.audit_data.protocol_version = (DRAFT or LATEST).version
            self.audit_data.server_info = self._parse_payload_model(Implementation, payload.get("serverInfo"))
            self.audit_data.capabilities = self._parse_payload_model(ServerCapabilities, payload.get("capabilities"))
            instructions = payload.get("instructions")
            self.audit_data.instructions = instructions if isinstance(instructions, str) else None
        else:
            # No discover payload, but the stateless gateway answered — the
            # server effectively speaks the probes' target version.
            self.audit_data.protocol_version = (DRAFT or LATEST).version

        stateless = probes.get(PROBE_STATELESS_LIST)
        if stateless is not None and stateless.payload is not None:
            raw_tools = stateless.payload.get("tools")
            if isinstance(raw_tools, list):
                try:
                    self.audit_data.tools = [Tool.model_validate(tool) for tool in raw_tools]
                except ValidationError as e:
                    logger.info("Could not parse tools from the stateless probe payload: %s", e)

    @staticmethod
    def _parse_payload_model(model: type, value: object):
        """Validate a probe-payload fragment into an MCP model, or None."""
        if not isinstance(value, dict):
            return None
        try:
            return model.model_validate(value)
        except ValidationError as e:
            logger.info("Could not parse %s from probe payload: %s", model.__name__, e)
            return None

    def _skipped_for_partial(self, rule: BaseRule) -> bool:
        """Whether a rule must be skipped in a partial audit (no server session).

        A partial audit never established a session, so any rule whose every
        ``@requires_*`` field went uncollected (all ``None``) cannot judge and
        must be skipped as insufficient-data — otherwise it would pass or fail
        the server on absent data (e.g. the error-response rules auto-pass on a
        missing observation, inflating the partial score). Rules that still
        have data to work with (e.g. TLS, which has the url) run normally, and
        full-data rules (auth-posture) gate themselves via skip_reason.
        """
        if not self.audit_data.partial:
            return False
        requires = getattr(rule.check, "_requires", None)
        names: tuple[str, ...] = (requires,) if isinstance(requires, str) else tuple(requires or ())
        if not names or "full_data" in names:
            return False
        return all(getattr(self.audit_data, name, None) is None for name in names)

    def _run_all_rules(self) -> None:
        """Execute all applicable audit rules and update the audit score.

        Iterates through all rules, executes each one, logs the results,
        and updates the overall audit score based on rule severity and pass/fail status.

        Rules whose spec-version range excludes the server's negotiated
        protocol version — or whose skip_reason reports missing/redundant
        observations — are skipped: they contribute to neither score nor
        max_score, and are recorded in skipped_rules so the report shows they
        were considered.

        Rules in the READINESS_GROUP score on the separate readiness axis
        (readiness_score/readiness_max); everything else scores on the main axis.
        A separator line is logged before the first readiness rule so the two
        sections are visually distinct in the streamed output.
        """
        # Readiness promotion (the documented migration in methodology.mdx):
        # a server that negotiates the modern lifecycle gets its readiness
        # rules counted in the MAIN score. Legacy-only servers keep readiness
        # informative — guidance, not punishment. Partial audits are never
        # promoted: their score is already not comparable to a full audit's,
        # and folding a second axis in would make it less interpretable.
        self.readiness_promoted = self.era in (Era.MODERN, Era.DUAL) and not self.audit_data.partial

        readiness_header_emitted = False
        for rule in sorted(self.rules, key=lambda r: r.sort_order):
            if rule.group_name == READINESS_GROUP and not readiness_header_emitted:
                readiness_header_emitted = True
                logger.info("")
                logger.info(
                    "🔭 Readiness checks for MCP %s (%s):",
                    (DRAFT or LATEST).version,
                    "counted in the main score — modern-lifecycle server"
                    if self.readiness_promoted
                    else "informative — not part of the main score",
                )

            skip_reason: str | None = None
            if not rule.applies_to(self.audit_data.protocol_version):
                skip_reason = SKIP_REASON_NOT_APPLICABLE
            elif self._skipped_for_partial(rule):
                skip_reason = SKIP_REASON_INSUFFICIENT_DATA
            else:
                skip_reason = rule.skip_reason(self.audit_data)

            if skip_reason is not None:
                logger.info("⏭️ Skipping rule '%s': %s", rule.rule_id, skip_reason)
                self.skipped_rules.append(
                    SkippedRule(
                        rule_id=rule.rule_id,
                        rule_name=rule.rule_name,
                        reason=skip_reason,
                        group_name=rule.group_name,
                    )
                )
                continue

            res: RuleResult = rule.check(self.audit_data)
            res.rule_id = rule.rule_id
            if rule.basis and (res.details is None or "basis" not in res.details):
                res.details = {**(res.details or {}), "basis": rule.basis}
            logger.info(res.message)

            if rule.group_name == READINESS_GROUP:
                self.readiness_max += res.severity.value
                if res.passed:
                    self.readiness_score += res.severity.value
                self.readiness_results.append(res)
                if self.readiness_promoted:
                    # Same points also count toward the main score; the
                    # readiness sub-report stays populated as the transparent
                    # breakdown of this share of the score.
                    self.max_score += res.severity.value
                    if res.passed:
                        self.score += res.severity.value
            else:
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

    async def _collect_probes(self) -> None:
        """Run the sessionless HTTP probes and store their observations.

        Probes observe spec behaviors outside the negotiated session (e.g.
        2026-07-28 stateless-lifecycle support) — see mcpscore.probes. They
        are HTTP-only: stdio audits record NOT_APPLICABLE results so rules
        can distinguish "not probed" from "not collected".
        """
        url = self.audit_data.url
        if url is None or not url.startswith(("http://", "https://")):
            self.audit_data.probes = not_applicable_results(reason="probes require an HTTP(S) transport")
            return

        self.audit_data.probes = await run_all_probes(url, headers=self.headers)

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
            self.audit_data.protocol_version = str(init_result.protocol_version)
            self.audit_data.server_info = init_result.server_info
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

    def get_audit_report(self) -> dict:
        """Generate a machine-readable report of the full audit.

        Returns:
            Dictionary containing:
            - score: Achieved audit score
            - max_score: Maximum possible score
            - summary: Aggregate pass/fail counts (see get_audit_summary)
            - results: Per-rule results keyed by stable rule_id
              (see RuleResult.to_dict)
            - skipped_rules: Rules considered but not executed (with reason),
              e.g. rules outside the server's spec-version range
            - spec: Negotiated/latest/readiness-target spec versions and the
              observed lifecycle era (legacy / modern / dual-era)
            - readiness: Independent readiness score for the next spec
              revision, with its per-rule results and the counted_in_main flag

        """
        return {
            "score": self.score,
            "max_score": self.max_score,
            # True when the audit sent an Authorization credential (--token or
            # an explicit Authorization --header). Other custom headers (e.g.
            # tracing) do not mark the audit authenticated. Only the flag is
            # reported — header values are never included.
            "authenticated": has_authorization_credential(self.headers),
            # A partial audit ran without a server session (e.g. an auth-gated
            # server): only probe-derived rules scored; session-dependent rules
            # were skipped as insufficient-data. The score is NOT comparable to
            # a full audit's — partial_reason says why.
            "partial": self.audit_data.partial,
            "partial_reason": self.audit_data.partial_reason,
            "summary": self.get_audit_summary(),
            "results": [res.to_dict() for res in self.results],
            "skipped_rules": [s.to_dict() for s in self.skipped_rules],
            "spec": {
                "negotiated_version": self.audit_data.protocol_version,
                "latest_version": LATEST.version,
                "readiness_target": (DRAFT or LATEST).version,
                "era": self.era.value if self.era is not None else None,
            },
            "readiness": {
                "score": self.readiness_score,
                "max_score": self.readiness_max,
                # True when this server negotiates the modern lifecycle and
                # these points are included in the top-level score/max_score
                # (never true for partial audits).
                "counted_in_main": self.readiness_promoted,
                "results": [res.to_dict() for res in self.readiness_results],
                "skipped": sum(1 for s in self.skipped_rules if s.group_name == READINESS_GROUP),
            },
        }

    def get_audit_summary(self) -> dict:
        """Generate a comprehensive summary of the audit results.

        Returns:
            Dictionary containing:
            - total: Total number of main-axis rules executed
            - passed: Number of main-axis rules that passed
            - failed: Number of main-axis rules that failed
            - skipped: Number of main-axis rules considered but not executed
              (readiness-group skips are counted in the report's readiness
              section instead, keeping the summary internally consistent)
            - by_severity: Breakdown by severity level (CRITICAL, HIGH, MEDIUM, LOW)
              with counts for total, passed, and failed rules in each category

        """
        return {
            "total": len(self.results),
            "passed": sum(1 for r in self.results if r.passed),
            "failed": sum(1 for r in self.results if not r.passed),
            "skipped": sum(1 for s in self.skipped_rules if s.group_name != READINESS_GROUP),
            "by_severity": {
                severity.name: {
                    "total": sum(1 for r in self.results if r.severity == severity),
                    "passed": sum(1 for r in self.results if r.severity == severity and r.passed),
                    "failed": sum(1 for r in self.results if r.severity == severity and not r.passed),
                }
                for severity in RuleSeverity
            },
        }
