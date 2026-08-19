"""Probes over the stdio transport.

The bug these cover: probes used to be HTTP-only, so a stdio server that fully
supported the modern (2026-07-28) lifecycle was recorded as having *no* modern
support — every readiness rule skipped for want of data, and the audit still
reported a readiness fraction as though it had looked. Because 2026-07-28
removed the handshake, no ``initialize`` can reveal that support; only a
stateless request can.

These tests launch a real subprocess rather than mocking the transport: the
whole defect lived in the layer between "we know how to ask" and "we actually
asked over this transport", which a mock would step over.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from typing import TextIO

from mcp import StdioServerParameters
import pytest

from mcpscore.enums import MCPTransportType
from mcpscore.probes import (
    GATEWAY_PROBE_IDS,
    HTTP_ONLY_PROBE_IDS,
    PROBE_DISCOVER,
    PROBE_IDS,
    PROBE_MALFORMED_META,
    PROBE_MISSING_RESOURCE,
    PROBE_REMOVED_METHOD,
    PROBE_STATELESS_LIST,
    PROBE_UNKNOWN_METHOD,
    PROBE_UNKNOWN_VERSION,
    ProbeOutcome,
    detect_era,
    has_modern_support,
    run_stdio_probes,
)
from mcpscore.spec import Era

SERVER = str(Path(__file__).parent / "stdio_probe_server.py")


def _params(*, legacy: bool = False) -> StdioServerParameters:
    """Launch parameters for the fixture server, in modern or legacy-only mode."""
    return StdioServerParameters(
        command=sys.executable,
        args=[SERVER],
        env={"MCPSCORE_PROBE_LEGACY": "1"} if legacy else None,
    )


# Module-scoped and synchronous on purpose: each call launches one subprocess
# for the whole probe suite (test_probe_suite_launches_one_sibling_process pins
# that), and the pytest-asyncio loop is function-scoped, so an async module
# fixture would be a scope mismatch. Probing once per mode keeps the
# real-process coverage without paying for it in every test.
@pytest.fixture(scope="module")
def modern_probes():
    return asyncio.run(run_stdio_probes(_params()))


@pytest.fixture(scope="module")
def legacy_probes():
    return asyncio.run(run_stdio_probes(_params(legacy=True)))


class TestModernStdioServer:
    """A stdio server that speaks 2026-07-28 must be observed doing so."""

    def test_modern_support_is_detected(self, modern_probes):
        """The regression: this returned False for every stdio server."""
        assert has_modern_support(modern_probes) is True

    @pytest.mark.parametrize(
        "probe_id",
        [
            PROBE_DISCOVER,
            PROBE_STATELESS_LIST,
            PROBE_MALFORMED_META,
            PROBE_UNKNOWN_VERSION,
            PROBE_MISSING_RESOURCE,
            PROBE_REMOVED_METHOD,
            PROBE_UNKNOWN_METHOD,
        ],
    )
    def test_transport_agnostic_probes_are_judged(self, modern_probes, probe_id):
        """Every non-HTTP probe reaches a verdict — not NOT_APPLICABLE, not ERROR."""
        assert modern_probes[probe_id].outcome is ProbeOutcome.SUPPORTED

    def test_discover_payload_is_captured(self, modern_probes):
        """The DiscoverResult itself is available to the rules, not just an outcome."""
        assert modern_probes[PROBE_DISCOVER].details["supported_versions"] == ["2026-07-28"]

    def test_http_only_probes_are_not_applicable(self, modern_probes):
        """HTTP-specific questions are recorded as inapplicable, never as failures.

        NOT_APPLICABLE and UNSUPPORTED are different claims: the first says the
        question does not exist on this transport, the second that the server
        got it wrong. Only the first is true of a stdio server and an Origin
        header.
        """
        for probe_id in HTTP_ONLY_PROBE_IDS:
            assert modern_probes[probe_id].outcome is ProbeOutcome.NOT_APPLICABLE

    def test_every_probe_id_is_accounted_for(self, modern_probes):
        """No probe silently vanishes — rules index by id and would KeyError."""
        assert set(modern_probes) == set(PROBE_IDS)

    def test_era_is_dual_when_the_handshake_also_worked(self, modern_probes):
        """A stdio server answering both lifecycles is dual-era, not legacy."""
        assert detect_era("2025-11-25", modern_probes) is Era.DUAL

    async def test_auditor_dispatches_stdio_probes_and_reports_dual_era(self, monkeypatch):
        """Regression: the auditor must actually use the retained launch parameters."""
        from mcpscore import mcp_auditor as mcp_auditor_module
        from mcpscore.mcp_auditor import MCPAuditor
        from mcpscore.mcp_client import MCPClient

        # Opt back out of conftest's hermetic stub: this test exists precisely
        # to prove the auditor reaches the real stdio probe runner, and it runs
        # against the local fixture subprocess, not the network.
        monkeypatch.setattr(mcp_auditor_module, "run_stdio_probes", run_stdio_probes)

        client = MCPClient()
        client.stdio_params = _params()
        auditor = MCPAuditor()
        auditor.mcp_client = client
        auditor.audit_data.protocol_version = "2025-11-25"

        await auditor._collect_probes()
        auditor.era = detect_era(auditor.audit_data.protocol_version, auditor.audit_data.probes)

        assert auditor.audit_data.probes[PROBE_DISCOVER].outcome is ProbeOutcome.SUPPORTED
        assert auditor.era is Era.DUAL

    async def test_probe_suite_launches_one_sibling_process(self, monkeypatch):
        """Modern requests are stateless, but do not require one process each.

        Starting the audited command seven times can repeat expensive or
        externally visible startup behavior. The suite needs one connection
        without a legacy handshake, not seven independent processes.
        """
        from mcpscore import probes as probes_module

        real_stdio_client = probes_module.stdio_client
        launches = 0

        @asynccontextmanager
        async def counting_stdio_client(
            params: StdioServerParameters,
            errlog: TextIO,
        ) -> AsyncIterator[tuple[object, object]]:
            nonlocal launches
            launches += 1
            async with real_stdio_client(params, errlog=errlog) as streams:
                yield streams

        monkeypatch.setattr(probes_module, "stdio_client", counting_stdio_client)

        results = await run_stdio_probes(_params())

        assert launches == 1
        assert results[PROBE_DISCOVER].outcome is ProbeOutcome.SUPPORTED


class TestLegacyOnlyStdioServer:
    """The negative case: probing must not manufacture support that isn't there."""

    def test_modern_support_is_absent(self, legacy_probes):
        assert has_modern_support(legacy_probes) is False

    def test_gateway_probes_are_unsupported_not_errors(self, legacy_probes):
        """A refusal is an observation. Recording ERROR would make rules skip."""
        for probe_id in GATEWAY_PROBE_IDS:
            assert legacy_probes[probe_id].outcome is ProbeOutcome.UNSUPPORTED

    def test_era_stays_legacy(self, legacy_probes):
        assert detect_era("2025-11-25", legacy_probes) is Era.LEGACY


class TestProbeFailureIsData:
    """A server that cannot be launched or does not answer is not an exception."""

    async def test_unlaunchable_command_yields_error_outcomes(self):
        """Probes never raise: a missing executable is ERROR, so rules skip."""
        params = StdioServerParameters(command="mcpscore-does-not-exist", args=[])
        results = await run_stdio_probes(params)

        assert set(results) == set(PROBE_IDS)
        for probe_id in set(PROBE_IDS) - HTTP_ONLY_PROBE_IDS:
            assert results[probe_id].outcome is ProbeOutcome.ERROR

    async def test_process_that_dies_before_answering_is_an_error(self):
        """Losing the pipe is "could not verify", so dependent rules skip.

        Not UNSUPPORTED: we never observed the server refusing anything, and
        recording a refusal we did not see is the same category of mistake as
        the HTTP-only gap this whole change fixes.
        """
        params = StdioServerParameters(command=sys.executable, args=["-c", "pass"])
        results = await run_stdio_probes(params)

        assert results[PROBE_DISCOVER].outcome is ProbeOutcome.ERROR


class TestHttpStatusIsTransportAware:
    """Paired 'JSON-RPC code AND HTTP status' requirements over a transport with no status."""

    def test_absent_status_satisfies_the_http_half(self):
        from mcpscore.probes import _http_status_is, _ProbeResponse

        stdio = _ProbeResponse(status_code=None, headers={}, payload=None)
        assert _http_status_is(stdio, 400) is True

    def test_present_status_is_still_compared(self):
        from mcpscore.probes import _http_status_is, _ProbeResponse

        assert _http_status_is(_ProbeResponse(200, {}, None), 400) is False
        assert _http_status_is(_ProbeResponse(400, {}, None), 400) is True


class TestContentTypeRuleOnStdio:
    """HTTP-only readiness rules keep the probe's not-applicable semantics."""

    def test_skips_on_stdio(self, monkeypatch):
        """A stdio server sends no Content-Type; that is not a finding.

        Without this the rule failed every modern stdio server for the absence
        of a header the transport cannot send.
        """
        from mcpscore.rules import AuditData
        from mcpscore.rules.base import SKIP_REASON_NOT_APPLICABLE
        from mcpscore.rules.readiness import ResponseContentTypeRule

        audit_data = AuditData()
        audit_data.transport_type = MCPTransportType.STDIO

        assert ResponseContentTypeRule().skip_reason(audit_data) == SKIP_REASON_NOT_APPLICABLE

    def test_probe_backed_http_rules_skip_as_not_applicable(self, modern_probes):
        """HTTP-only probes are not missing data on stdio; their subject is absent."""
        from mcpscore.rules import AuditData
        from mcpscore.rules.base import SKIP_REASON_NOT_APPLICABLE
        from mcpscore.rules.readiness import (
            HeaderValidationReadinessRule,
            NoSessionIdReadinessRule,
            OriginValidationRule,
        )

        audit_data = AuditData(probes=modern_probes)
        audit_data.transport_type = MCPTransportType.STDIO

        for rule in (HeaderValidationReadinessRule(), NoSessionIdReadinessRule(), OriginValidationRule()):
            assert rule.skip_reason(audit_data) == SKIP_REASON_NOT_APPLICABLE


class TestStdioFraming:
    """What arrives on stdout before the answer must not be mistaken for it."""

    NOISY_SERVER = (
        "import json, sys\n"
        "sys.stdin.readline()\n"
        # A plain log line, then a notification (no id), then the real answer.
        "sys.stdout.write('starting up, not JSON\\n')\n"
        "sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'method': 'notifications/ready'}) + '\\n')\n"
        "sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': "
        "{'supportedVersions': ['2026-07-28'], 'resultType': 'complete'}}) + '\\n')\n"
        "sys.stdout.flush()\n"
    )

    async def test_noise_before_the_response_is_skipped(self):
        """Servers log to stdout and send notifications; neither is the reply.

        Taking the first line would read 'starting up, not JSON' as a malformed
        response and report the server as lacking support it has.
        """
        params = StdioServerParameters(command=sys.executable, args=["-c", self.NOISY_SERVER])
        results = await run_stdio_probes(params)

        assert results[PROBE_DISCOVER].outcome is ProbeOutcome.SUPPORTED
        assert results[PROBE_DISCOVER].details["supported_versions"] == ["2026-07-28"]
