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
from pathlib import Path
import signal
import sys

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
# per probe, and the pytest-asyncio loop is function-scoped, so an async
# module fixture would be a scope mismatch. Probing once per mode keeps the
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

    async def test_server_that_answers_nothing_is_also_an_error(self):
        """Silence is not a refusal.

        A legacy server *answers* -32601, which is UNSUPPORTED — a real
        observation. One that closes without a word was never observed
        refusing anything, so it must not be failed at CRITICAL severity by
        the gateway rules.
        """
        params = StdioServerParameters(command=sys.executable, args=["-c", "import sys; sys.stdin.read()"])
        results = await run_stdio_probes(params)

        assert results[PROBE_DISCOVER].outcome is ProbeOutcome.ERROR

    @pytest.mark.parametrize(
        ("label", "args"),
        [
            ("exits before reading", ["-c", "pass"]),
            ("reads then closes", ["-c", "import sys; sys.stdin.read()"]),
        ],
    )
    async def test_outcome_does_not_depend_on_timing(self, label, args):
        """The same server must score the same way every run.

        Writing to a process that has already exited raises on some platforms
        and silently buffers on others, and even on one machine it depends on
        whether the child has finished exiting. That made an identical server
        alternate between ERROR (rules skip) and UNSUPPORTED (gateway rules
        fail it at CRITICAL) — a score that moved run to run. Repeating the
        probe is the only way to see it; a single call passes either way.
        """
        outcomes = set()
        for _ in range(10):
            results = await run_stdio_probes(StdioServerParameters(command=sys.executable, args=args))
            outcomes.add(results[PROBE_DISCOVER].outcome)

        assert outcomes == {ProbeOutcome.ERROR}, f"{label} produced varying outcomes: {outcomes}"


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
    """The one readiness rule whose subject is an HTTP header."""

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


class TestStdioTeardown:
    """A probed server that will not exit must not outlive the audit."""

    STUBBORN_SERVER = (
        "import signal, sys, time\n"
        "signal.signal(signal.SIGTERM, lambda *a: None)\n"  # ignore polite termination
        # Announce readiness only once the handler is installed: signalling a
        # process that has not finished booting kills it by default, which
        # would make this test pass while exercising the wrong branch.
        "sys.stdout.write('ready\\n')\n"
        "sys.stdout.flush()\n"
        "time.sleep(300)\n"
    )

    async def test_a_server_ignoring_sigterm_is_killed(self, monkeypatch):
        """Escalate to SIGKILL rather than leaving a stuck child behind."""
        from mcpscore import probes as probes_module

        monkeypatch.setattr(probes_module, "_TERMINATE_TIMEOUT_S", 0.1)
        monkeypatch.setattr(probes_module, "PROBE_TIMEOUT_S", 0.1)

        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            self.STUBBORN_SERVER,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        assert process.stdout is not None
        # .strip(): Windows translates "\n" to "\r\n" on a text-mode stdout.
        assert (await process.stdout.readline()).strip() == b"ready"

        await probes_module._terminate(process)

        # -SIGKILL, not -SIGTERM: proof the escalation actually happened rather
        # than the child dying politely.
        assert process.returncode == -signal.SIGKILL


class TestTerminateSurvivesPlatformSignalErrors:
    """Signalling an already-exited process raises, and differently per platform.

    POSIX raises `ProcessLookupError`; Windows raises a plain `OSError` (access
    denied) and reports the exit later. An uncaught one escapes `_terminate`,
    which runs in a `finally` — so the child is never reaped and surfaces later
    as `ResourceWarning: subprocess N is still running`, failing the run under
    `filterwarnings = ["error"]` far from the cause.
    """

    class _AlreadyExited:
        """A process object that behaves like a Windows child that just died."""

        def __init__(self, error: OSError) -> None:
            self.returncode = None
            self.stdout = None
            self._error = error
            self.waited = False

        def terminate(self) -> None:
            raise self._error

        async def wait(self) -> int:
            self.waited = True
            self.returncode = 0
            return 0

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(ProcessLookupError(), id="posix-process-lookup"),
            pytest.param(PermissionError(5, "Access is denied"), id="windows-access-denied"),
        ],
    )
    async def test_the_child_is_still_reaped(self, error):
        from mcpscore.probes import _terminate

        process = self._AlreadyExited(error)
        await _terminate(process)  # type: ignore[arg-type]  — a deliberate stand-in

        assert process.waited, "an unreaped child leaks and trips ResourceWarning at GC"
