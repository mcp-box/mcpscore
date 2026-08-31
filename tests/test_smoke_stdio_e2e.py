"""Real-process smoke-mode test against the stdio fixture server.

Launches ``stdio_smoke_server.py`` as a genuine subprocess over the SDK's
stdio transport and runs the full smoke suite on the live session — the same
path ``mcpscore <target> --smoke`` takes after an audit. Each fixture tool
scripts one verdict, so this proves the checks against a real wire exchange
rather than a scripted session: schema-conforming structuredContent passes,
a schema-violating one fails, accepted invalid arguments fail, rejections
pass, and the unannotated tool is never called (the fixture kills the server
process if it ever is).
"""

from __future__ import annotations

from pathlib import Path
import sys
from typing import TYPE_CHECKING

from mcpscore import MCPClient, StdioCommand
from mcpscore.smoke import (
    CHECK_INVALID_ARGUMENTS,
    CHECK_STRUCTURED_CONTENT,
    CHECK_UNKNOWN_TOOL,
    SmokeReport,
    SmokeVerdict,
    run_smoke_checks,
)

if TYPE_CHECKING:
    import pytest

SERVER = str(Path(__file__).parent / "stdio_smoke_server.py")


async def _run_against_fixture(*, call_all: bool, only_tools: set[str] | None = None) -> SmokeReport:
    client = MCPClient()
    try:
        success, _transport = await client.detect_and_connect(StdioCommand(command=sys.executable, args=(SERVER,)))
        assert success
        tools = await client.list_tools()
        assert tools is not None
        if only_tools is not None:
            tools = [tool for tool in tools if tool.name in only_tools]
        assert client.session is not None
        return await run_smoke_checks(client.session, tools, call_all=call_all)
    finally:
        await client.cleanup()


class TestSmokeRealProcess:
    async def test_verdicts_against_the_fixture_server(self) -> None:
        report = await _run_against_fixture(call_all=False)

        by_subject = {(check.check_id, check.tool_name): check for check in report.checks}

        # honest: conforming structuredContent, proper -32602 rejection.
        assert by_subject[(CHECK_STRUCTURED_CONTENT, "honest")].verdict is SmokeVerdict.PASS
        assert by_subject[(CHECK_INVALID_ARGUMENTS, "honest")].verdict is SmokeVerdict.PASS

        # dishonest: declared outputSchema, non-conforming structuredContent —
        # the quickstart-resources#163 defect, caught only by calling.
        dishonest = by_subject[(CHECK_STRUCTURED_CONTENT, "dishonest")]
        assert dishonest.verdict is SmokeVerdict.FAIL
        assert "not honored" in dishonest.message
        assert by_subject[(CHECK_INVALID_ARGUMENTS, "dishonest")].verdict is SmokeVerdict.PASS

        # sloppy: no outputSchema to verify; accepts schema-invalid arguments.
        assert by_subject[(CHECK_STRUCTURED_CONTENT, "sloppy")].verdict is SmokeVerdict.SKIP
        sloppy = by_subject[(CHECK_INVALID_ARGUMENTS, "sloppy")]
        assert sloppy.verdict is SmokeVerdict.FAIL
        assert "accepted schema-invalid arguments" in sloppy.message

        # writer is unannotated: the safety default skips it (the fixture
        # kills the whole server if it is ever actually called).
        for check_id in (CHECK_STRUCTURED_CONTENT, CHECK_INVALID_ARGUMENTS):
            writer = by_subject[(check_id, "writer")]
            assert writer.verdict is SmokeVerdict.SKIP
            assert "--call-all" in writer.message

        # Unknown tool: rejected with the spec's exemplary -32602.
        unknown = by_subject[(CHECK_UNKNOWN_TOOL, None)]
        assert unknown.verdict is SmokeVerdict.PASS
        assert unknown.details["error_code"] == -32602

        assert (report.passed, report.failed, report.skipped) == (4, 2, 3)

    async def test_call_all_really_calls_the_unannotated_tool(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Prove --call-all lifts the safety default.

        The fixture's writer tool dies on invocation, so the smoke run must
        observe the crashed server rather than report a safety skip.
        """
        from mcpscore import smoke

        # The crashed transport should surface as immediate errors; the
        # shortened deadline is a hang tripwire, not part of the contract.
        monkeypatch.setattr(smoke, "SMOKE_CALL_TIMEOUT_S", 5.0)

        report = await _run_against_fixture(call_all=True, only_tools={"writer"})

        structured = next(check for check in report.checks if check.check_id == CHECK_STRUCTURED_CONTENT)
        assert structured.tool_name == "writer"
        # The call was attempted (no safety skip); the dead process shows up
        # as an unexercisable schema, and the later checks fail on the crash.
        assert "--call-all" not in structured.message
        assert structured.verdict is not SmokeVerdict.PASS
        assert report.failed >= 1
