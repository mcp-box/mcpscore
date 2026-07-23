"""Comprehensive tests for the CLI entry point.

This module tests the command-line interface functionality including:
- Main entry point setup and logging configuration
- Async main execution flow
- Success and error paths
- Command-line argument handling
- Auto-detection of transport types (STDIO, Streamable HTTP, SSE)
- Integration with MCPClient and MCPAuditor
"""

from __future__ import annotations

from datetime import datetime
import json
import logging
import sys
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcpscore import MCPAuditor, MCPClient, MCPTransportType
from mcpscore.cli import async_main, build_parser, build_report, main

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture
    from _pytest.monkeypatch import MonkeyPatch


@pytest.fixture
def mock_client() -> MagicMock:
    """Create a mock MCPClient for testing.

    Returns:
        MagicMock configured with async methods for detect_and_connect and cleanup.

    """
    client = MagicMock(spec=MCPClient)
    client.detect_and_connect = AsyncMock(return_value=(True, MCPTransportType.STDIO))
    client.cleanup = AsyncMock()
    # Instance attribute (set in __init__) — spec'd mocks don't expose it, so
    # assign explicitly; the partial-audit branch reads it on connect failure.
    client.last_connection_error = None
    return client


@pytest.fixture
def mock_auditor() -> MagicMock:
    """Create a mock MCPAuditor for testing.

    Returns:
        MagicMock configured with async audit method returning score tuple.

    """
    auditor = MagicMock(spec=MCPAuditor)
    auditor.audit = AsyncMock(return_value=(85, 100))
    auditor.audit_modern_only = AsyncMock(return_value=False)
    auditor.get_audit_report = MagicMock(return_value=_report_payload())
    return auditor


def _report_payload(**overrides) -> dict:
    """Complete report dict as returned by MCPAuditor.get_audit_report()."""
    report = {
        "score": 85,
        "max_score": 100,
        "authenticated": False,
        "partial": False,
        "partial_reason": None,
        "summary": {"total": 2, "passed": 1, "failed": 1, "skipped": 0, "by_severity": {}},
        "results": [],
        "skipped_rules": [],
        "spec": {
            "negotiated_version": "2025-11-25",
            "latest_version": "2025-11-25",
            "readiness_target": "2026-07-28",
            "era": "legacy",
        },
        "readiness": {"score": 3, "max_score": 13, "results": []},
    }
    report.update(overrides)
    return report


class TestMain:
    """Tests for the main() entry point function."""

    def test_main_sets_up_logging(self, monkeypatch: MonkeyPatch) -> None:
        """Verify that main() configures logging correctly.

        This test ensures the logging system is initialized with:
        - INFO level logging
        - Simple message format without timestamps/levels
        - Output to stderr (keeping stdout clean for --json reports)
        """
        # Mock asyncio.run to prevent actual execution
        mock_run = MagicMock()
        monkeypatch.setattr("mcpscore.cli.asyncio.run", mock_run)

        # Mock logging.basicConfig to verify it's called correctly
        with patch("mcpscore.cli.logging.basicConfig") as mock_basic_config:
            main()

            # Verify basicConfig was called with correct parameters
            mock_basic_config.assert_called_once_with(level=logging.INFO, format="%(message)s", stream=sys.stderr)

        # Check that asyncio.run was called
        mock_run.assert_called_once()
        # Close the unawaited coroutine to avoid RuntimeWarning
        mock_run.call_args[0][0].close()

    def test_main_calls_asyncio_run_with_async_main(self, monkeypatch: MonkeyPatch) -> None:
        """Verify that main() properly calls asyncio.run with async_main.

        This test ensures the synchronous entry point correctly invokes
        the asynchronous main function via asyncio.run().
        """
        mock_run = MagicMock()
        monkeypatch.setattr("mcpscore.cli.asyncio.run", mock_run)

        main()

        # Verify asyncio.run was called with async_main
        mock_run.assert_called_once()
        # The argument should be a coroutine
        args = mock_run.call_args[0]
        assert len(args) == 1
        # Verify it's a coroutine by checking if it has send/throw/close methods
        assert hasattr(args[0], "send")
        # Close the unawaited coroutine to avoid RuntimeWarning
        args[0].close()


class TestAsyncMain:
    """Tests for the async_main() core logic function."""

    async def test_async_main_success_with_stdio(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test successful audit workflow with a local server (STDIO).

        This test verifies the complete happy path for local .py files:
        1. Welcome message is logged
        2. Auto-detection connects via STDIO
        3. Audit runs and returns scores
        4. Final score is displayed
        5. Client cleanup is called
        """
        monkeypatch.setattr(sys, "argv", ["mcpscore", "/path/to/server.py"])
        mock_client.detect_and_connect = AsyncMock(return_value=(True, MCPTransportType.STDIO))

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        assert "Welcome to MCPScore!" in caplog.text
        mock_client.detect_and_connect.assert_called_once_with("/path/to/server.py")
        assert "Connected to the MCP server: /path/to/server.py" in caplog.text
        assert "Transport: stdio" in caplog.text
        assert "Starting the audit..." in caplog.text
        mock_auditor.audit.assert_called_once_with(mock_client)
        assert "Audit finished. Final score: 85/100" in caplog.text
        mock_client.cleanup.assert_called_once()

    async def test_async_main_success_with_streamable_http(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test successful audit workflow with a remote server via Streamable HTTP."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "https://example.com/mcp"])
        mock_client.detect_and_connect = AsyncMock(return_value=(True, MCPTransportType.STREAMABLE_HTTP))

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        mock_client.detect_and_connect.assert_called_once_with("https://example.com/mcp")
        assert "Connected to the MCP server: https://example.com/mcp" in caplog.text
        assert "Transport: streamable-http" in caplog.text
        mock_auditor.audit.assert_called_once_with(mock_client)
        mock_client.cleanup.assert_called_once()

    async def test_async_main_success_with_sse(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test successful audit workflow with a remote server via SSE."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "https://example.com/sse"])
        mock_client.detect_and_connect = AsyncMock(return_value=(True, MCPTransportType.SSE))

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        mock_client.detect_and_connect.assert_called_once_with("https://example.com/sse")
        assert "Connected to the MCP server: https://example.com/sse" in caplog.text
        assert "Transport: sse" in caplog.text
        mock_auditor.audit.assert_called_once_with(mock_client)
        mock_client.cleanup.assert_called_once()

    async def test_async_main_no_arguments(
        self,
        monkeypatch: MonkeyPatch,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that missing server path argument exits with code 1."""
        monkeypatch.setattr(sys, "argv", ["mcpscore"])

        with (
            caplog.at_level(logging.INFO),
            pytest.raises(SystemExit) as exc_info,
        ):
            await async_main()

        assert exc_info.value.code == 1
        assert "Welcome to MCPScore!" in caplog.text
        assert "Usage error" in caplog.text
        assert "target" in caplog.text

    async def test_async_main_connection_failure(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that connection failure exits with code 2."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "/path/to/server.py"])
        mock_client.detect_and_connect = AsyncMock(return_value=(False, None))

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
            pytest.raises(SystemExit) as exc_info,
        ):
            await async_main()

        assert exc_info.value.code == 2
        assert "Error connecting to the MCP server: /path/to/server.py" in caplog.text
        mock_auditor.audit.assert_not_called()
        # Even a failed connection can leave resources on the exit stack.
        mock_client.cleanup.assert_awaited_once()

    async def test_async_main_with_different_server_path(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that different server paths are correctly processed."""
        server_path = "/custom/path/to/my_server.js"
        monkeypatch.setattr(sys, "argv", ["mcpscore", server_path])

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        mock_client.detect_and_connect.assert_called_once_with(server_path)
        assert f"Connected to the MCP server: {server_path}" in caplog.text

    async def test_async_main_audit_scores_displayed_correctly(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that audit scores are displayed correctly in logs."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "/path/to/server.py"])
        mock_auditor.get_audit_report = MagicMock(return_value=_report_payload(score=42, max_score=75))
        mock_auditor.audit = AsyncMock(return_value=(42, 75))

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        assert "Audit finished. Final score: 42/75" in caplog.text

    async def test_async_main_creates_fresh_client_and_auditor(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
    ) -> None:
        """Test that fresh instances of client and auditor are created."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "/path/to/server.py"])

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client) as mock_client_cls,
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor) as mock_auditor_cls,
        ):
            await async_main()

        mock_client_cls.assert_called_once()
        mock_auditor_cls.assert_called_once()

    async def test_async_main_cleanup_always_called_on_success(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
    ) -> None:
        """Test that cleanup is always called after successful audit."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "/path/to/server.py"])

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
        ):
            await async_main()

        mock_client.cleanup.assert_called_once()

    async def test_async_main_logs_all_key_steps(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that all key steps in the audit process are logged."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "/path/to/server.py"])

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        log_messages = [
            "Welcome to MCPScore!",
            "Connected to the MCP server: /path/to/server.py",
            "Transport: stdio",
            "Starting the audit...",
            "Audit finished. Final score: 85/100",
        ]

        for message in log_messages:
            assert message in caplog.text


class TestLogging:
    """Tests for logging configuration and output."""

    def test_logging_configured_by_main(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Verify that main() configures the logging system."""
        mock_run = MagicMock()
        monkeypatch.setattr("mcpscore.cli.asyncio.run", mock_run)

        with patch("mcpscore.cli.logging.basicConfig") as mock_basic_config:
            main()

            mock_basic_config.assert_called_once_with(level=logging.INFO, format="%(message)s", stream=sys.stderr)
            # Close the unawaited coroutine to avoid RuntimeWarning
            mock_run.call_args[0][0].close()

    async def test_logging_messages_appear_correctly(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Verify that log messages are output correctly during execution."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "/path/to/server.py"])

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        assert "Welcome to MCPScore!" in caplog.text
        assert "Connected to the MCP server" in caplog.text
        assert "Starting the audit" in caplog.text
        assert "Audit finished" in caplog.text


class TestErrorHandling:
    """Tests for error handling and edge cases."""

    async def test_empty_argv_list(
        self,
        monkeypatch: MonkeyPatch,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test handling of empty sys.argv (edge case)."""
        monkeypatch.setattr(sys, "argv", [])

        with (
            caplog.at_level(logging.INFO),
            pytest.raises(SystemExit) as exc_info,
        ):
            await async_main()

        assert exc_info.value.code == 1
        assert "Usage error" in caplog.text

    async def test_argv_with_only_script_name(
        self,
        monkeypatch: MonkeyPatch,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test handling of argv with only script name (typical no-args case)."""
        monkeypatch.setattr(sys, "argv", ["mcpscore"])

        with (
            caplog.at_level(logging.INFO),
            pytest.raises(SystemExit) as exc_info,
        ):
            await async_main()

        assert exc_info.value.code == 1
        assert "Usage error" in caplog.text

    async def test_connection_failure_exits_before_audit(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
    ) -> None:
        """Test that connection failure prevents audit execution."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "/path/to/server.py"])
        mock_client.detect_and_connect = AsyncMock(return_value=(False, None))

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            pytest.raises(SystemExit),
        ):
            await async_main()

        mock_auditor.audit.assert_not_called()

    async def test_connection_failure_with_url(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that connection failure for a URL exits with code 2."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "https://example.com/mcp"])
        mock_client.detect_and_connect = AsyncMock(return_value=(False, None))

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
            pytest.raises(SystemExit) as exc_info,
        ):
            await async_main()

        assert exc_info.value.code == 2
        assert "Error connecting to the MCP server: https://example.com/mcp" in caplog.text
        mock_auditor.audit.assert_not_called()
        # Even a failed connection can leave resources on the exit stack.
        mock_client.cleanup.assert_awaited_once()


class TestMainGuard:
    """Tests for the __main__ guard."""

    def test_main_guard_calls_main(self) -> None:
        """Test that the __main__ guard properly calls main()."""
        import inspect

        import mcpscore.cli

        source = inspect.getsource(mcpscore.cli)
        assert 'if __name__ == "__main__":' in source
        assert "    main()" in source


class TestIntegration:
    """Integration tests for the complete CLI workflow."""

    async def test_full_workflow_with_multiple_runs(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
    ) -> None:
        """Test that multiple CLI runs don't interfere with each other."""
        targets = [
            ("/path/to/server1.py", MCPTransportType.STDIO),
            ("https://example.com/mcp", MCPTransportType.STREAMABLE_HTTP),
            ("https://example.com/sse", MCPTransportType.SSE),
        ]

        for target, transport in targets:
            mock_client.reset_mock()
            mock_auditor.reset_mock()

            mock_client.detect_and_connect = AsyncMock(return_value=(True, transport))
            mock_client.cleanup = AsyncMock()
            mock_auditor.audit = AsyncMock(return_value=(80, 100))

            monkeypatch.setattr(sys, "argv", ["mcpscore", target])

            with (
                patch("mcpscore.cli.MCPClient", return_value=mock_client),
                patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            ):
                await async_main()

            mock_client.detect_and_connect.assert_called_once_with(target)
            mock_auditor.audit.assert_called_once()
            mock_client.cleanup.assert_called_once()

    def test_integration_with_asyncio_run_mocked(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
    ) -> None:
        """Test that main() properly integrates with asyncio.run()."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "/path/to/server.py"])

        mock_run = MagicMock()
        monkeypatch.setattr("mcpscore.cli.asyncio.run", mock_run)

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
        ):
            main()

        mock_run.assert_called_once()
        args = mock_run.call_args[0]
        assert len(args) == 1
        assert hasattr(args[0], "send")  # Coroutine duck-typing
        # Close the unawaited coroutine to avoid RuntimeWarning
        args[0].close()


class TestJSONOutput:
    """Tests for the --json machine-readable report output."""

    @pytest.fixture
    def audit_report(self) -> dict:
        """Audit report payload as returned by MCPAuditor.get_audit_report()."""
        return _report_payload(
            summary={"total": 2, "passed": 1, "failed": 1, "skipped": 0, "by_severity": {}},
            results=[
                {
                    "rule_id": "transport_streamable_http",
                    "rule_name": "Streamable HTTP Transport",
                    "severity": "LOW",
                    "severity_value": 1,
                    "passed": True,
                    "message": "ok",
                    "details": None,
                },
            ],
        )

    async def test_json_flag_emits_report_to_stdout(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        audit_report: dict,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """With --json, stdout contains exactly one parseable JSON report."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "/path/to/server.py", "--json"])
        mock_auditor.get_audit_report = MagicMock(return_value=audit_report)

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
        ):
            await async_main()

        report = json.loads(capsys.readouterr().out)
        assert report["schema_version"] == 1
        assert report["target"] == "/path/to/server.py"
        assert report["transport"] == "stdio"
        assert report["score"] == 85
        assert report["max_score"] == 100
        assert report["results"][0]["rule_id"] == "transport_streamable_http"
        assert "mcpscore_version" in report
        assert "generated_at" in report

    async def test_without_json_flag_stdout_is_empty(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Without --json, nothing is written to stdout (logs go to stderr)."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "/path/to/server.py"])

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
        ):
            await async_main()

        assert capsys.readouterr().out == ""

    async def test_json_flag_with_remote_server(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        audit_report: dict,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The report carries the detected remote transport and target URL."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "https://example.com/mcp", "--json"])
        mock_client.detect_and_connect = AsyncMock(return_value=(True, MCPTransportType.STREAMABLE_HTTP))
        mock_auditor.get_audit_report = MagicMock(return_value=audit_report)

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
        ):
            await async_main()

        report = json.loads(capsys.readouterr().out)
        assert report["target"] == "https://example.com/mcp"
        assert report["transport"] == "streamable-http"

    def test_unknown_option_exits_with_code_1(
        self,
        monkeypatch: MonkeyPatch,
        caplog: LogCaptureFixture,
    ) -> None:
        """Unknown CLI options are usage errors (exit code 1, not argparse's 2)."""
        with (
            caplog.at_level(logging.ERROR),
            pytest.raises(SystemExit) as exc_info,
        ):
            build_parser().parse_args(["/path/to/server.py", "--bogus"])

        assert exc_info.value.code == 1
        assert "Usage error" in caplog.text


class TestBuildReport:
    """Tests for the build_report() helper."""

    def test_build_report_merges_metadata_and_audit_results(self, mock_auditor: MagicMock) -> None:
        """Report contains the metadata envelope plus the auditor's report."""
        mock_auditor.get_audit_report = MagicMock(
            return_value={"score": 10, "max_score": 20, "summary": {}, "results": []},
        )

        report = build_report("/srv.py", MCPTransportType.STDIO, mock_auditor)

        assert report["schema_version"] == 1
        assert report["target"] == "/srv.py"
        assert report["transport"] == "stdio"
        assert report["score"] == 10
        assert report["max_score"] == 20
        assert report["results"] == []
        # generated_at must be a valid ISO-8601 UTC timestamp
        assert datetime.fromisoformat(report["generated_at"]).tzinfo is not None

    def test_build_report_transport_none(self, mock_auditor: MagicMock) -> None:
        """A missing transport is serialized as null, not the string 'None'."""
        mock_auditor.get_audit_report = MagicMock(
            return_value={"score": 0, "max_score": 0, "summary": {}, "results": []},
        )

        report = build_report("/srv.py", None, mock_auditor)

        assert report["transport"] is None

    def test_build_report_is_json_serializable(self, mock_auditor: MagicMock) -> None:
        """The report round-trips through json.dumps without a custom encoder."""
        mock_auditor.get_audit_report = MagicMock(
            return_value={"score": 5, "max_score": 5, "summary": {}, "results": []},
        )

        report = build_report("https://example.com/mcp", MCPTransportType.SSE, mock_auditor)

        assert json.loads(json.dumps(report))["transport"] == "sse"


class TestAsyncMainCleanup:
    """Tests for cleanup guarantees in async_main()."""

    async def test_async_main_cleanup_called_when_audit_raises(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
    ) -> None:
        """Client cleanup must run even when the audit itself raises."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "https://example.com/mcp"])
        mock_auditor.audit = AsyncMock(side_effect=RuntimeError("audit blew up"))

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            pytest.raises(RuntimeError, match="audit blew up"),
        ):
            await async_main()

        mock_client.cleanup.assert_called_once()


class TestModernOnlyFallback:
    async def test_modern_only_server_is_audited_instead_of_exit_2(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """A failed legacy connection falls back to the probe-only modern audit."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "https://modern.example/mcp"])
        mock_client.detect_and_connect = AsyncMock(return_value=(False, None))
        mock_auditor.audit_modern_only = AsyncMock(return_value=True)
        mock_auditor.score = 10
        mock_auditor.max_score = 97

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()  # must not raise SystemExit

        mock_auditor.audit_modern_only.assert_awaited_once_with("https://modern.example/mcp")
        assert "Modern-only MCP server detected" in caplog.text

    async def test_url_without_modern_support_still_exits_2(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["mcpscore", "https://legacy.example/mcp"])
        mock_client.detect_and_connect = AsyncMock(return_value=(False, None))

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            pytest.raises(SystemExit) as exc_info,
        ):
            await async_main()

        assert exc_info.value.code == 2
        mock_auditor.audit_modern_only.assert_awaited_once_with("https://legacy.example/mcp")

    async def test_stdio_target_never_tries_modern_fallback(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["mcpscore", "/path/to/server.py"])
        mock_client.detect_and_connect = AsyncMock(return_value=(False, None))

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            pytest.raises(SystemExit) as exc_info,
        ):
            await async_main()

        assert exc_info.value.code == 2
        mock_auditor.audit_modern_only.assert_not_awaited()

    async def test_modern_only_json_report_is_emitted(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        capsys,
    ) -> None:
        monkeypatch.setattr(sys, "argv", ["mcpscore", "https://modern.example/mcp", "--json"])
        mock_client.detect_and_connect = AsyncMock(return_value=(False, None))
        mock_auditor.audit_modern_only = AsyncMock(return_value=True)
        mock_auditor.score = 10
        mock_auditor.max_score = 97
        mock_auditor.audit_data = MagicMock()
        mock_auditor.audit_data.transport_type = MCPTransportType.STREAMABLE_HTTP
        mock_auditor.get_audit_report.return_value = _report_payload(score=10, max_score=97)

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
        ):
            await async_main()

        report = json.loads(capsys.readouterr().out)
        assert report["target"] == "https://modern.example/mcp"
        assert report["transport"] == str(MCPTransportType.STREAMABLE_HTTP)
        assert report["score"] == 10


class TestLogAuditOutcome:
    async def test_readiness_not_assessed_for_stdio(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """A run with no probe observations logs the not-assessed readiness line."""
        monkeypatch.setattr(sys, "argv", ["mcpscore", "/path/to/server.py"])
        mock_auditor.get_audit_report = MagicMock(
            return_value=_report_payload(readiness={"score": 0, "max_score": 0, "results": [], "skipped": 0})
        )

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        assert "not assessed" in caplog.text


class TestCollectHeaders:
    """Tests for --header / --token / MCPSCORE_TOKEN parsing."""

    def test_parse_header_splits_on_first_colon(self) -> None:
        from mcpscore.cli import parse_header

        assert parse_header("Authorization: Bearer abc") == ("Authorization", "Bearer abc")
        assert parse_header("X-Trace: a:b:c") == ("X-Trace", "a:b:c")

    def test_parse_header_rejects_missing_colon(self) -> None:
        from mcpscore.cli import parse_header

        with pytest.raises(ValueError, match="invalid header"):
            parse_header("nocolon")

    def test_header_error_never_echoes_the_value(self) -> None:
        from mcpscore.cli import build_parser, collect_headers

        # A missing colon can mean the whole argument is a mistyped secret
        # (e.g. "Authorization Bearer <token>"); the error text is logged, so
        # it must identify the bad argument by position, never by content.
        args = build_parser().parse_args(["https://x", "--header", "X-A: 1", "--header", "Authorization supersecret"])
        with pytest.raises(ValueError, match="--header #2") as exc:
            collect_headers(args)
        assert "supersecret" not in str(exc.value)

    def test_collect_headers_empty(self) -> None:
        from mcpscore.cli import build_parser, collect_headers

        args = build_parser().parse_args(["https://x"])
        assert collect_headers(args) == {}

    def test_collect_headers_repeatable_and_token(self, monkeypatch: MonkeyPatch) -> None:
        from mcpscore.cli import build_parser, collect_headers

        monkeypatch.delenv("MCPSCORE_TOKEN", raising=False)
        args = build_parser().parse_args(["https://x", "--header", "X-A: 1", "--header", "X-B: 2", "--token", "tok"])
        assert collect_headers(args) == {"X-A": "1", "X-B": "2", "Authorization": "Bearer tok"}

    def test_explicit_authorization_header_wins_over_token(self, monkeypatch: MonkeyPatch) -> None:
        from mcpscore.cli import build_parser, collect_headers

        monkeypatch.delenv("MCPSCORE_TOKEN", raising=False)
        args = build_parser().parse_args(["https://x", "--header", "Authorization: Custom z", "--token", "tok"])
        assert collect_headers(args) == {"Authorization": "Custom z"}

    def test_token_falls_back_to_env(self, monkeypatch: MonkeyPatch) -> None:
        from mcpscore.cli import build_parser, collect_headers

        monkeypatch.setenv("MCPSCORE_TOKEN", "envtok")
        args = build_parser().parse_args(["https://x"])
        assert collect_headers(args) == {"Authorization": "Bearer envtok"}


class TestAuthCliFlow:
    """Tests for the auth-header and partial-audit CLI wiring."""

    async def test_headers_passed_to_client_and_auditor(
        self, monkeypatch: MonkeyPatch, mock_client: MagicMock, mock_auditor: MagicMock
    ) -> None:
        monkeypatch.delenv("MCPSCORE_TOKEN", raising=False)
        monkeypatch.setattr(sys, "argv", ["mcpscore", "https://x/mcp", "--token", "secret"])
        captured = {}

        def capture_client(**kwargs):
            captured["client_headers"] = kwargs.get("headers")
            return mock_client

        def capture_auditor(**kwargs):
            captured["auditor_headers"] = kwargs.get("headers")
            return mock_auditor

        mock_client.detect_and_connect = AsyncMock(return_value=(True, MCPTransportType.STREAMABLE_HTTP))
        with (
            patch("mcpscore.cli.MCPClient", side_effect=capture_client),
            patch("mcpscore.cli.MCPAuditor", side_effect=capture_auditor),
        ):
            await async_main()

        assert captured["client_headers"] == {"Authorization": "Bearer secret"}
        assert captured["auditor_headers"] == {"Authorization": "Bearer secret"}

    async def test_bad_header_exits_1(self, monkeypatch: MonkeyPatch) -> None:
        monkeypatch.setattr(sys, "argv", ["mcpscore", "https://x/mcp", "--header", "nocolon"])
        with pytest.raises(SystemExit) as exc:
            await async_main()
        assert exc.value.code == 1

    async def test_401_triggers_partial_audit(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        from mcpscore.mcp_client import ConnectionErrorReason, ConnectionFailure

        monkeypatch.setattr(sys, "argv", ["mcpscore", "https://gated.example/mcp"])
        mock_client.detect_and_connect = AsyncMock(return_value=(False, None))
        mock_client.last_connection_error = ConnectionFailure(reason=ConnectionErrorReason.UNAUTHORIZED)
        mock_auditor.audit_modern_only = AsyncMock(return_value=False)
        mock_auditor.audit_partial = AsyncMock(return_value=True)
        mock_auditor.get_audit_report = MagicMock(
            return_value=_report_payload(score=19, max_score=19, partial=True, partial_reason="requires auth")
        )
        mock_auditor.audit_data = MagicMock(transport_type=MCPTransportType.STREAMABLE_HTTP)

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        mock_auditor.audit_partial.assert_awaited_once()
        # The reason describes the completed partial audit, not a hard failure.
        reason = mock_auditor.audit_partial.await_args.kwargs["reason"]
        assert "requires authentication" in reason
        assert "HTTP 401" in reason
        assert "Partial audit" in caplog.text

    async def test_client_cleanup_runs_on_every_exit_path(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
    ) -> None:
        """Early returns (modern-only, partial) and exit-2 must still close the client.

        Failed detection attempts can leave resources on the client's exit
        stack, so cleanup() has to run no matter how async_main() exits.
        """
        from mcpscore.mcp_client import ConnectionErrorReason, ConnectionFailure

        mock_client.detect_and_connect = AsyncMock(return_value=(False, None))
        mock_client.cleanup = AsyncMock()
        mock_auditor.audit_partial = AsyncMock(return_value=True)
        mock_auditor.get_audit_report = MagicMock(return_value=_report_payload(score=1, max_score=1))
        mock_auditor.audit_data = MagicMock(transport_type=None)

        scenarios = [
            # (audit_modern_only result, connection failure, expects SystemExit)
            (True, None, False),  # modern-only early return
            (False, ConnectionFailure(reason=ConnectionErrorReason.UNAUTHORIZED), False),  # partial early return
            (False, ConnectionFailure(reason=ConnectionErrorReason.UNREACHABLE), True),  # exit 2
        ]
        for modern, failure, exits in scenarios:
            mock_client.cleanup.reset_mock()
            mock_client.last_connection_error = failure
            mock_auditor.audit_modern_only = AsyncMock(return_value=modern)
            monkeypatch.setattr(sys, "argv", ["mcpscore", "https://x.example/mcp"])
            with (
                patch("mcpscore.cli.MCPClient", return_value=mock_client),
                patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            ):
                if exits:
                    with pytest.raises(SystemExit):
                        await async_main()
                else:
                    await async_main()
            mock_client.cleanup.assert_awaited_once()

    async def test_partial_audit_emits_json_report(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        capsys,
    ) -> None:
        from mcpscore.mcp_client import ConnectionErrorReason, ConnectionFailure

        monkeypatch.setattr(sys, "argv", ["mcpscore", "https://gated.example/mcp", "--json"])
        mock_client.detect_and_connect = AsyncMock(return_value=(False, None))
        mock_client.last_connection_error = ConnectionFailure(reason=ConnectionErrorReason.UNAUTHORIZED)
        mock_auditor.audit_modern_only = AsyncMock(return_value=False)
        mock_auditor.audit_partial = AsyncMock(return_value=True)
        mock_auditor.get_audit_report = MagicMock(
            return_value=_report_payload(score=19, max_score=19, partial=True, partial_reason="requires auth")
        )
        mock_auditor.audit_data = MagicMock(transport_type=None)

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
        ):
            await async_main()

        report = json.loads(capsys.readouterr().out)
        assert report["target"] == "https://gated.example/mcp"
        assert report["partial"] is True
        assert report["partial_reason"] == "requires auth"

    async def test_rejected_credentials_get_verify_guidance(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        from mcpscore.mcp_client import ConnectionErrorReason, ConnectionFailure

        monkeypatch.delenv("MCPSCORE_TOKEN", raising=False)
        monkeypatch.setattr(sys, "argv", ["mcpscore", "https://gated.example/mcp", "--token", "expired"])
        mock_client.detect_and_connect = AsyncMock(return_value=(False, None))
        mock_client.last_connection_error = ConnectionFailure(reason=ConnectionErrorReason.UNAUTHORIZED)
        mock_auditor.audit_modern_only = AsyncMock(return_value=False)
        mock_auditor.audit_partial = AsyncMock(return_value=True)
        mock_auditor.get_audit_report = MagicMock(
            return_value=_report_payload(score=19, max_score=19, partial=True, partial_reason="rejected")
        )
        mock_auditor.audit_data = MagicMock(transport_type=MCPTransportType.STREAMABLE_HTTP)

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        # Credentials were supplied and refused: the guidance must say so
        # instead of advising the user to pass a token they already passed.
        reason = mock_auditor.audit_partial.await_args.kwargs["reason"]
        assert "rejected the provided credentials" in reason
        assert "HTTP 401" in reason
        assert "pass a token" not in reason
        assert "rejected the provided credentials" in caplog.text

    async def test_non_auth_headers_get_missing_credential_guidance(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """A tracing header is not a credential — a 401 means auth is missing, not rejected.

        Keys off the same predicate as the report's authenticated flag, so the
        log and the report never contradict each other.
        """
        from mcpscore.mcp_client import ConnectionErrorReason, ConnectionFailure

        monkeypatch.delenv("MCPSCORE_TOKEN", raising=False)
        monkeypatch.setattr(sys, "argv", ["mcpscore", "https://gated.example/mcp", "--header", "X-Trace-Id: abc"])
        mock_client.detect_and_connect = AsyncMock(return_value=(False, None))
        mock_client.last_connection_error = ConnectionFailure(reason=ConnectionErrorReason.UNAUTHORIZED)
        mock_auditor.audit_modern_only = AsyncMock(return_value=False)
        mock_auditor.audit_partial = AsyncMock(return_value=True)
        mock_auditor.get_audit_report = MagicMock(
            return_value=_report_payload(score=19, max_score=19, partial=True, partial_reason="requires auth")
        )
        mock_auditor.audit_data = MagicMock(transport_type=MCPTransportType.STREAMABLE_HTTP)

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        reason = mock_auditor.audit_partial.await_args.kwargs["reason"]
        assert "requires authentication" in reason
        assert "pass a token" in reason
        assert "rejected" not in reason
        assert "rejected" not in caplog.text

    async def test_non_auth_failure_still_exits_2(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
    ) -> None:
        from mcpscore.mcp_client import ConnectionErrorReason, ConnectionFailure

        monkeypatch.setattr(sys, "argv", ["mcpscore", "https://down.example/mcp"])
        mock_client.detect_and_connect = AsyncMock(return_value=(False, None))
        mock_client.last_connection_error = ConnectionFailure(reason=ConnectionErrorReason.UNREACHABLE)
        mock_auditor.audit_modern_only = AsyncMock(return_value=False)

        with (
            patch("mcpscore.cli.MCPClient", return_value=mock_client),
            patch("mcpscore.cli.MCPAuditor", return_value=mock_auditor),
            pytest.raises(SystemExit) as exc,
        ):
            await async_main()

        assert exc.value.code == 2
        mock_auditor.audit_partial.assert_not_called()
