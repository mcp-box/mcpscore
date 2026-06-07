"""Comprehensive tests for the CLI entry point.

This module tests the command-line interface functionality including:
- Main entry point setup and logging configuration
- Async main execution flow
- Success and error paths
- Command-line argument handling
- Auto-detection of transport types (STDIO, Streamable HTTP, SSE)
- Integration with MCPClient and MCPDoctor
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcpdoctor import MCPClient, MCPDoctor, MCPTransportType
from mcpdoctor.cli import async_main, main

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
    return client


@pytest.fixture
def mock_doctor() -> MagicMock:
    """Create a mock MCPDoctor for testing.

    Returns:
        MagicMock configured with async audit method returning score tuple.

    """
    doctor = MagicMock(spec=MCPDoctor)
    doctor.audit = AsyncMock(return_value=(85, 100))
    return doctor


class TestMain:
    """Tests for the main() entry point function."""

    def test_main_sets_up_logging(self, monkeypatch: MonkeyPatch) -> None:
        """Verify that main() configures logging correctly.

        This test ensures the logging system is initialized with:
        - INFO level logging
        - Simple message format without timestamps/levels
        """
        # Mock asyncio.run to prevent actual execution
        mock_run = MagicMock()
        monkeypatch.setattr("mcpdoctor.cli.asyncio.run", mock_run)

        # Mock logging.basicConfig to verify it's called correctly
        with patch("mcpdoctor.cli.logging.basicConfig") as mock_basic_config:
            main()

            # Verify basicConfig was called with correct parameters
            mock_basic_config.assert_called_once_with(level=logging.INFO, format="%(message)s")

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
        monkeypatch.setattr("mcpdoctor.cli.asyncio.run", mock_run)

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

    @pytest.mark.asyncio
    async def test_async_main_success_with_stdio(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_doctor: MagicMock,
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
        monkeypatch.setattr(sys, "argv", ["mcpdoctor", "/path/to/server.py"])
        mock_client.detect_and_connect = AsyncMock(return_value=(True, MCPTransportType.STDIO))

        with (
            patch("mcpdoctor.cli.MCPClient", return_value=mock_client),
            patch("mcpdoctor.cli.MCPDoctor", return_value=mock_doctor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        assert "Welcome to MCPDoctor!" in caplog.text
        mock_client.detect_and_connect.assert_called_once_with("/path/to/server.py")
        assert "Connected to the MCP server: /path/to/server.py" in caplog.text
        assert "Transport: stdio" in caplog.text
        assert "Starting the audit..." in caplog.text
        mock_doctor.audit.assert_called_once_with(mock_client)
        assert "Audit finished. Final score: 85/100" in caplog.text
        mock_client.cleanup.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_main_success_with_streamable_http(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_doctor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test successful audit workflow with a remote server via Streamable HTTP."""
        monkeypatch.setattr(sys, "argv", ["mcpdoctor", "https://example.com/mcp"])
        mock_client.detect_and_connect = AsyncMock(return_value=(True, MCPTransportType.STREAMABLE_HTTP))

        with (
            patch("mcpdoctor.cli.MCPClient", return_value=mock_client),
            patch("mcpdoctor.cli.MCPDoctor", return_value=mock_doctor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        mock_client.detect_and_connect.assert_called_once_with("https://example.com/mcp")
        assert "Connected to the MCP server: https://example.com/mcp" in caplog.text
        assert "Transport: streamable-http" in caplog.text
        mock_doctor.audit.assert_called_once_with(mock_client)
        mock_client.cleanup.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_main_success_with_sse(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_doctor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test successful audit workflow with a remote server via SSE."""
        monkeypatch.setattr(sys, "argv", ["mcpdoctor", "https://example.com/sse"])
        mock_client.detect_and_connect = AsyncMock(return_value=(True, MCPTransportType.SSE))

        with (
            patch("mcpdoctor.cli.MCPClient", return_value=mock_client),
            patch("mcpdoctor.cli.MCPDoctor", return_value=mock_doctor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        mock_client.detect_and_connect.assert_called_once_with("https://example.com/sse")
        assert "Connected to the MCP server: https://example.com/sse" in caplog.text
        assert "Transport: sse" in caplog.text
        mock_doctor.audit.assert_called_once_with(mock_client)
        mock_client.cleanup.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_main_no_arguments(
        self,
        monkeypatch: MonkeyPatch,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that missing server path argument exits with code 1."""
        monkeypatch.setattr(sys, "argv", ["mcpdoctor"])

        with (
            caplog.at_level(logging.INFO),
            pytest.raises(SystemExit) as exc_info,
        ):
            await async_main()

        assert exc_info.value.code == 1
        assert "Welcome to MCPDoctor!" in caplog.text
        assert "Usage: mcpdoctor <server_path_or_url>" in caplog.text

    @pytest.mark.asyncio
    async def test_async_main_connection_failure(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_doctor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that connection failure exits with code 2."""
        monkeypatch.setattr(sys, "argv", ["mcpdoctor", "/path/to/server.py"])
        mock_client.detect_and_connect = AsyncMock(return_value=(False, None))

        with (
            patch("mcpdoctor.cli.MCPClient", return_value=mock_client),
            patch("mcpdoctor.cli.MCPDoctor", return_value=mock_doctor),
            caplog.at_level(logging.INFO),
            pytest.raises(SystemExit) as exc_info,
        ):
            await async_main()

        assert exc_info.value.code == 2
        assert "Error connecting to the MCP server: /path/to/server.py" in caplog.text
        mock_doctor.audit.assert_not_called()
        mock_client.cleanup.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_main_with_different_server_path(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_doctor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that different server paths are correctly processed."""
        server_path = "/custom/path/to/my_server.js"
        monkeypatch.setattr(sys, "argv", ["mcpdoctor", server_path])

        with (
            patch("mcpdoctor.cli.MCPClient", return_value=mock_client),
            patch("mcpdoctor.cli.MCPDoctor", return_value=mock_doctor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        mock_client.detect_and_connect.assert_called_once_with(server_path)
        assert f"Connected to the MCP server: {server_path}" in caplog.text

    @pytest.mark.asyncio
    async def test_async_main_audit_scores_displayed_correctly(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_doctor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that audit scores are displayed correctly in logs."""
        monkeypatch.setattr(sys, "argv", ["mcpdoctor", "/path/to/server.py"])
        mock_doctor.audit = AsyncMock(return_value=(42, 75))

        with (
            patch("mcpdoctor.cli.MCPClient", return_value=mock_client),
            patch("mcpdoctor.cli.MCPDoctor", return_value=mock_doctor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        assert "Audit finished. Final score: 42/75" in caplog.text

    @pytest.mark.asyncio
    async def test_async_main_creates_fresh_client_and_doctor(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_doctor: MagicMock,
    ) -> None:
        """Test that fresh instances of client and doctor are created."""
        monkeypatch.setattr(sys, "argv", ["mcpdoctor", "/path/to/server.py"])

        with (
            patch("mcpdoctor.cli.MCPClient", return_value=mock_client) as mock_client_cls,
            patch("mcpdoctor.cli.MCPDoctor", return_value=mock_doctor) as mock_doctor_cls,
        ):
            await async_main()

        mock_client_cls.assert_called_once()
        mock_doctor_cls.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_main_cleanup_always_called_on_success(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_doctor: MagicMock,
    ) -> None:
        """Test that cleanup is always called after successful audit."""
        monkeypatch.setattr(sys, "argv", ["mcpdoctor", "/path/to/server.py"])

        with (
            patch("mcpdoctor.cli.MCPClient", return_value=mock_client),
            patch("mcpdoctor.cli.MCPDoctor", return_value=mock_doctor),
        ):
            await async_main()

        mock_client.cleanup.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_main_logs_all_key_steps(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_doctor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that all key steps in the audit process are logged."""
        monkeypatch.setattr(sys, "argv", ["mcpdoctor", "/path/to/server.py"])

        with (
            patch("mcpdoctor.cli.MCPClient", return_value=mock_client),
            patch("mcpdoctor.cli.MCPDoctor", return_value=mock_doctor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        log_messages = [
            "Welcome to MCPDoctor!",
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
        monkeypatch.setattr("mcpdoctor.cli.asyncio.run", mock_run)

        with patch("mcpdoctor.cli.logging.basicConfig") as mock_basic_config:
            main()

            mock_basic_config.assert_called_once_with(level=logging.INFO, format="%(message)s")
            # Close the unawaited coroutine to avoid RuntimeWarning
            mock_run.call_args[0][0].close()

    @pytest.mark.asyncio
    async def test_logging_messages_appear_correctly(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_doctor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Verify that log messages are output correctly during execution."""
        monkeypatch.setattr(sys, "argv", ["mcpdoctor", "/path/to/server.py"])

        with (
            patch("mcpdoctor.cli.MCPClient", return_value=mock_client),
            patch("mcpdoctor.cli.MCPDoctor", return_value=mock_doctor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        assert "Welcome to MCPDoctor!" in caplog.text
        assert "Connected to the MCP server" in caplog.text
        assert "Starting the audit" in caplog.text
        assert "Audit finished" in caplog.text


class TestErrorHandling:
    """Tests for error handling and edge cases."""

    @pytest.mark.asyncio
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
        assert "Usage: mcpdoctor <server_path_or_url>" in caplog.text

    @pytest.mark.asyncio
    async def test_argv_with_only_script_name(
        self,
        monkeypatch: MonkeyPatch,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test handling of argv with only script name (typical no-args case)."""
        monkeypatch.setattr(sys, "argv", ["mcpdoctor"])

        with (
            caplog.at_level(logging.INFO),
            pytest.raises(SystemExit) as exc_info,
        ):
            await async_main()

        assert exc_info.value.code == 1
        assert "Usage: mcpdoctor <server_path_or_url>" in caplog.text

    @pytest.mark.asyncio
    async def test_connection_failure_exits_before_audit(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_doctor: MagicMock,
    ) -> None:
        """Test that connection failure prevents audit execution."""
        monkeypatch.setattr(sys, "argv", ["mcpdoctor", "/path/to/server.py"])
        mock_client.detect_and_connect = AsyncMock(return_value=(False, None))

        with (
            patch("mcpdoctor.cli.MCPClient", return_value=mock_client),
            patch("mcpdoctor.cli.MCPDoctor", return_value=mock_doctor),
            pytest.raises(SystemExit),
        ):
            await async_main()

        mock_doctor.audit.assert_not_called()

    @pytest.mark.asyncio
    async def test_connection_failure_with_url(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_doctor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that connection failure for a URL exits with code 2."""
        monkeypatch.setattr(sys, "argv", ["mcpdoctor", "https://example.com/mcp"])
        mock_client.detect_and_connect = AsyncMock(return_value=(False, None))

        with (
            patch("mcpdoctor.cli.MCPClient", return_value=mock_client),
            patch("mcpdoctor.cli.MCPDoctor", return_value=mock_doctor),
            caplog.at_level(logging.INFO),
            pytest.raises(SystemExit) as exc_info,
        ):
            await async_main()

        assert exc_info.value.code == 2
        assert "Error connecting to the MCP server: https://example.com/mcp" in caplog.text
        mock_doctor.audit.assert_not_called()
        mock_client.cleanup.assert_not_called()


class TestMainGuard:
    """Tests for the __main__ guard."""

    def test_main_guard_calls_main(self) -> None:
        """Test that the __main__ guard properly calls main()."""
        import inspect

        import mcpdoctor.cli

        source = inspect.getsource(mcpdoctor.cli)
        assert 'if __name__ == "__main__":' in source
        assert "    main()" in source


class TestIntegration:
    """Integration tests for the complete CLI workflow."""

    @pytest.mark.asyncio
    async def test_full_workflow_with_multiple_runs(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_doctor: MagicMock,
    ) -> None:
        """Test that multiple CLI runs don't interfere with each other."""
        targets = [
            ("/path/to/server1.py", MCPTransportType.STDIO),
            ("https://example.com/mcp", MCPTransportType.STREAMABLE_HTTP),
            ("https://example.com/sse", MCPTransportType.SSE),
        ]

        for target, transport in targets:
            mock_client.reset_mock()
            mock_doctor.reset_mock()

            mock_client.detect_and_connect = AsyncMock(return_value=(True, transport))
            mock_client.cleanup = AsyncMock()
            mock_doctor.audit = AsyncMock(return_value=(80, 100))

            monkeypatch.setattr(sys, "argv", ["mcpdoctor", target])

            with (
                patch("mcpdoctor.cli.MCPClient", return_value=mock_client),
                patch("mcpdoctor.cli.MCPDoctor", return_value=mock_doctor),
            ):
                await async_main()

            mock_client.detect_and_connect.assert_called_once_with(target)
            mock_doctor.audit.assert_called_once()
            mock_client.cleanup.assert_called_once()

    def test_integration_with_asyncio_run_mocked(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_doctor: MagicMock,
    ) -> None:
        """Test that main() properly integrates with asyncio.run()."""
        monkeypatch.setattr(sys, "argv", ["mcpdoctor", "/path/to/server.py"])

        mock_run = MagicMock()
        monkeypatch.setattr("mcpdoctor.cli.asyncio.run", mock_run)

        with (
            patch("mcpdoctor.cli.MCPClient", return_value=mock_client),
            patch("mcpdoctor.cli.MCPDoctor", return_value=mock_doctor),
        ):
            main()

        mock_run.assert_called_once()
        args = mock_run.call_args[0]
        assert len(args) == 1
        assert hasattr(args[0], "send")  # Coroutine duck-typing
        # Close the unawaited coroutine to avoid RuntimeWarning
        args[0].close()
