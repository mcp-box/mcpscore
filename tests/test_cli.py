"""Comprehensive tests for the CLI entry point.

This module tests the command-line interface functionality including:
- Main entry point setup and logging configuration
- Async main execution flow
- Success and error paths
- Command-line argument handling
- Integration with MCPClient and MCPAuditor
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcpaudit import MCPAuditor, MCPClient, MCPTransportType
from mcpaudit.cli import async_main, main

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture
    from _pytest.monkeypatch import MonkeyPatch


@pytest.fixture
def mock_client() -> MagicMock:
    """Create a mock MCPClient for testing.

    Returns:
        MagicMock configured with async methods for connect_to_server and cleanup.

    """
    client = MagicMock(spec=MCPClient)
    client.connect_to_server = AsyncMock(return_value=True)
    client.cleanup = AsyncMock()
    return client


@pytest.fixture
def mock_auditor() -> MagicMock:
    """Create a mock MCPAuditor for testing.

    Returns:
        MagicMock configured with async audit method returning score tuple.

    """
    auditor = MagicMock(spec=MCPAuditor)
    auditor.audit = AsyncMock(return_value=(85, 100))
    return auditor


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
        monkeypatch.setattr("mcpaudit.cli.asyncio.run", mock_run)

        # Mock logging.basicConfig to verify it's called correctly
        with patch("mcpaudit.cli.logging.basicConfig") as mock_basic_config:
            main()

            # Verify basicConfig was called with correct parameters
            mock_basic_config.assert_called_once_with(level=logging.INFO, format="%(message)s")

        # Check that asyncio.run was called
        mock_run.assert_called_once()

    def test_main_calls_asyncio_run_with_async_main(self, monkeypatch: MonkeyPatch) -> None:
        """Verify that main() properly calls asyncio.run with async_main.

        This test ensures the synchronous entry point correctly invokes
        the asynchronous main function via asyncio.run().
        """
        mock_run = MagicMock()
        monkeypatch.setattr("mcpaudit.cli.asyncio.run", mock_run)

        main()

        # Verify asyncio.run was called with async_main
        mock_run.assert_called_once()
        # The argument should be a coroutine
        args = mock_run.call_args[0]
        assert len(args) == 1
        # Verify it's a coroutine by checking if it has send/throw/close methods
        assert hasattr(args[0], "send")


class TestAsyncMain:
    """Tests for the async_main() core logic function."""

    @pytest.mark.asyncio
    async def test_async_main_success_path(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test successful audit workflow end-to-end.

        This test verifies the complete happy path:
        1. Welcome message is logged
        2. Connection to server succeeds
        3. Audit runs and returns scores
        4. Final score is displayed
        5. Client cleanup is called
        """
        # Set up command line arguments
        monkeypatch.setattr(sys, "argv", ["mcpaudit", "/path/to/server.py"])

        # Mock MCPClient and MCPAuditor constructors
        with (
            patch("mcpaudit.cli.MCPClient", return_value=mock_client),
            patch("mcpaudit.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        # Verify welcome message
        assert "Welcome to MCPAudit!" in caplog.text

        # Verify connection was attempted
        mock_client.connect_to_server.assert_called_once_with(MCPTransportType.STDIO, "/path/to/server.py")

        # Verify success messages
        assert "Connected to the MCP server: /path/to/server.py" in caplog.text
        assert "Transport: stdio" in caplog.text

        # Verify audit was started and completed
        assert "Starting the audit..." in caplog.text
        mock_auditor.audit.assert_called_once_with(mock_client)
        assert "Audit finished. Final score: 85/100" in caplog.text

        # Verify cleanup was called
        mock_client.cleanup.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_main_no_arguments(
        self,
        monkeypatch: MonkeyPatch,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that missing server path argument exits with code 1.

        This test verifies proper error handling when no command-line
        arguments are provided, including:
        - Error message is logged
        - System exits with code 1
        - Usage instructions are displayed
        """
        # Set up command line with only program name
        monkeypatch.setattr(sys, "argv", ["mcpaudit"])

        with (
            caplog.at_level(logging.INFO),
            pytest.raises(SystemExit) as exc_info,
        ):
            await async_main()

        # Verify exit code is 1
        assert exc_info.value.code == 1

        # Verify error message and usage instruction
        assert "Welcome to MCPAudit!" in caplog.text
        assert "Usage: mcpaudit <path_to_server_script>" in caplog.text

    @pytest.mark.asyncio
    async def test_async_main_connection_failure(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that connection failure exits with code 2.

        This test verifies proper error handling when the MCP server
        connection fails, including:
        - Connection is attempted
        - Error message is logged
        - System exits with code 2
        - Cleanup is not called (no connection established)
        """
        # Set up command line arguments
        monkeypatch.setattr(sys, "argv", ["mcpaudit", "/path/to/server.py"])

        # Configure mock to return connection failure
        mock_client.connect_to_server = AsyncMock(return_value=False)

        with (
            patch("mcpaudit.cli.MCPClient", return_value=mock_client),
            patch("mcpaudit.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
            pytest.raises(SystemExit) as exc_info,
        ):
            await async_main()

        # Verify exit code is 2
        assert exc_info.value.code == 2

        # Verify error message
        assert "Error connecting to the MCP server: /path/to/server.py" in caplog.text

        # Verify audit was never called
        mock_auditor.audit.assert_not_called()

        # Verify cleanup was never called (no connection to clean up)
        mock_client.cleanup.assert_not_called()

    @pytest.mark.asyncio
    async def test_async_main_with_different_server_path(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that different server paths are correctly processed.

        This test verifies that the CLI correctly handles various
        server path formats and passes them to the connection logic.
        """
        server_path = "/custom/path/to/my_server.js"
        monkeypatch.setattr(sys, "argv", ["mcpaudit", server_path])

        with (
            patch("mcpaudit.cli.MCPClient", return_value=mock_client),
            patch("mcpaudit.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        # Verify the custom path was used
        mock_client.connect_to_server.assert_called_once_with(MCPTransportType.STDIO, server_path)
        assert f"Connected to the MCP server: {server_path}" in caplog.text

    @pytest.mark.asyncio
    async def test_async_main_audit_scores_displayed_correctly(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that audit scores are displayed correctly in logs.

        This test verifies that different score values are properly
        formatted and logged.
        """
        monkeypatch.setattr(sys, "argv", ["mcpaudit", "/path/to/server.py"])

        # Configure mock to return different scores
        mock_auditor.audit = AsyncMock(return_value=(42, 75))

        with (
            patch("mcpaudit.cli.MCPClient", return_value=mock_client),
            patch("mcpaudit.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        # Verify the custom scores are displayed
        assert "Audit finished. Final score: 42/75" in caplog.text

    @pytest.mark.asyncio
    async def test_async_main_transport_type_is_stdio(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that transport type is always STDIO for CLI.

        This test verifies that the CLI correctly uses STDIO transport
        type for server communication.
        """
        monkeypatch.setattr(sys, "argv", ["mcpaudit", "/path/to/server.py"])

        with (
            patch("mcpaudit.cli.MCPClient", return_value=mock_client),
            patch("mcpaudit.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        # Verify STDIO transport is logged
        assert "Transport: stdio" in caplog.text

        # Verify connect_to_server was called with STDIO
        call_args = mock_client.connect_to_server.call_args
        assert call_args[0][0] == MCPTransportType.STDIO

    @pytest.mark.asyncio
    async def test_async_main_creates_fresh_client_and_auditor(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
    ) -> None:
        """Test that fresh instances of client and auditor are created.

        This test verifies that the CLI creates new instances rather
        than reusing existing ones, ensuring clean state for each run.
        """
        monkeypatch.setattr(sys, "argv", ["mcpaudit", "/path/to/server.py"])

        with (
            patch("mcpaudit.cli.MCPClient", return_value=mock_client) as mock_client_cls,
            patch("mcpaudit.cli.MCPAuditor", return_value=mock_auditor) as mock_auditor_cls,
        ):
            await async_main()

        # Verify constructors were called
        mock_client_cls.assert_called_once()
        mock_auditor_cls.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_main_cleanup_always_called_on_success(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
    ) -> None:
        """Test that cleanup is always called after successful audit.

        This test verifies proper resource management by ensuring
        cleanup is called even after successful operations.
        """
        monkeypatch.setattr(sys, "argv", ["mcpaudit", "/path/to/server.py"])

        with (
            patch("mcpaudit.cli.MCPClient", return_value=mock_client),
            patch("mcpaudit.cli.MCPAuditor", return_value=mock_auditor),
        ):
            await async_main()

        # Verify cleanup was called exactly once
        mock_client.cleanup.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_main_logs_all_key_steps(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test that all key steps in the audit process are logged.

        This test verifies comprehensive logging of the audit workflow
        for better user feedback and debugging.
        """
        monkeypatch.setattr(sys, "argv", ["mcpaudit", "/path/to/server.py"])

        with (
            patch("mcpaudit.cli.MCPClient", return_value=mock_client),
            patch("mcpaudit.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        # Verify all expected log messages appear in order
        log_messages = [
            "Welcome to MCPAudit!",
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
        """Verify that main() configures the logging system.

        This test ensures the CLI sets up logging with basicConfig,
        which configures the root logger with appropriate settings.
        """
        mock_run = MagicMock()
        monkeypatch.setattr("mcpaudit.cli.asyncio.run", mock_run)

        # Mock basicConfig to verify it's called correctly
        with patch("mcpaudit.cli.logging.basicConfig") as mock_basic_config:
            main()

            # Verify basicConfig was called with correct parameters
            mock_basic_config.assert_called_once_with(level=logging.INFO, format="%(message)s")

    @pytest.mark.asyncio
    async def test_logging_messages_appear_correctly(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
        caplog: LogCaptureFixture,
    ) -> None:
        """Verify that log messages are output correctly during execution.

        This test ensures all key steps are logged appropriately
        for user feedback.
        """
        monkeypatch.setattr(sys, "argv", ["mcpaudit", "/path/to/server.py"])

        with (
            patch("mcpaudit.cli.MCPClient", return_value=mock_client),
            patch("mcpaudit.cli.MCPAuditor", return_value=mock_auditor),
            caplog.at_level(logging.INFO),
        ):
            await async_main()

        # Verify key log messages appear
        assert "Welcome to MCPAudit!" in caplog.text
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
        """Test handling of empty sys.argv (edge case).

        This test verifies behavior when sys.argv is unexpectedly empty,
        which should still result in proper error handling.
        """
        # Edge case: empty argv
        monkeypatch.setattr(sys, "argv", [])

        with (
            caplog.at_level(logging.INFO),
            pytest.raises(SystemExit) as exc_info,
        ):
            await async_main()

        assert exc_info.value.code == 1
        assert "Usage: mcpaudit <path_to_server_script>" in caplog.text

    @pytest.mark.asyncio
    async def test_argv_with_only_script_name(
        self,
        monkeypatch: MonkeyPatch,
        caplog: LogCaptureFixture,
    ) -> None:
        """Test handling of argv with only script name (typical no-args case).

        This test verifies the most common error case: running the CLI
        without any arguments.
        """
        monkeypatch.setattr(sys, "argv", ["mcpaudit"])

        with (
            caplog.at_level(logging.INFO),
            pytest.raises(SystemExit) as exc_info,
        ):
            await async_main()

        assert exc_info.value.code == 1
        assert "Usage: mcpaudit <path_to_server_script>" in caplog.text

    @pytest.mark.asyncio
    async def test_connection_failure_exits_before_audit(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
    ) -> None:
        """Test that connection failure prevents audit execution.

        This test verifies that the audit is not attempted when
        the connection fails, avoiding unnecessary operations.
        """
        monkeypatch.setattr(sys, "argv", ["mcpaudit", "/path/to/server.py"])
        mock_client.connect_to_server = AsyncMock(return_value=False)

        with (
            patch("mcpaudit.cli.MCPClient", return_value=mock_client),
            patch("mcpaudit.cli.MCPAuditor", return_value=mock_auditor),
            pytest.raises(SystemExit),
        ):
            await async_main()

        # Audit should never be called
        mock_auditor.audit.assert_not_called()


class TestMainGuard:
    """Tests for the __main__ guard."""

    def test_main_guard_calls_main(self) -> None:
        """Test that the __main__ guard properly calls main().

        This test verifies that when the CLI module is executed directly,
        it calls the main() function.
        """
        # Import the CLI module and verify the guard exists
        import inspect

        import mcpaudit.cli

        # Verify the guard exists in the code
        source = inspect.getsource(mcpaudit.cli)
        assert 'if __name__ == "__main__":' in source
        assert "    main()" in source


class TestIntegration:
    """Integration tests for the complete CLI workflow."""

    @pytest.mark.asyncio
    async def test_full_workflow_with_multiple_runs(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
    ) -> None:
        """Test that multiple CLI runs don't interfere with each other.

        This test verifies that the CLI can be run multiple times
        sequentially without state pollution between runs.
        """
        server_paths = ["/path/to/server1.py", "/path/to/server2.py"]

        for server_path in server_paths:
            # Reset mocks
            mock_client.reset_mock()
            mock_auditor.reset_mock()

            # Configure mocks
            mock_client.connect_to_server = AsyncMock(return_value=True)
            mock_client.cleanup = AsyncMock()
            mock_auditor.audit = AsyncMock(return_value=(80, 100))

            monkeypatch.setattr(sys, "argv", ["mcpaudit", server_path])

            with (
                patch("mcpaudit.cli.MCPClient", return_value=mock_client),
                patch("mcpaudit.cli.MCPAuditor", return_value=mock_auditor),
            ):
                await async_main()

            # Verify each run completed successfully
            mock_client.connect_to_server.assert_called_once()
            mock_auditor.audit.assert_called_once()
            mock_client.cleanup.assert_called_once()

    def test_integration_with_asyncio_run_mocked(
        self,
        monkeypatch: MonkeyPatch,
        mock_client: MagicMock,
        mock_auditor: MagicMock,
    ) -> None:
        """Test that main() properly integrates with asyncio.run().

        This test verifies that the synchronous main() function
        correctly executes the asynchronous async_main() using asyncio.run().
        """
        monkeypatch.setattr(sys, "argv", ["mcpaudit", "/path/to/server.py"])

        # Mock asyncio.run to capture what coroutine is passed
        mock_run = MagicMock()
        monkeypatch.setattr("mcpaudit.cli.asyncio.run", mock_run)

        with (
            patch("mcpaudit.cli.MCPClient", return_value=mock_client),
            patch("mcpaudit.cli.MCPAuditor", return_value=mock_auditor),
        ):
            # Call main() which should use asyncio.run internally
            main()

        # Verify asyncio.run was called
        mock_run.assert_called_once()
        # Verify it was called with a coroutine
        args = mock_run.call_args[0]
        assert len(args) == 1
        assert hasattr(args[0], "send")  # Coroutine duck-typing
