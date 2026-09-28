"""Unit tests for MCPClient STDIO transport error paths."""

import asyncio
import logging
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import AsyncMock, patch

from mcp import StdioServerParameters
import pytest

from mcpscore.enums import ConnectionErrorReason, MCPTransportType
import mcpscore.mcp_client as client_module
from mcpscore.mcp_client import (
    SERVER_STDERR_LINE_LIMIT,
    SERVER_STDERR_PREFIX,
    MCPClient,
    ServerStderrRelay,
    StdioCommand,
    is_exec_format_error,
    missing_dependency_hint,
    relayed_stdio_client,
    stdio_launch_hint,
)


class TestMCPClientStdioErrors:
    """Test MCPClient STDIO transport error handling."""

    @pytest.fixture
    def mcp_client(self):
        """Create a fresh MCPClient instance for each test."""
        return MCPClient()

    async def test_detect_missing_script_without_launching(self, mcp_client, tmp_path, caplog):
        """A typo'd script path is unreachable and cannot enter modern fallback."""
        missing = tmp_path / "missing.py"

        with patch.object(mcp_client, "connect_to_server", new=AsyncMock()) as connect:
            success, transport = await mcp_client.detect_and_connect(str(missing))

        assert success is False
        assert transport is None
        connect.assert_not_awaited()
        assert mcp_client.stdio_params is None
        assert mcp_client.last_connection_error is not None
        assert mcp_client.last_connection_error.reason is ConnectionErrorReason.UNREACHABLE
        assert "Server script not found" in caplog.text

    async def test_connect_stdio_invalid_file_extension(self, mcp_client, caplog):
        """Test stdio connection with invalid file extension."""
        invalid_paths = [
            "server.txt",
            "server.sh",
            "server",
            "server.exe",
        ]

        for path in invalid_paths:
            result = await mcp_client._connect_with_stdio(path)
            assert result is False
            assert "Server script must be a .py or .js file" in caplog.text

    async def test_connect_stdio_python_filenotfound(self, mcp_client, caplog):
        """Test stdio connection with Python interpreter not found."""
        server_path = "server.py"

        with patch("mcpscore.mcp_client.stdio_client") as mock_client:
            # Simulate FileNotFoundError (Python not found)
            mock_client.return_value.__aenter__.side_effect = FileNotFoundError("python not found")

            result = await mcp_client._connect_with_stdio(server_path)

            assert result is False
            assert "Python interpreter not found" in caplog.text

    async def test_connect_stdio_nodejs_filenotfound(self, mcp_client, caplog):
        """Test stdio connection with Node.js not found."""
        server_path = "server.js"

        with patch("mcpscore.mcp_client.stdio_client") as mock_client:
            # Simulate FileNotFoundError (Node.js not found)
            mock_client.return_value.__aenter__.side_effect = FileNotFoundError("node not found")

            result = await mcp_client._connect_with_stdio(server_path)

            assert result is False
            assert "Node.js not found" in caplog.text

    async def test_connect_stdio_permission_error(self, mcp_client, caplog):
        """Test stdio connection with permission denied."""
        server_path = "server.py"

        with patch("mcpscore.mcp_client.stdio_client") as mock_client:
            # Simulate PermissionError
            mock_client.return_value.__aenter__.side_effect = PermissionError("Permission denied")

            result = await mcp_client._connect_with_stdio(server_path)

            assert result is False
            assert "Permission denied launching server" in caplog.text

    async def test_connect_stdio_generic_exception(self, mcp_client, caplog):
        """Test stdio connection with generic exception."""
        server_path = "server.py"

        with patch("mcpscore.mcp_client.stdio_client") as mock_client, caplog.at_level(logging.INFO):
            # Simulate generic exception
            mock_client.return_value.__aenter__.side_effect = RuntimeError("Unexpected error")

            result = await mcp_client._connect_with_stdio(server_path)

            assert result is False
            assert "Legacy MCP initialize handshake failed" in caplog.text
            assert mcp_client.last_connection_error is not None
            assert mcp_client.last_connection_error.detail == "Unexpected error"

    async def test_failed_handshake_retains_launch_parameters_for_modern_fallback(self, mcp_client):
        """A rejected legacy handshake must not discard the probe launch spec."""
        with patch.object(
            mcp_client,
            "_establish_session",
            new=AsyncMock(side_effect=RuntimeError("modern-only server rejected initialize")),
        ):
            result = await mcp_client._connect_with_stdio("server.py")

        assert result is False
        assert mcp_client.stdio_params is not None
        assert mcp_client.stdio_params.args == ["server.py"]

    async def test_connect_stdio_success_python(self, mcp_client):
        """Test successful stdio connection with Python server."""
        server_path = "server.py"

        mock_stdio = AsyncMock()
        mock_write = AsyncMock()
        mock_session = AsyncMock()

        with (
            patch("mcpscore.mcp_client.stdio_client") as mock_client,
            patch("mcpscore.mcp_client.ClientSession", return_value=mock_session),
        ):
            # Set up successful connection
            mock_client.return_value.__aenter__.return_value = (mock_stdio, mock_write)
            mock_session.__aenter__.return_value = mock_session

            result = await mcp_client._connect_with_stdio(server_path)

            assert result is True
            assert mcp_client.session == mock_session
            assert mcp_client.transport_type == MCPTransportType.STDIO
            assert mcp_client.url is None

    async def test_connect_stdio_success_nodejs(self, mcp_client):
        """Test successful stdio connection with Node.js server."""
        server_path = "server.js"

        mock_stdio = AsyncMock()
        mock_write = AsyncMock()
        mock_session = AsyncMock()

        with (
            patch("mcpscore.mcp_client.stdio_client") as mock_client,
            patch("mcpscore.mcp_client.ClientSession", return_value=mock_session),
        ):
            # Set up successful connection
            mock_client.return_value.__aenter__.return_value = (mock_stdio, mock_write)
            mock_session.__aenter__.return_value = mock_session

            result = await mcp_client._connect_with_stdio(server_path)

            assert result is True
            assert mcp_client.session == mock_session
            assert mcp_client.transport_type == MCPTransportType.STDIO

    async def test_detect_and_connect_stdio_failure(self, mcp_client):
        """Test detect_and_connect returns None transport on stdio failure."""
        server_path = "server.py"

        with patch.object(mcp_client, "_connect_with_stdio", return_value=False):
            success, transport = await mcp_client.detect_and_connect(server_path)

            assert success is False
            assert transport is None


class TestStdioCommand:
    """Generic stdio commands: any-language local servers via StdioCommand."""

    @pytest.fixture
    def mcp_client(self):
        return MCPClient()

    async def test_display_joins_command_and_args(self):
        cmd = StdioCommand(command="java", args=("-jar", "server.jar"))
        assert cmd.display == "java -jar server.jar"

    async def test_detect_and_connect_dispatches_stdio_command(self, mcp_client):
        cmd = StdioCommand(command="./server")
        with patch.object(mcp_client, "_connect_with_stdio_command", return_value=True) as connect:
            success, transport = await mcp_client.detect_and_connect(cmd)
        assert success is True
        assert transport is MCPTransportType.STDIO
        connect.assert_awaited_once_with(cmd)

    async def test_detect_and_connect_stdio_command_failure(self, mcp_client):
        cmd = StdioCommand(command="./server")
        with patch.object(mcp_client, "_connect_with_stdio_command", return_value=False):
            success, transport = await mcp_client.detect_and_connect(cmd)
        assert success is False
        assert transport is None

    async def test_command_passed_through_without_env(self, mcp_client):
        """No --env: the SDK's own default environment handling applies (env=None)."""
        cmd = StdioCommand(command="dotnet", args=("run", "--project", "./srv"))
        with (
            patch("mcpscore.mcp_client.stdio_client"),
            patch.object(mcp_client, "_establish_session", new=AsyncMock()) as establish,
        ):
            result = await mcp_client._connect_with_stdio_command(cmd)
        assert result is True
        params = mcp_client.stdio_params
        assert params is not None
        assert params.command == "dotnet"
        assert params.args == ["run", "--project", "./srv"]
        assert params.env is None
        establish.assert_awaited_once()

    async def test_env_merged_over_default_environment(self, mcp_client):
        """--env vars land on top of the SDK default env, not instead of it."""
        cmd = StdioCommand(command="./server", env={"API_KEY": "secret", "PATH": "/custom"})
        with (
            patch("mcpscore.mcp_client.stdio_client"),
            patch("mcpscore.mcp_client.get_default_environment", return_value={"PATH": "/usr/bin", "HOME": "/home"}),
            patch.object(mcp_client, "_establish_session", new=AsyncMock()),
        ):
            result = await mcp_client._connect_with_stdio_command(cmd)
        assert result is True
        params = mcp_client.stdio_params
        assert params is not None
        assert params.env == {"PATH": "/custom", "HOME": "/home", "API_KEY": "secret"}

    async def test_command_not_found_names_the_command(self, mcp_client, caplog):
        cmd = StdioCommand(command="no-such-binary")
        with patch("mcpscore.mcp_client.stdio_client") as mock_stdio:
            mock_stdio.return_value.__aenter__.side_effect = FileNotFoundError("not found")
            result = await mcp_client._connect_with_stdio_command(cmd)
        assert result is False
        assert "Command not found: 'no-such-binary'" in caplog.text
        assert "Traceback" not in caplog.text
        assert mcp_client.last_connection_error is not None

    async def test_command_handshake_timeout_classified(self, mcp_client, caplog):
        cmd = StdioCommand(command="./slow-server")
        with patch("mcpscore.mcp_client.stdio_client") as mock_stdio:
            mock_stdio.return_value.__aenter__.side_effect = TimeoutError()
            result = await mcp_client._connect_with_stdio_command(cmd)
        assert result is False
        assert "handshake timed out" in caplog.text
        assert "./slow-server" in caplog.text
        assert mcp_client.last_connection_error.reason.value == "timeout"

    async def test_command_handshake_cancelled_classified_not_mcp(self, mcp_client, caplog):
        """Classify an SDK-teardown CancelledError as NOT_MCP, not a re-raise.

        The cancellation comes from the SDK's context teardown, not from our
        own task being cancelled — it means the process spoke no MCP.
        """
        import asyncio

        cmd = StdioCommand(command="./not-an-mcp-server")
        with patch("mcpscore.mcp_client.stdio_client") as mock_stdio:
            mock_stdio.return_value.__aenter__.side_effect = asyncio.CancelledError()
            result = await mcp_client._connect_with_stdio_command(cmd)
        assert result is False
        assert "handshake failed" in caplog.text
        assert mcp_client.last_connection_error.reason.value == "not_mcp"


class TestStdioCommandRealProcess:
    """End-to-end: launch a real server process, no transport mocking.

    Guards the integration the mocked tests cannot see: StdioServerParameters,
    the SDK's environment handling, actual process launch, and the MCP
    handshake working together.
    """

    async def test_handshake_and_env_round_trip_through_real_process(self):
        from pathlib import Path
        import sys as _sys

        server = str(Path(__file__).parent / "stdio_e2e_server.py")
        cmd = StdioCommand(
            command=_sys.executable,
            args=(server,),
            env={"MCPSCORE_E2E_ENV": "env-round-trip-proof"},
        )
        client = MCPClient()
        try:
            success, transport = await client.detect_and_connect(cmd)
            assert success is True
            assert transport is MCPTransportType.STDIO
            # The env var reached the real subprocess: the server echoes it
            # back as its version through the actual handshake.
            assert client._init_result is not None
            assert client._init_result.server_info.version == "env-round-trip-proof"
        finally:
            await client.cleanup()


class TestStdioLaunchHints:
    """A --stdio command the OS cannot launch gets one explanatory line, never a traceback."""

    @pytest.fixture
    def mcp_client(self):
        return MCPClient()

    async def test_script_named_as_command_shows_interpreter_form(self, mcp_client, tmp_path, monkeypatch, caplog):
        """`--stdio weather.py` looks the script up on PATH; the fix is to name its interpreter."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "weather.py").write_text("print('hi')\n", encoding="utf-8")
        with patch("mcpscore.mcp_client.stdio_client") as mock_stdio:
            mock_stdio.return_value.__aenter__.side_effect = FileNotFoundError(2, "No such file", "weather.py")
            result = await mcp_client._connect_with_stdio_command(StdioCommand(command="weather.py"))
        assert result is False
        assert "'weather.py' is a script, not an executable command" in caplog.text
        assert "--stdio python weather.py" in caplog.text
        assert "--stdio uv run weather.py" in caplog.text
        assert "Traceback" not in caplog.text
        assert mcp_client.last_connection_error.reason is ConnectionErrorReason.UNREACHABLE

    async def test_missing_script_named_as_command(self, mcp_client, tmp_path, monkeypatch, caplog):
        monkeypatch.chdir(tmp_path)
        with patch("mcpscore.mcp_client.stdio_client") as mock_stdio:
            mock_stdio.return_value.__aenter__.side_effect = FileNotFoundError(2, "No such file", "server.js")
            result = await mcp_client._connect_with_stdio_command(StdioCommand(command="server.js"))
        assert result is False
        assert "Server script not found: 'server.js'" in caplog.text
        assert "--stdio node server.js" in caplog.text
        assert "Traceback" not in caplog.text

    async def test_permission_denied_on_command_is_one_line(self, mcp_client, caplog):
        with patch("mcpscore.mcp_client.stdio_client") as mock_stdio:
            mock_stdio.return_value.__aenter__.side_effect = PermissionError(13, "Permission denied", "./srv")
            result = await mcp_client._connect_with_stdio_command(StdioCommand(command="./srv"))
        assert result is False
        assert "Permission denied launching './srv'. Make it executable (chmod +x)" in caplog.text
        assert "Traceback" not in caplog.text
        assert mcp_client.last_connection_error.reason is ConnectionErrorReason.UNREACHABLE

    def test_hint_for_script_without_exec_bit(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "srv.py").write_text("", encoding="utf-8")
        hint = stdio_launch_hint("./srv.py", permission_denied=True)
        assert hint.startswith("'./srv.py' is a script, not an executable command")
        assert "--stdio python ./srv.py" in hint

    @pytest.mark.skipif(os.name == "nt", reason="POSIX quoting; the Windows form has its own test")
    def test_hint_quotes_paths_for_the_shell(self, tmp_path, monkeypatch):
        """The suggested command must paste back correctly when the path needs quoting."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "my server.py").write_text("", encoding="utf-8")
        hint = stdio_launch_hint("my server.py")
        assert "--stdio python 'my server.py'" in hint
        assert "--stdio uv run 'my server.py'" in hint
        assert "--stdio node 'a;b.js'" in stdio_launch_hint("a;b.js")

    @pytest.mark.skipif(os.name == "nt", reason="exec bits and shebangs are POSIX")
    def test_executable_script_with_bad_shebang_is_not_called_a_script_mistake(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        script = tmp_path / "srv.py"
        script.write_text("#!/nonexistent/python\nprint('hi')\n", encoding="utf-8")
        script.chmod(0o755)
        with pytest.raises(FileNotFoundError):
            subprocess.run(["./srv.py"], check=False)
        hint = stdio_launch_hint("./srv.py")
        assert hint.startswith("'./srv.py' is executable but could not be launched: its shebang interpreter")
        assert "--stdio python ./srv.py" in hint

    @pytest.mark.skipif(os.name == "nt", reason="exec bits and shebangs are POSIX")
    def test_bare_executable_script_is_a_path_lookup_problem_not_a_shebang(self, tmp_path, monkeypatch):
        """A bare name is looked up on PATH, so a +x file in the current directory is not the launched one."""
        monkeypatch.chdir(tmp_path)
        script = tmp_path / "srv.py"
        script.write_text("#!/usr/bin/env python3\nprint('hi')\n", encoding="utf-8")
        script.chmod(0o755)
        # A PATH containing "." would launch the script and hide the lookup failure.
        (tmp_path / "empty-path").mkdir()
        monkeypatch.setenv("PATH", str(tmp_path / "empty-path"))
        with pytest.raises(FileNotFoundError):
            subprocess.run(["srv.py"], check=False)
        hint = stdio_launch_hint("srv.py")
        assert hint.startswith("'srv.py' is a script, not an executable command")
        assert "shebang" not in hint
        assert "--stdio python srv.py" in hint

    def test_hint_uses_windows_quoting_on_windows(self, tmp_path, monkeypatch):
        """cmd.exe keeps POSIX single quotes literally, so Windows gets double-quoted paths."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "my server.py").write_text("", encoding="utf-8")
        # Flip the module switch, not os.name: on 3.11 pathlib reads os.name per call.
        monkeypatch.setattr(client_module, "_WINDOWS", True)
        hint = stdio_launch_hint("my server.py")
        assert '--stdio python "my server.py"' in hint
        assert '--stdio uv run "my server.py"' in hint
        assert "python 'my server.py'" not in hint

    def test_hint_quotes_cmd_metacharacters_on_windows(self, tmp_path, monkeypatch):
        """cmd.exe would split on & or expand %; such paths are double-quoted, plain ones are not."""
        monkeypatch.chdir(tmp_path)
        for name in ("a&b.py", "100%.py", "plain.py"):
            (tmp_path / name).write_text("", encoding="utf-8")
        monkeypatch.setattr(client_module, "_WINDOWS", True)
        assert '--stdio python "a&b.py"' in stdio_launch_hint("a&b.py")
        assert '--stdio python "100%.py"' in stdio_launch_hint("100%.py")
        assert "--stdio python plain.py" in stdio_launch_hint("plain.py")

    @pytest.mark.skipif(os.name == "nt", reason="exec bits and shebangs are POSIX")
    def test_executable_script_without_shebang_raises_exec_format_error(self, tmp_path, monkeypatch):
        """The OS answer that the launcher must recognize: ENOEXEC, not file-not-found."""
        import errno

        monkeypatch.chdir(tmp_path)
        script = tmp_path / "srv.py"
        script.write_text("print('hi')\n", encoding="utf-8")
        script.chmod(0o755)
        with pytest.raises(OSError, match="Exec format error") as raised:
            subprocess.run(["./srv.py"], check=False)
        assert raised.value.errno == errno.ENOEXEC
        assert is_exec_format_error(raised.value)

    async def test_executable_script_without_shebang_gets_the_interpreter_hint(self, mcp_client, caplog):
        """ENOEXEC is a launch problem, not a handshake failure."""
        import errno

        with patch("mcpscore.mcp_client.stdio_client") as mock_stdio:
            mock_stdio.return_value.__aenter__.side_effect = OSError(errno.ENOEXEC, "Exec format error", "./srv.py")
            result = await mcp_client._connect_with_stdio_command(StdioCommand(command="./srv.py"))
        assert result is False
        assert "'./srv.py' is executable but has no usable shebang" in caplog.text
        assert "--stdio python ./srv.py" in caplog.text
        assert "Traceback" not in caplog.text
        assert "handshake failed" not in caplog.text
        assert mcp_client.last_connection_error.reason is ConnectionErrorReason.UNREACHABLE

    async def test_other_os_errors_stay_handshake_failures(self, mcp_client, caplog):
        caplog.set_level(logging.INFO, logger="mcpscore.mcp_client")
        with patch("mcpscore.mcp_client.stdio_client") as mock_stdio:
            mock_stdio.return_value.__aenter__.side_effect = OSError(32, "Broken pipe")
            result = await mcp_client._connect_with_stdio_command(StdioCommand(command="./srv"))
        assert result is False
        assert "Legacy MCP initialize handshake failed for server: ./srv" in caplog.text

    def test_exec_format_hint_for_a_binary(self):
        hint = stdio_launch_hint("./srv", exec_format=True)
        assert hint.startswith("'./srv' is not an executable this system can run")

    def test_hint_for_plain_missing_command(self):
        assert stdio_launch_hint("no-such-binary") == (
            "Command not found: 'no-such-binary'. Please ensure it is installed and on PATH."
        )


class TestServerStderrRelay:
    """Whatever a local server writes to stderr reaches the log with a prefix."""

    def test_child_stderr_lines_are_logged_with_prefix(self, caplog):
        caplog.set_level(logging.INFO, logger="mcpscore.mcp_client")
        with ServerStderrRelay() as relay:
            subprocess.run(
                [sys.executable, "-c", "import sys; sys.stderr.write('boom\\nbang\\n')"],
                stderr=relay.errlog,
                check=True,
            )
        assert relay.errlog.closed
        messages = [record.getMessage() for record in caplog.records]
        assert f"{SERVER_STDERR_PREFIX}boom" in messages
        assert f"{SERVER_STDERR_PREFIX}bang" in messages

    def test_a_line_without_newline_is_relayed_in_bounded_pieces(self, caplog):
        """A server that never writes a newline must not grow our memory: long output arrives chunked."""
        caplog.set_level(logging.INFO, logger="mcpscore.mcp_client")
        payload = "x" * (SERVER_STDERR_LINE_LIMIT * 2 + 100)
        with ServerStderrRelay() as relay:
            relay.errlog.write(payload)
            relay.errlog.flush()
        pieces = [record.getMessage()[len(SERVER_STDERR_PREFIX) :] for record in caplog.records]
        assert len(pieces) == 3
        assert all(len(piece) <= SERVER_STDERR_LINE_LIMIT for piece in pieces)
        assert "".join(pieces) == payload

    async def test_teardown_waits_off_the_event_loop(self, monkeypatch):
        """A pump that cannot drain must not stall the loop while the relay closes."""
        monkeypatch.setattr(ServerStderrRelay, "JOIN_TIMEOUT_S", 0.3)
        relay = ServerStderrRelay().start()
        # A second writer keeps the pipe open, so the pump never sees EOF.
        holder = os.dup(relay.errlog.fileno())
        ticks = 0

        async def tick() -> None:
            nonlocal ticks
            while True:
                await asyncio.sleep(0.02)
                ticks += 1

        ticker = asyncio.ensure_future(tick())
        try:
            await relay.aclose()
        finally:
            ticker.cancel()
            os.close(holder)
        assert relay.errlog.closed
        assert ticks >= 5

    async def test_transport_receives_the_relay_pipe(self):
        """The SDK gets the relay's pipe as errlog, and the pipe closes with the transport."""
        params = StdioServerParameters(command="srv", args=[])
        with patch("mcpscore.mcp_client.stdio_client") as mock_stdio:
            mock_stdio.return_value.__aenter__.return_value = ("read", "write")
            async with relayed_stdio_client(params) as streams:
                errlog = mock_stdio.call_args.kwargs["errlog"]
                assert streams == ("read", "write")
                assert mock_stdio.call_args.args[0] is params
                assert errlog.fileno() >= 0
                assert not errlog.closed
        assert errlog.closed

    def test_held_lines_wait_for_release(self, caplog):
        caplog.set_level(logging.INFO, logger="mcpscore.mcp_client")
        relay = ServerStderrRelay(hold=True).start()
        relay.errlog.write("early\n")
        relay.close()
        assert not caplog.records
        relay.release()
        assert [record.getMessage() for record in caplog.records] == [f"{SERVER_STDERR_PREFIX}early"]

    def test_discarded_lines_are_debug_only(self, caplog):
        caplog.set_level(logging.DEBUG, logger="mcpscore.mcp_client")
        relay = ServerStderrRelay(hold=True).start()
        relay.errlog.write("Traceback (most recent call last):\nModuleNotFoundError: No module named 'platformdirs'\n")
        relay.close()
        assert relay.missing_module() == "platformdirs"
        relay.discard()
        assert [record.levelno for record in caplog.records] == [logging.DEBUG, logging.DEBUG]

    def test_held_lines_are_bounded_and_the_drop_is_counted(self, caplog, monkeypatch):
        caplog.set_level(logging.INFO, logger="mcpscore.mcp_client")
        monkeypatch.setattr(client_module, "SERVER_STDERR_HELD_LINES", 2)
        relay = ServerStderrRelay(hold=True).start()
        relay.errlog.write("a\nb\nc\n")
        relay.close()
        relay.release()
        assert [record.getMessage() for record in caplog.records] == [
            f"{SERVER_STDERR_PREFIX}(1 earlier lines omitted)",
            f"{SERVER_STDERR_PREFIX}b",
            f"{SERVER_STDERR_PREFIX}c",
        ]

    def test_no_missing_module_in_other_output(self):
        relay = ServerStderrRelay(hold=True).start()
        relay.errlog.write("ValueError: bad config\n")
        relay.close()
        assert relay.missing_module() is None


class TestMissingDependency:
    """A .py server whose dependencies are not in mcpscore's Python gets the command that works."""

    @pytest.fixture
    def mcp_client(self):
        return MCPClient()

    @pytest.fixture(autouse=True)
    def repo_root(self, tmp_path):
        """Stop the project-file search at tmp_path, whatever lies above it on this machine."""
        (tmp_path / ".git").mkdir()

    @pytest.fixture(autouse=True)
    def uv_installed(self, monkeypatch):
        """Have uv on PATH unless a test removes it, whatever this machine has."""
        monkeypatch.setattr(client_module.shutil, "which", lambda name: f"/usr/bin/{name}")

    def test_hint_for_a_uv_project_in_the_current_directory(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
        hint = missing_dependency_hint("srv.py", "platformdirs")
        assert hint.startswith("srv.py could not start: No module named 'platformdirs'.")
        assert hint.endswith("mcpscore --stdio uv run srv.py")

    def test_hint_for_a_uv_project_elsewhere(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "proj").mkdir()
        (tmp_path / "proj" / "pyproject.toml").write_text("", encoding="utf-8")
        script = str(Path("proj") / "srv.py")
        hint = missing_dependency_hint(script, "x")
        assert hint.endswith(
            client_module._paste_ready(["mcpscore", "--stdio", "uv", "run", "--project", "proj", script])
        )

    def test_hint_for_requirements_txt(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
        hint = missing_dependency_hint("srv.py", "x")
        assert hint.endswith("mcpscore --stdio uv run --with-requirements requirements.txt srv.py")

    def test_hint_without_project_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        hint = missing_dependency_hint("srv.py", "x")
        assert hint.endswith("mcpscore --stdio <python-with-its-dependencies> srv.py")

    async def test_real_server_missing_a_module_gets_the_hint_not_the_traceback(
        self, mcp_client, tmp_path, monkeypatch, caplog
    ):
        caplog.set_level(logging.INFO, logger="mcpscore.mcp_client")
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
        (tmp_path / "srv.py").write_text("import mcpscore_no_such_module\n", encoding="utf-8")

        success, transport = await mcp_client.detect_and_connect("srv.py")

        assert (success, transport) == (False, None)
        assert "srv.py could not start: No module named 'mcpscore_no_such_module'" in caplog.text
        assert "mcpscore --stdio uv run srv.py" in caplog.text
        assert not [r for r in caplog.records if r.levelno >= logging.INFO and SERVER_STDERR_PREFIX in r.getMessage()]
        assert "handshake failed" not in caplog.text
        # Not UNKNOWN: the CLI must not retry the dead launch as a modern-only server.
        assert mcp_client.last_connection_error.reason is ConnectionErrorReason.UNREACHABLE

    async def test_real_server_failing_otherwise_still_shows_its_stderr(self, mcp_client, tmp_path, caplog):
        caplog.set_level(logging.INFO, logger="mcpscore.mcp_client")
        script = tmp_path / "srv.py"
        script.write_text("raise SystemExit('bad config')\n", encoding="utf-8")

        success, _ = await mcp_client.detect_and_connect(str(script))

        assert success is False
        assert f"{SERVER_STDERR_PREFIX}bad config" in caplog.text
        assert "could not start" not in caplog.text

    async def test_a_stdio_command_is_not_second_guessed(self, mcp_client, tmp_path, caplog):
        """With --stdio the user chose the interpreter: relay its stderr unchanged."""
        caplog.set_level(logging.INFO, logger="mcpscore.mcp_client")
        script = tmp_path / "srv.py"
        script.write_text("import mcpscore_no_such_module\n", encoding="utf-8")

        success = await mcp_client._connect_with_stdio_command(StdioCommand(sys.executable, (str(script),)))

        assert success is False
        assert f"{SERVER_STDERR_PREFIX}ModuleNotFoundError" in caplog.text
        assert "could not start" not in caplog.text

    @pytest.mark.parametrize(
        "error", [asyncio.CancelledError(), OSError(32, "Broken pipe")], ids=["cancelled", "oserror"]
    )
    async def test_missing_module_is_explained_whichever_way_the_handshake_dies(
        self, mcp_client, tmp_path, monkeypatch, caplog, error
    ):
        """The SDK can end a dead launch with a teardown cancellation or a pipe error, not only a generic one."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "srv.py").write_text("", encoding="utf-8")
        with (
            patch("mcpscore.mcp_client.stdio_client") as mock_stdio,
            patch.object(ServerStderrRelay, "missing_module", return_value="platformdirs"),
        ):
            mock_stdio.return_value.__aenter__.side_effect = error
            success = await mcp_client._connect_with_stdio("srv.py")

        assert success is False
        assert "srv.py could not start: No module named 'platformdirs'" in caplog.text
        assert "handshake failed" not in caplog.text
        assert mcp_client.last_connection_error.reason is ConnectionErrorReason.UNREACHABLE

    def test_hint_finds_the_project_above_a_nested_script(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
        (tmp_path / "src").mkdir()
        script = str(Path("src") / "server.py")
        hint = missing_dependency_hint(script, "x")
        assert hint.endswith(client_module._paste_ready(["mcpscore", "--stdio", "uv", "run", script]))

    def test_hint_finds_requirements_above_a_nested_script(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
        (tmp_path / "src").mkdir()
        script = str(Path("src") / "server.py")
        hint = missing_dependency_hint(script, "x")
        assert hint.endswith(
            client_module._paste_ready(
                ["mcpscore", "--stdio", "uv", "run", "--with-requirements", "requirements.txt", script]
            )
        )

    def test_nearest_project_file_wins(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
        (tmp_path / "server").mkdir()
        (tmp_path / "server" / "requirements.txt").write_text("", encoding="utf-8")
        script = str(Path("server") / "srv.py")
        hint = missing_dependency_hint(script, "x")
        assert "--with-requirements" in hint

    def test_search_stops_at_the_repository_root(self, tmp_path, monkeypatch):
        (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
        (tmp_path / "other").mkdir()
        (tmp_path / "other" / ".git").mkdir()
        monkeypatch.chdir(tmp_path / "other")
        hint = missing_dependency_hint("srv.py", "x")
        assert hint.endswith("mcpscore --stdio <python-with-its-dependencies> srv.py")

    def test_project_outside_the_working_directory_is_named_absolutely(self, tmp_path, monkeypatch):
        (tmp_path / "proj").mkdir()
        (tmp_path / "proj" / "pyproject.toml").write_text("", encoding="utf-8")
        (tmp_path / "elsewhere").mkdir()
        monkeypatch.chdir(tmp_path / "elsewhere")
        script = str(tmp_path / "proj" / "srv.py")
        hint = missing_dependency_hint(script, "x")
        project = str((tmp_path / "proj").resolve())
        assert hint.endswith(
            client_module._paste_ready(["mcpscore", "--stdio", "uv", "run", "--project", project, script])
        )

    @pytest.mark.parametrize(
        ("launch", "held"),
        [
            (lambda client: client._connect_with_stdio("srv.py"), True),
            (lambda client: client._connect_with_stdio("srv.js"), False),
            (lambda client: client._connect_with_stdio_command(StdioCommand("srv")), False),
        ],
        ids=["python-file", "js-file", "stdio-command"],
    )
    async def test_stderr_is_held_only_for_a_python_file(self, mcp_client, launch, held):
        """A --stdio server's startup prompt must reach the user while it waits, not after the timeout."""
        holds: list[bool] = []
        real_init = ServerStderrRelay.__init__

        def spy(relay, *, hold=False):
            holds.append(hold)
            real_init(relay, hold=hold)

        with (
            patch.object(ServerStderrRelay, "__init__", spy),
            patch("mcpscore.mcp_client.stdio_client") as mock_stdio,
        ):
            mock_stdio.return_value.__aenter__.side_effect = FileNotFoundError()
            await launch(mcp_client)
        assert holds == [held]

    def test_search_ends_at_the_filesystem_root(self, monkeypatch):
        """Outside any repository the search stops at the root and falls back to the generic form."""
        monkeypatch.setattr(client_module, "_PROJECT_FILES", ("mcpscore-no-such-project-file",))
        script = str(Path(Path.cwd().anchor) / "srv.py")
        assert client_module._nearest_project_file(script) is None

    @staticmethod
    def _make_venv_python(folder: Path) -> Path:
        python = folder / ".venv" / ("Scripts/python.exe" if client_module._WINDOWS else "bin/python")
        python.parent.mkdir(parents=True)
        python.write_text("", encoding="utf-8")
        return python

    def test_without_uv_the_project_venv_is_suggested(self, tmp_path, monkeypatch):
        """pip-installed mcpscore brings no uv: a uv command would fail with command not found."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(client_module.shutil, "which", lambda _name: None)
        (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
        python = self._make_venv_python(tmp_path)
        hint = missing_dependency_hint("srv.py", "x")
        assert hint.endswith(
            client_module._paste_ready(["mcpscore", "--stdio", str(python.relative_to(tmp_path)), "srv.py"])
        )
        assert "uv run" not in hint

    def test_without_uv_or_venv_the_generic_form_is_suggested(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(client_module.shutil, "which", lambda _name: None)
        (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
        hint = missing_dependency_hint("srv.py", "x")
        assert hint.endswith("mcpscore --stdio <python-with-its-dependencies> srv.py")

    def test_a_venv_next_to_a_script_without_project_files_is_suggested(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        python = self._make_venv_python(tmp_path)
        hint = missing_dependency_hint("srv.py", "x")
        assert hint.endswith(
            client_module._paste_ready(["mcpscore", "--stdio", str(python.relative_to(tmp_path)), "srv.py"])
        )
