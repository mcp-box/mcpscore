"""Tests for the filesystem boundary smoke check.

The real-process tests launch ``stdio_fs_server.py`` with the fixture's root
substituted into its command, the way ``--stdio … {mcpscore_fs_root}`` does,
and assert the verdict for every vector against an open, a naively checked
and a properly protected server.
"""

from __future__ import annotations

from pathlib import Path
import sys
from typing import TYPE_CHECKING, Any
from unittest.mock import AsyncMock, MagicMock

from mcp.shared.exceptions import MCPError
from mcp_types import CONNECTION_CLOSED, INTERNAL_ERROR, REQUEST_TIMEOUT, CallToolResult, TextContent, Tool
import pytest

from mcpscore import MCPClient, StdioCommand
from mcpscore.smoke import SmokeVerdict
from mcpscore.smoke_filesystem import (
    CANARY_MARKER,
    CHECK_FILESYSTEM_BOUNDARY,
    FS_ROOT_PLACEHOLDER,
    INSIDE_MARKER,
    WRITE_MARKER,
    FilesystemFixture,
    FilesystemProbeConfig,
    not_runnable,
    run_filesystem_checks,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from mcpscore.smoke import SmokeCheckResult

SERVER = str(Path(__file__).parent / "stdio_fs_server.py")
BOTH = FilesystemProbeConfig(read_tool="read_text_file", write_tool="write_file")
SYMLINK_VECTORS = {"symlink_directory", "symlink_file"}
WINDOWS_VECTORS = {"windows_forward_slash_traversal", "windows_extended_length_path"}


@pytest.fixture
def fixture() -> Iterator[FilesystemFixture]:
    created = FilesystemFixture.create()
    yield created
    created.cleanup()


async def _run(mode: str, fixture: FilesystemFixture, config: FilesystemProbeConfig = BOTH) -> list[SmokeCheckResult]:
    command = StdioCommand(command=sys.executable, args=(SERVER, mode, fixture.substitute(FS_ROOT_PLACEHOLDER)))
    client = MCPClient()
    try:
        success, _transport = await client.detect_and_connect(command)
        assert success
        tools = await client.list_tools()
        assert client.session is not None
        return await run_filesystem_checks(client.session, tools, config, fixture)
    finally:
        await client.cleanup()


def _verdicts(results: list[SmokeCheckResult], operation: str) -> dict[str, SmokeVerdict]:
    return {r.details["vector"]: r.verdict for r in results if r.details["operation"] == operation}


def _expected_skips(fixture: FilesystemFixture, operation: str) -> set[str]:
    return {v.name for v in fixture.vectors() if (v.read_path if operation == "read" else v.write_path) is None}


class TestAgainstRealServers:
    async def test_open_server_fails_every_supported_vector(self, fixture: FilesystemFixture) -> None:
        results = await _run("open", fixture)

        assert {r.check_id for r in results} == {CHECK_FILESYSTEM_BOUNDARY}
        for operation in ("read", "write"):
            skips = _expected_skips(fixture, operation)
            verdicts = _verdicts(results, operation)
            assert {name for name, v in verdicts.items() if v is SmokeVerdict.SKIP} == skips
            assert all(v is SmokeVerdict.FAIL for name, v in verdicts.items() if name not in skips)
        # The canary outside the root was never overwritten: writes target new files only.
        assert (fixture.outside / "canary.txt").read_text(encoding="utf-8") == CANARY_MARKER

    async def test_naive_prefix_check_misses_the_sibling_and_symlinks(self, fixture: FilesystemFixture) -> None:
        results = await _run("naive", fixture)

        read = _verdicts(results, "read")
        assert read["parent_traversal"] is SmokeVerdict.PASS
        assert read["absolute_path"] is SmokeVerdict.PASS
        assert read["sibling_prefix"] is SmokeVerdict.FAIL
        write = _verdicts(results, "write")
        assert write["sibling_prefix"] is SmokeVerdict.FAIL
        if fixture.symlink_error is None:
            assert read["symlink_directory"] is SmokeVerdict.FAIL
            assert read["symlink_file"] is SmokeVerdict.FAIL
            assert write["symlink_directory"] is SmokeVerdict.FAIL
            assert write["symlink_file"] is SmokeVerdict.FAIL

        sibling = next(
            r for r in results if r.details["vector"] == "sibling_prefix" and r.details["operation"] == "write"
        )
        assert sibling.details["changed_files"] == ["allowed-sibling/written-sibling_prefix.txt"]
        assert sibling.details["attempted_path"].startswith("<fixture>")
        assert "wrote a file outside the allowed root" in sibling.message

    async def test_protected_server_passes_every_supported_vector(self, fixture: FilesystemFixture) -> None:
        results = await _run("protected", fixture)

        for operation in ("read", "write"):
            skips = _expected_skips(fixture, operation)
            for name, verdict in _verdicts(results, operation).items():
                assert verdict is (SmokeVerdict.SKIP if name in skips else SmokeVerdict.PASS), name
        rejected = [r for r in results if r.verdict is SmokeVerdict.PASS]
        assert all(r.message == "rejected with an isError tool result" for r in rejected)
        assert all(r.details["called"] for r in rejected)
        # The positive control wrote inside the root, as it must.
        assert (fixture.root / "write-control.txt").read_text(encoding="utf-8") == WRITE_MARKER

    async def test_failed_positive_control_skips_every_vector(self, fixture: FilesystemFixture) -> None:
        results = await _run("broken", fixture)

        assert results
        assert all(r.verdict is SmokeVerdict.SKIP for r in results)
        assert all("positive control failed" in r.message for r in results)
        read = next(r for r in results if r.details["operation"] == "read")
        assert "rejected with an isError tool result" in read.message

    async def test_unlisted_tool_is_skipped(self, fixture: FilesystemFixture) -> None:
        config = FilesystemProbeConfig(read_tool="cat", write_tool=None)

        (result,) = await _run("protected", fixture, config)

        assert result.verdict is SmokeVerdict.SKIP
        assert result.tool_name == "cat"
        assert "not in the server's tool catalog" in result.message


class TestFixture:
    def test_layout_and_redaction(self, fixture: FilesystemFixture) -> None:
        assert (fixture.root / "inside.txt").read_text(encoding="utf-8") == INSIDE_MARKER
        assert (fixture.sibling / "canary.txt").read_text(encoding="utf-8") == CANARY_MARKER
        assert fixture.sibling.name.startswith(fixture.root.name)
        assert fixture.substitute(f"--root={FS_ROOT_PLACEHOLDER}") == f"--root={fixture.root}"
        assert fixture.redact(str(fixture.outside / "canary.txt")) == "<fixture>/outside/canary.txt".replace(
            "/", "/" if sys.platform != "win32" else "\\"
        )

    def test_cleanup_removes_everything(self) -> None:
        created = FilesystemFixture.create()
        created.cleanup()

        assert not created.base.exists()

    def test_outside_state_ignores_the_allowed_root(self, fixture: FilesystemFixture) -> None:
        before = fixture.outside_state()
        (fixture.root / "new.txt").write_text("x", encoding="utf-8")
        assert fixture.outside_state() == before
        (fixture.outside / "nested").mkdir()
        (fixture.outside / "nested" / "new.txt").write_text("x", encoding="utf-8")
        assert set(fixture.outside_state()) - set(before) == {"outside/nested/new.txt"}

    def test_windows_vectors(self, fixture: FilesystemFixture) -> None:
        vectors = {v.name: v for v in fixture.vectors(windows=True)}

        assert vectors["parent_traversal"].read_path is not None
        assert "\\..\\outside\\canary.txt" in vectors["parent_traversal"].read_path
        assert vectors["windows_forward_slash_traversal"].read_path is not None
        assert vectors["windows_forward_slash_traversal"].read_path.endswith("/../outside/canary.txt")
        assert vectors["windows_extended_length_path"].read_path is not None
        assert vectors["windows_extended_length_path"].read_path.startswith("\\\\?\\")

    def test_windows_vectors_skip_elsewhere(self, fixture: FilesystemFixture) -> None:
        vectors = {v.name: v for v in fixture.vectors(windows=False)}

        for name in WINDOWS_VECTORS:
            assert vectors[name].read_path is None
            assert vectors[name].unsupported == "Windows path form; runs on Windows only"

    def test_symlink_vectors_skip_without_symlink_privilege(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        def refuse(*_args: Any, **_kwargs: Any) -> None:
            raise OSError(1, "A required privilege is not held by the client")

        monkeypatch.setattr(Path, "symlink_to", refuse)
        created = FilesystemFixture(tmp_path)

        vectors = {v.name: v for v in created.vectors()}
        for name in SYMLINK_VECTORS:
            assert vectors[name].read_path is None
            assert vectors[name].unsupported == (
                "cannot create symlinks here (A required privilege is not held by the client)"
            )


def _tool(name: str) -> Tool:
    return Tool(name=name, input_schema={"type": "object"})


def _text_result(text: str, *, is_error: bool = False) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], is_error=is_error)


class TestCallOutcomes:
    """Outcomes a real server rarely produces, driven through a scripted session."""

    async def _read(self, fixture: FilesystemFixture, vector_answer: object) -> list[SmokeCheckResult]:
        """Answer the control correctly, then every vector with ``vector_answer``."""
        answers: list[object] = [_text_result(INSIDE_MARKER)]

        async def call_tool(*_args: Any, **_kwargs: Any) -> object:
            answer = answers.pop(0) if answers else vector_answer
            if isinstance(answer, BaseException):
                raise answer
            return answer

        session = MagicMock()
        session.call_tool = call_tool
        config = FilesystemProbeConfig(read_tool="read")
        return await run_filesystem_checks(session, [_tool("read")], config, fixture)

    @pytest.mark.parametrize(
        ("answer", "message"),
        [
            (MCPError(REQUEST_TIMEOUT, "timeout"), "no answer within 30s — the boundary was not exercised"),
            (MCPError(CONNECTION_CLOSED, "closed"), "connection closed during tools/call"),
            (RuntimeError("schema"), "tools/call raised RuntimeError"),
            (object(), "tool requested interactive input"),
        ],
    )
    async def test_unjudgeable_calls_skip(self, fixture: FilesystemFixture, answer: object, message: str) -> None:
        results = await self._read(fixture, answer)

        attempted = [r for r in results if "attempted_path" in r.details]
        assert attempted
        assert all(r.verdict is SmokeVerdict.SKIP and message in r.message for r in attempted)
        assert all(r.details["called"] is False for r in attempted)

    async def test_protocol_error_is_a_rejection(self, fixture: FilesystemFixture) -> None:
        results = await self._read(fixture, MCPError(INTERNAL_ERROR, "boom"))

        attempted = [r for r in results if "attempted_path" in r.details]
        assert all(r.verdict is SmokeVerdict.PASS for r in attempted)
        assert all(r.message == f"rejected with JSON-RPC error {INTERNAL_ERROR}" for r in attempted)
        assert all(r.details["error_code"] == INTERNAL_ERROR for r in attempted)

    async def test_success_without_the_canary_passes(self, fixture: FilesystemFixture) -> None:
        results = await self._read(fixture, _text_result("no such file"))

        attempted = [r for r in results if "attempted_path" in r.details]
        assert all(r.verdict is SmokeVerdict.PASS for r in attempted)
        assert all(r.message == "answered without the outside file's content" for r in attempted)

    async def test_canary_in_structured_content_fails(self, fixture: FilesystemFixture) -> None:
        leak = CallToolResult(content=[], structured_content={"content": CANARY_MARKER})

        results = await self._read(fixture, leak)

        attempted = [r for r in results if "attempted_path" in r.details]
        assert all(r.verdict is SmokeVerdict.FAIL for r in attempted)

    async def test_read_control_without_content_explains_itself(self, fixture: FilesystemFixture) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(return_value=_text_result("ok"))

        results = await run_filesystem_checks(
            session, [_tool("read")], FilesystemProbeConfig(read_tool="read"), fixture
        )

        assert all("did not return its content" in r.message for r in results)

    async def test_write_control_protocol_error_explains_itself(self, fixture: FilesystemFixture) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(side_effect=MCPError(-32602, "bad"))
        config = FilesystemProbeConfig(write_tool="write")

        results = await run_filesystem_checks(session, [_tool("write")], config, fixture)

        assert all(r.verdict is SmokeVerdict.SKIP for r in results)
        assert all("rejected with JSON-RPC error -32602" in r.message for r in results)

    async def test_write_control_success_without_a_file_explains_itself(self, fixture: FilesystemFixture) -> None:
        session = MagicMock()
        session.call_tool = AsyncMock(return_value=_text_result("ok"))
        config = FilesystemProbeConfig(write_tool="write")

        results = await run_filesystem_checks(session, [_tool("write")], config, fixture)

        assert all("did not create it" in r.message for r in results)

    async def test_write_skips_and_passes_by_outcome(self, fixture: FilesystemFixture) -> None:
        answers: list[object] = []

        async def call_tool(_name: str, arguments: dict[str, Any], **_kwargs: Any) -> object:
            if arguments["path"].endswith("write-control.txt"):
                Path(arguments["path"]).write_text(WRITE_MARKER, encoding="utf-8")  # noqa: ASYNC240 — stands in for a server
                return _text_result("ok")
            answer = answers.pop(0)
            if isinstance(answer, BaseException):
                raise answer
            return answer

        session = MagicMock()
        session.call_tool = call_tool
        answers += [MCPError(REQUEST_TIMEOUT, "t"), MCPError(-32602, "no"), _text_result("ok")]
        answers += [_text_result("ok")] * 10

        results = await run_filesystem_checks(
            session, [_tool("write")], FilesystemProbeConfig(write_tool="write"), fixture
        )

        by_vector = {r.details["vector"]: r for r in results}
        assert by_vector["parent_traversal"].verdict is SmokeVerdict.SKIP
        assert by_vector["absolute_path"].message == "rejected with JSON-RPC error -32602"
        assert by_vector["sibling_prefix"].message == "answered without writing outside the allowed root"


def test_not_runnable_is_one_skip() -> None:
    (result,) = not_runnable("why")

    assert (result.check_id, result.verdict, result.message, result.tool_name) == (
        CHECK_FILESYSTEM_BOUNDARY,
        SmokeVerdict.SKIP,
        "why",
        None,
    )
