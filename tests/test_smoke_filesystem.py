"""Tests for the filesystem boundary smoke check.

The real-process tests launch ``stdio_fs_server.py`` with the fixture's root
substituted into its command, the way ``--stdio … {mcpscore_fs_root}`` does,
and assert the verdict for every vector against an open, a naively checked
and a properly protected server.
"""

from __future__ import annotations

from pathlib import Path, PureWindowsPath
import sys
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock

from mcp.shared.exceptions import MCPError
from mcp_types import CONNECTION_CLOSED, INTERNAL_ERROR, REQUEST_TIMEOUT, CallToolResult, TextContent, Tool
import pytest

from mcpscore import MCPClient, StdioCommand
from mcpscore.mcp_client import RawRequest, RawResult
from mcpscore.smoke import SmokeReport, SmokeVerdict
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
    from collections.abc import Callable, Iterator

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

    async def test_a_leak_that_breaks_the_output_schema_still_fails(self, fixture: FilesystemFixture) -> None:
        results = await _run("open_schema", fixture, FilesystemProbeConfig(read_tool="read_text_file"))

        read = _verdicts(results, "read")
        assert read["absolute_path"] is SmokeVerdict.FAIL
        assert read["sibling_prefix"] is SmokeVerdict.FAIL

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

    def test_redaction_covers_the_forward_slash_spelling_of_a_windows_base(self, tmp_path: Path) -> None:
        fixture = FilesystemFixture(tmp_path)
        fixture.base = PureWindowsPath("C:\\Temp\\mcpscore-fs-x")  # pyright: ignore[reportAttributeAccessIssue]

        assert fixture.redact("C:/Temp/mcpscore-fs-x/allowed/../outside/canary.txt") == (
            "<fixture>/allowed/../outside/canary.txt"
        )
        assert fixture.redact("C:\\Temp\\mcpscore-fs-x\\outside") == "<fixture>\\outside"

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


def _scripted_session(answer_for: Callable[[dict[str, Any]], object]) -> MagicMock:
    """Build a session whose raw ``tools/call`` answers come from ``answer_for(arguments)``.

    An exception is raised, a ``CallToolResult`` is sent as its wire form, and
    anything else is returned as given.
    """

    async def send_request(request: RawRequest, *_args: Any, **_kwargs: Any) -> object:
        answer = answer_for(request.params["arguments"])
        if isinstance(answer, BaseException):
            raise answer
        if isinstance(answer, CallToolResult):
            return RawResult(**answer.model_dump(by_alias=True, mode="json", exclude_none=True))
        return answer

    session = MagicMock()
    session.send_request = send_request
    return session


class TestCallOutcomes:
    """Outcomes a real server rarely produces, driven through a scripted session."""

    async def _read(self, fixture: FilesystemFixture, vector_answer: object) -> list[SmokeCheckResult]:
        """Answer the control correctly, then every vector with ``vector_answer``."""

        def answer_for(arguments: dict[str, Any]) -> object:
            return _text_result(INSIDE_MARKER) if arguments["path"].endswith("inside.txt") else vector_answer

        config = FilesystemProbeConfig(read_tool="read")
        return await run_filesystem_checks(_scripted_session(answer_for), [_tool("read")], config, fixture)

    async def _write(
        self, fixture: FilesystemFixture, control: Callable[[Path, str], object]
    ) -> list[SmokeCheckResult]:
        """Answer every write call with ``control(path, content)``."""

        def answer_for(arguments: dict[str, Any]) -> object:
            return control(Path(arguments["path"]), arguments["content"])

        config = FilesystemProbeConfig(write_tool="write")
        return await run_filesystem_checks(_scripted_session(answer_for), [_tool("write")], config, fixture)

    @pytest.mark.parametrize(
        ("answer", "message", "called"),
        [
            (MCPError(REQUEST_TIMEOUT, "timeout"), "no answer within 30s — the boundary was not exercised", False),
            (MCPError(CONNECTION_CLOSED, "closed"), "connection closed during tools/call", False),
            (RuntimeError("transport"), "tools/call raised RuntimeError", False),
            (RawResult(inputRequests={}), "the answer is not a tool result", True),
        ],
    )
    async def test_unjudgeable_calls_skip(
        self, fixture: FilesystemFixture, answer: object, message: str, *, called: bool
    ) -> None:
        results = await self._read(fixture, answer)

        attempted = [r for r in results if "attempted_path" in r.details]
        assert attempted
        assert all(r.verdict is SmokeVerdict.SKIP and message in r.message for r in attempted)
        assert all(r.details["called"] is called for r in attempted)

    async def test_a_tool_that_answered_its_control_counts_as_called(self, fixture: FilesystemFixture) -> None:
        results = await self._read(fixture, MCPError(CONNECTION_CLOSED, "closed"))

        report = SmokeReport(executed=True, checks=results)
        assert report.tools_called == 1
        assert all(r.details["control_called"] is True for r in results)
        assert all(r.details.get("called") is not True for r in results)

    async def test_an_unanswered_write_control_is_not_counted_as_called(self, fixture: FilesystemFixture) -> None:
        def write_then_time_out(path: Path, content: str) -> object:
            if path.name == "write-control.txt":
                path.write_text(content, encoding="utf-8")
            return MCPError(REQUEST_TIMEOUT, "timeout")

        results = await self._write(fixture, write_then_time_out)

        assert SmokeReport(executed=True, checks=results).tools_called == 0
        assert all(r.details["control_called"] is False for r in results)

    async def test_protocol_error_is_a_rejection(self, fixture: FilesystemFixture) -> None:
        results = await self._read(fixture, MCPError(INTERNAL_ERROR, "boom"))

        attempted = [r for r in results if "attempted_path" in r.details]
        assert all(r.verdict is SmokeVerdict.PASS for r in attempted)
        assert all(r.message == f"rejected with JSON-RPC error {INTERNAL_ERROR}" for r in attempted)
        assert all(r.details["error_code"] == INTERNAL_ERROR for r in attempted)

    @pytest.mark.parametrize(
        "error",
        [MCPError(INTERNAL_ERROR, f"cannot parse: {CANARY_MARKER}"), MCPError(-32602, "bad", {"x": CANARY_MARKER})],
    )
    async def test_canary_in_a_protocol_error_fails(self, fixture: FilesystemFixture, error: MCPError) -> None:
        results = await self._read(fixture, error)

        attempted = [r for r in results if "attempted_path" in r.details]
        assert attempted
        assert all(r.verdict is SmokeVerdict.FAIL for r in attempted)

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
        session = _scripted_session(lambda _arguments: _text_result("ok"))

        results = await run_filesystem_checks(
            session, [_tool("read")], FilesystemProbeConfig(read_tool="read"), fixture
        )

        assert all("did not return its content" in r.message for r in results)

    async def test_write_control_protocol_error_explains_itself(self, fixture: FilesystemFixture) -> None:
        results = await self._write(fixture, lambda _path, _content: MCPError(-32602, "bad"))

        assert all(r.verdict is SmokeVerdict.SKIP for r in results)
        assert all("rejected with JSON-RPC error -32602" in r.message for r in results)

    async def test_write_control_success_without_a_file_explains_itself(self, fixture: FilesystemFixture) -> None:
        results = await self._write(fixture, lambda _path, _content: _text_result("ok"))

        assert all("did not create it" in r.message for r in results)

    async def test_write_control_in_another_encoding_is_a_mismatch(self, fixture: FilesystemFixture) -> None:
        def write_utf16(path: Path, content: str) -> object:
            path.write_bytes(content.encode("utf-16"))
            return _text_result("ok")

        results = await self._write(fixture, write_utf16)

        assert all(r.verdict is SmokeVerdict.SKIP and "did not create it" in r.message for r in results)

    async def test_write_skips_and_passes_by_outcome(self, fixture: FilesystemFixture) -> None:
        answers: list[object] = [MCPError(REQUEST_TIMEOUT, "t"), MCPError(-32602, "no")]

        def answer_for(arguments: dict[str, Any]) -> object:
            if arguments["path"].endswith("write-control.txt"):
                Path(arguments["path"]).write_text(WRITE_MARKER, encoding="utf-8")
                return _text_result("ok")
            return answers.pop(0) if answers else _text_result("ok")

        config = FilesystemProbeConfig(write_tool="write")
        results = await run_filesystem_checks(_scripted_session(answer_for), [_tool("write")], config, fixture)

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
