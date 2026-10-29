"""Filesystem boundary smoke check: does a filesystem tool stay inside its allowed root?

Opt-in twice over: it runs under ``--smoke`` only when the configuration has a
``[smoke.filesystem]`` table naming the tools to exercise, and only against a
``--stdio`` server whose command carries the ``{mcpscore_fs_root}``
placeholder. mcpscore builds a disposable fixture, passes its allowed
directory to the server through the placeholder, and asks the named tools to
read and write paths that resolve outside it::

    <fixture>/allowed/            the root the server is given
    <fixture>/allowed/inside.txt  positive control for reads
    <fixture>/allowed/link-out    symlink to <fixture>/outside
    <fixture>/allowed/*-link.txt  symlinks to files outside
    <fixture>/outside/canary.txt  canary: must never be read
    <fixture>/allowed-sibling/    shares the root's name as a prefix

Evidence is the canary, never the tool's word: a read fails when the response
contains the canary marker, a write fails when a file appears or changes
outside the allowed root. A positive control (reading or writing inside the
root) must work first; when it does not, every vector skips, so a broken tool
mapping is never credited as a boundary that holds.

Results join the smoke report under ``smoke_filesystem_boundary``; like every
smoke check, they never enter the score. Paths in the report are shown
relative to the fixture.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import tempfile
from typing import TYPE_CHECKING, Any

from mcp.shared.exceptions import MCPError
from mcp_types import CONNECTION_CLOSED, REQUEST_TIMEOUT, CallToolResult

from .smoke import SMOKE_CALL_TIMEOUT_S, SmokeCheckResult, SmokeVerdict

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mcp import ClientSession
    from mcp_types import Tool

CHECK_FILESYSTEM_BOUNDARY = "smoke_filesystem_boundary"

FS_ROOT_PLACEHOLDER = "{mcpscore_fs_root}"
"""Replaced in the ``--stdio`` command with the fixture's allowed directory."""

BASIS_FILESYSTEM_BOUNDARY = (
    "MCP 2025-11-25 Tools §Security Considerations (servers MUST validate all tool inputs and implement proper "
    "access controls); Roots §Security Considerations (servers SHOULD respect root boundaries and validate all paths)"
)

CANARY_MARKER = "mcpscore-filesystem-canary-outside-root"
"""Content of every file outside the allowed root. Seeing it in a response is the read failure."""

INSIDE_MARKER = "mcpscore-filesystem-control-inside-root"
"""Content of the read control file inside the root."""

WRITE_MARKER = "mcpscore-filesystem-write-probe"
"""Content the write probes send."""

OPERATION_READ = "read"
OPERATION_WRITE = "write"

_ROOT_NAME = "allowed"
_SIBLING_NAME = "allowed-sibling"
_OUTSIDE_NAME = "outside"
_CANARY_NAME = "canary.txt"
_INSIDE_NAME = "inside.txt"
_WRITE_CONTROL_NAME = "write-control.txt"
_LINK_DIR_NAME = "link-out"
_LINK_FILE_NAME = "canary-link.txt"
_WRITE_LINK_NAME = "write-link.txt"


@dataclass(frozen=True)
class FilesystemProbeConfig:
    """The ``[smoke.filesystem]`` table: which tools to exercise and how to pass them a path.

    At least one of ``read_tool`` and ``write_tool`` is set. Naming a tool here
    is the consent to call it, whatever its annotations say.
    """

    read_tool: str | None = None
    read_path_argument: str = "path"
    write_tool: str | None = None
    write_path_argument: str = "path"
    write_content_argument: str = "content"


@dataclass(frozen=True)
class BoundaryVector:
    """One way of naming a path outside the allowed root."""

    name: str
    read_path: str | None
    """Path that resolves to a canary file; None when the vector is unsupported here."""

    write_path: str | None
    """Path that resolves to a new file outside the root; None when unsupported."""

    unsupported: str | None = None
    """Why the vector cannot run on this platform or fixture."""


class FilesystemFixture:
    """A disposable directory tree with an allowed root, a sibling and an outside canary.

    Created before the server launches, so the root can be substituted into
    its command; removed by ``cleanup``. All paths are resolved, because a
    server that resolves its root (``/var`` → ``/private/var`` on macOS) must
    see the same spelling the probes send.
    """

    def __init__(self, base: Path) -> None:
        """Lay out the fixture under ``base``, an empty directory this object owns."""
        super().__init__()
        self.base = base.resolve()
        self.root = self.base / _ROOT_NAME
        self.sibling = self.base / _SIBLING_NAME
        self.outside = self.base / _OUTSIDE_NAME
        for directory in (self.root, self.sibling, self.outside):
            directory.mkdir()
        (self.root / _INSIDE_NAME).write_text(INSIDE_MARKER, encoding="utf-8")
        for directory in (self.sibling, self.outside):
            (directory / _CANARY_NAME).write_text(CANARY_MARKER, encoding="utf-8")
        self.symlink_error = self._make_symlinks()

    @classmethod
    def create(cls) -> FilesystemFixture:
        """Create a fixture in a fresh temporary directory."""
        return cls(Path(tempfile.mkdtemp(prefix="mcpscore-fs-")))

    def _make_symlinks(self) -> str | None:
        """Create the symlink escapes; return why they could not be created, or None."""
        try:
            (self.root / _LINK_DIR_NAME).symlink_to(self.outside, target_is_directory=True)
            (self.root / _LINK_FILE_NAME).symlink_to(self.outside / _CANARY_NAME)
            # Dangling until written through: a write that follows it lands outside.
            (self.root / _WRITE_LINK_NAME).symlink_to(self.outside / "written-symlink_file.txt")
        except OSError as e:
            return f"cannot create symlinks here ({e.strerror or type(e).__name__})"
        return None

    def substitute(self, value: str) -> str:
        """Replace the root placeholder in one command-line token."""
        return value.replace(FS_ROOT_PLACEHOLDER, str(self.root))

    def redact(self, path: str) -> str:
        """Show a path relative to the fixture, so the report carries no temp-directory names."""
        return path.replace(str(self.base), "<fixture>")

    def outside_state(self) -> dict[str, bytes]:
        """Snapshot every file outside the allowed root, keyed by fixture-relative path."""
        state: dict[str, bytes] = {}
        for directory in (self.sibling, self.outside):
            for path in sorted(directory.rglob("*")):
                if path.is_file() and not path.is_symlink():
                    state[path.relative_to(self.base).as_posix()] = path.read_bytes()
        return state

    def cleanup(self) -> None:
        """Remove the fixture; best effort, a leftover temp directory is not an audit failure."""
        shutil.rmtree(self.base, ignore_errors=True)

    def vectors(self, *, windows: bool | None = None) -> list[BoundaryVector]:
        """Every escape attempt, in a fixed order; Windows path forms only on Windows."""
        windows = os.name == "nt" if windows is None else windows
        sep = "\\" if windows else "/"
        root = str(self.root)

        def written(directory: Path, vector: str) -> Path:
            return directory / f"written-{vector}.txt"

        vectors = [
            BoundaryVector(
                "parent_traversal",
                f"{root}{sep}..{sep}{_OUTSIDE_NAME}{sep}{_CANARY_NAME}",
                f"{root}{sep}..{sep}{_OUTSIDE_NAME}{sep}{written(self.outside, 'parent_traversal').name}",
            ),
            BoundaryVector(
                "absolute_path",
                str(self.outside / _CANARY_NAME),
                str(written(self.outside, "absolute_path")),
            ),
            BoundaryVector(
                "sibling_prefix",
                str(self.sibling / _CANARY_NAME),
                str(written(self.sibling, "sibling_prefix")),
            ),
        ]
        if self.symlink_error is None:
            vectors += [
                BoundaryVector(
                    "symlink_directory",
                    str(self.root / _LINK_DIR_NAME / _CANARY_NAME),
                    str(self.root / _LINK_DIR_NAME / written(self.outside, "symlink_directory").name),
                ),
                BoundaryVector("symlink_file", str(self.root / _LINK_FILE_NAME), str(self.root / _WRITE_LINK_NAME)),
            ]
        else:
            vectors += [
                BoundaryVector("symlink_directory", None, None, self.symlink_error),
                BoundaryVector("symlink_file", None, None, self.symlink_error),
            ]
        if windows:
            forward = root.replace("\\", "/")
            vectors += [
                BoundaryVector(
                    "windows_forward_slash_traversal",
                    f"{forward}/../{_OUTSIDE_NAME}/{_CANARY_NAME}",
                    f"{forward}/../{_OUTSIDE_NAME}/{written(self.outside, 'windows_forward_slash_traversal').name}",
                ),
                BoundaryVector(
                    "windows_extended_length_path",
                    "\\\\?\\" + str(self.outside / _CANARY_NAME),
                    "\\\\?\\" + str(written(self.outside, "windows_extended_length_path")),
                ),
            ]
        else:
            reason = "Windows path form; runs on Windows only"
            vectors += [
                BoundaryVector("windows_forward_slash_traversal", None, None, reason),
                BoundaryVector("windows_extended_length_path", None, None, reason),
            ]
        return vectors


def _result(
    fixture: FilesystemFixture,
    tool: str,
    operation: str,
    vector: str,
    verdict: SmokeVerdict,
    message: str,
    path: str | None = None,
    **extra: Any,
) -> SmokeCheckResult:
    details: dict[str, Any] = {"basis": BASIS_FILESYSTEM_BOUNDARY, "operation": operation, "vector": vector}
    if path is not None:
        details["attempted_path"] = fixture.redact(path)
    return SmokeCheckResult(CHECK_FILESYSTEM_BOUNDARY, verdict, message, tool, {**details, **extra})


@dataclass(frozen=True)
class _CallOutcome:
    """What one probe call produced, reduced to what the verdicts need."""

    answered: bool
    """The server answered (a result or a JSON-RPC error), so the call counts as made."""

    text: str | None = None
    """The whole result serialized, for marker search; None when there was no result."""

    is_error: bool = False
    error_code: int | None = None
    failure: str | None = None
    """Why the call could not be judged (timeout, closed connection, client-side error)."""


async def _call(session: ClientSession, tool: str, arguments: dict[str, Any]) -> _CallOutcome:
    try:
        call_result = await session.call_tool(
            tool,
            arguments,
            read_timeout_seconds=SMOKE_CALL_TIMEOUT_S,
            allow_input_required=True,
            allow_claimed=True,
        )
    except MCPError as exc:
        if exc.code == REQUEST_TIMEOUT:
            return _CallOutcome(answered=False, failure=f"no answer within {SMOKE_CALL_TIMEOUT_S:.0f}s")
        if exc.code == CONNECTION_CLOSED:
            return _CallOutcome(answered=False, failure="connection closed during tools/call")
        return _CallOutcome(answered=True, is_error=True, error_code=exc.code)
    except Exception as exc:  # noqa: BLE001 — a smoke check never aborts the run
        return _CallOutcome(answered=False, failure=f"tools/call raised {type(exc).__name__}")
    if not isinstance(call_result, CallToolResult):
        return _CallOutcome(answered=False, failure="tool requested interactive input")
    return _CallOutcome(answered=True, text=call_result.model_dump_json(), is_error=bool(call_result.is_error))


def _observed(outcome: _CallOutcome) -> dict[str, Any]:
    """Describe the call in the ``details`` every probe result carries."""
    observed: dict[str, Any] = {"called": outcome.answered}
    if outcome.error_code is not None:
        observed["error_code"] = outcome.error_code
    return observed


def _rejection_message(outcome: _CallOutcome) -> str:
    if outcome.error_code is not None:
        return f"rejected with JSON-RPC error {outcome.error_code}"
    return "rejected with an isError tool result"


async def _read_checks(
    session: ClientSession, fixture: FilesystemFixture, config: FilesystemProbeConfig, tool: str
) -> list[SmokeCheckResult]:
    def read_arguments(path: str) -> dict[str, Any]:
        return {config.read_path_argument: path}

    vectors = fixture.vectors()
    control_path = str(fixture.root / _INSIDE_NAME)
    control = await _call(session, tool, read_arguments(control_path))
    if control.text is None or control.is_error or INSIDE_MARKER not in control.text:
        why = control.failure or (_rejection_message(control) if control.is_error else "did not return its content")
        reason = (
            f"positive control failed: reading <fixture>/{_ROOT_NAME}/{_INSIDE_NAME} {why} — check that the server "
            f"was given {FS_ROOT_PLACEHOLDER} as its root and that read_tool and read_path_argument are right"
        )
        return [
            _result(fixture, tool, OPERATION_READ, v.name, SmokeVerdict.SKIP, reason, called=control.answered)
            for v in vectors
        ]

    results = []
    for vector in vectors:
        if vector.read_path is None:
            results.append(
                _result(fixture, tool, OPERATION_READ, vector.name, SmokeVerdict.SKIP, vector.unsupported or "")
            )
            continue
        outcome = await _call(session, tool, read_arguments(vector.read_path))
        if outcome.text is not None and CANARY_MARKER in outcome.text:
            verdict, message = SmokeVerdict.FAIL, "returned the content of a file outside the allowed root"
        elif outcome.failure is not None:
            verdict, message = SmokeVerdict.SKIP, f"{outcome.failure} — the boundary was not exercised"
        elif outcome.is_error:
            verdict, message = SmokeVerdict.PASS, _rejection_message(outcome)
        else:
            verdict, message = SmokeVerdict.PASS, "answered without the outside file's content"
        extra = _observed(outcome)
        results.append(_result(fixture, tool, OPERATION_READ, vector.name, verdict, message, vector.read_path, **extra))
    return results


async def _write_checks(
    session: ClientSession, fixture: FilesystemFixture, config: FilesystemProbeConfig, tool: str
) -> list[SmokeCheckResult]:
    def write_arguments(path: str) -> dict[str, Any]:
        return {config.write_path_argument: path, config.write_content_argument: WRITE_MARKER}

    vectors = fixture.vectors()
    control_file = fixture.root / _WRITE_CONTROL_NAME
    control = await _call(session, tool, write_arguments(str(control_file)))
    try:
        control_written = control_file.read_text(encoding="utf-8") == WRITE_MARKER
    except OSError:
        control_written = False
    if not control_written:
        why = control.failure or (_rejection_message(control) if control.is_error else "did not create it")
        reason = (
            f"positive control failed: writing <fixture>/{_ROOT_NAME}/{_WRITE_CONTROL_NAME} {why} — check that the "
            f"server was given {FS_ROOT_PLACEHOLDER} as its root and that write_tool, write_path_argument and "
            "write_content_argument are right"
        )
        return [
            _result(fixture, tool, OPERATION_WRITE, v.name, SmokeVerdict.SKIP, reason, called=control.answered)
            for v in vectors
        ]

    results = []
    for vector in vectors:
        if vector.write_path is None:
            results.append(
                _result(fixture, tool, OPERATION_WRITE, vector.name, SmokeVerdict.SKIP, vector.unsupported or "")
            )
            continue
        before = fixture.outside_state()
        outcome = await _call(session, tool, write_arguments(vector.write_path))
        after = fixture.outside_state()
        changed = sorted(path for path in after if before.get(path) != after[path])
        extra = _observed(outcome)
        if changed:
            verdict, message = SmokeVerdict.FAIL, "wrote a file outside the allowed root"
            extra["changed_files"] = changed
        elif outcome.failure is not None:
            verdict, message = SmokeVerdict.SKIP, f"{outcome.failure} — the boundary was not exercised"
        elif outcome.is_error:
            verdict, message = SmokeVerdict.PASS, _rejection_message(outcome)
        else:
            verdict, message = SmokeVerdict.PASS, "answered without writing outside the allowed root"
        results.append(
            _result(fixture, tool, OPERATION_WRITE, vector.name, verdict, message, vector.write_path, **extra)
        )
    return results


def _missing_tool(tool: str, operation: str) -> SmokeCheckResult:
    return SmokeCheckResult(
        CHECK_FILESYSTEM_BOUNDARY,
        SmokeVerdict.SKIP,
        f"{tool!r} is named in [smoke.filesystem] but is not in the server's tool catalog",
        tool,
        {"basis": BASIS_FILESYSTEM_BOUNDARY, "operation": operation},
    )


def not_runnable(reason: str) -> list[SmokeCheckResult]:
    """Build the single skip reported when the configured check cannot run at all."""
    return [
        SmokeCheckResult(
            CHECK_FILESYSTEM_BOUNDARY, SmokeVerdict.SKIP, reason, None, {"basis": BASIS_FILESYSTEM_BOUNDARY}
        )
    ]


async def run_filesystem_checks(
    session: ClientSession,
    tools: Sequence[Tool] | None,
    config: FilesystemProbeConfig,
    fixture: FilesystemFixture,
) -> list[SmokeCheckResult]:
    """Run the read and write boundary probes for the tools ``config`` names.

    Sequential, like the other smoke checks, so each change outside the root
    is attributable to exactly one call.
    """
    listed = {tool.name for tool in tools or []}
    results: list[SmokeCheckResult] = []
    for tool, operation, checks in (
        (config.read_tool, OPERATION_READ, _read_checks),
        (config.write_tool, OPERATION_WRITE, _write_checks),
    ):
        if tool is None:
            continue
        if tool not in listed:
            results.append(_missing_tool(tool, operation))
            continue
        results.extend(await checks(session, fixture, config, tool))
    return results
