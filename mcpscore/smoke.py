"""Smoke checks: opt-in ``tools/call`` verification behind the ``--smoke`` flag.

The audit never invokes ``tools/call`` — that invariant is what makes it safe
to point mcpscore at anyone's server. Smoke mode is the separate surface for
developers running mcpscore against their OWN server (typically in CI), where
invoking tools is the point: it verifies what listing alone cannot prove.

Checks (verdicts are pass / fail / skip — skip when a check could not be
exercised, e.g. an upstream outage must not fail the build):

- **Structured-content honesty**: every callable tool declaring an
  ``outputSchema`` is invoked; the result must carry conforming
  ``structuredContent`` (MCP 2025-11-25 Tools §Output Schema: servers MUST
  provide structured results that conform to the schema).
- **Invalid-argument rejection**: each callable tool is invoked with
  deliberately schema-invalid arguments and must reject them — an
  ``isError`` tool result or a JSON-RPC error are both proper rejections
  (MCP 2025-11-25 Tools §Error Handling); accepting them, hanging, or
  crashing fails.
- **Unknown-tool rejection**: ``tools/call`` on a nonexistent name must be
  rejected with a protocol error (MCP 2025-11-25 Tools §Error Handling,
  e.g. ``-32602 Unknown tool``), not executed and not a server crash.

Safety default: only tools annotated ``readOnlyHint: true`` are called;
``--call-all`` is the explicit second consent for everything else. Argument
synthesis is deterministic (defaults / const / examples / enum-first / type
zero-values — never an LLM), so the same server sees the same calls.

Smoke results never enter the 0-100 score and are reported in their own
``smoke`` report section; a smoke failure is its own CLI exit code (4). This
module is used by the CLI only — the web service never invokes tools.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import logging
from typing import TYPE_CHECKING, Any

from mcp.shared.exceptions import MCPError
from mcp_types import CONNECTION_CLOSED, INTERNAL_ERROR as ERROR_INTERNAL, REQUEST_TIMEOUT, CallToolResult

from .probes import ERROR_INVALID_PARAMS

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mcp import ClientSession
    from mcp_types import Tool

logger = logging.getLogger(__name__)

SMOKE_CALL_TIMEOUT_S = 30.0
"""Per-call deadline. A tool that cannot answer within this is reported as a
hang (invalid-argument check) or as unexercisable (structured-content check)."""

UNKNOWN_TOOL_NAME = "mcpscore_smoke_nonexistent_tool"
"""Deliberately fixed base name, not random: deterministic calls are part of
the smoke contract (same server, same calls). It is nevertheless a *legal*
tool name, so ``derive_unknown_tool_name`` proves absence against the
collected catalog instead of trusting implausibility."""

CHECK_STRUCTURED_CONTENT = "smoke_structured_content"
CHECK_INVALID_ARGUMENTS = "smoke_invalid_arguments"
CHECK_UNKNOWN_TOOL = "smoke_unknown_tool"

BASIS_OUTPUT_SCHEMA = "MCP 2025-11-25 Tools §Output Schema (structured results MUST conform to the declared schema)"
BASIS_ERROR_HANDLING = "MCP 2025-11-25 Tools §Error Handling (isError tool result or JSON-RPC protocol error)"
BASIS_UNKNOWN_TOOL = "MCP 2025-11-25 Tools §Error Handling (unknown tool → protocol error, e.g. -32602)"

_SAFETY_SKIP_REASON = "not called under the safety default (readOnlyHint is not true); pass --call-all to include it"

_SYNTHESIS_MAX_DEPTH = 4
"""Recursion bound for nested object synthesis. Shallow by design: sample
values come from the schema's own hints, not from exploring its full space."""


class SmokeVerdict(StrEnum):
    """Outcome of one smoke check observation."""

    PASS = "pass"  # noqa: S105 — a verdict label, not a password
    """The server exhibited the required behavior."""

    FAIL = "fail"
    """The server violated the checked contract."""

    SKIP = "skip"
    """The check could not be exercised (no schema declared, tool not callable
    under the safety default, upstream outage). Never a failure: someone
    else's outage must not fail the build."""


@dataclass(frozen=True)
class SmokeCheckResult:
    """Recorded outcome of one smoke check against one subject."""

    check_id: str
    """Stable identifier of the check that produced this result."""

    verdict: SmokeVerdict

    message: str
    """Human-readable explanation of the verdict."""

    tool_name: str | None = None
    """The tool this observation is about, or None for server-level checks."""

    details: dict[str, Any] = field(default_factory=dict)
    """Raw observations (JSON-RPC error codes, spec basis) kept small — the
    same policy as ``ProbeResult.details``."""

    def to_dict(self) -> dict:
        """Serialize this result for the machine-readable report."""
        return {
            "check_id": self.check_id,
            "tool_name": self.tool_name,
            "verdict": self.verdict.value,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class SmokeReport:
    """Every smoke observation from one ``--smoke`` run.

    Deliberately not part of the scored report: smoke verdicts depend on
    upstreams and environment, and determinism ("same server, same score") is
    the audit's contract. The CLI reports smoke in its own section and its
    own exit code.
    """

    executed: bool
    """False when --smoke was requested but no session was available to call
    tools on (partial and modern-only audits have none)."""

    reason: str | None = None
    """Why the checks did not run; None when ``executed``."""

    call_all: bool = False
    """Whether --call-all lifted the readOnlyHint safety default."""

    checks: list[SmokeCheckResult] = field(default_factory=list)

    @classmethod
    def not_executed(cls, reason: str) -> SmokeReport:
        """Build the report for a --smoke request that had no session to run on."""
        return cls(executed=False, reason=reason)

    def _count(self, verdict: SmokeVerdict) -> int:
        return sum(1 for check in self.checks if check.verdict is verdict)

    @property
    def passed(self) -> int:
        """Number of checks that passed."""
        return self._count(SmokeVerdict.PASS)

    @property
    def failed(self) -> int:
        """Number of checks that failed."""
        return self._count(SmokeVerdict.FAIL)

    @property
    def skipped(self) -> int:
        """Number of checks that could not be exercised."""
        return self._count(SmokeVerdict.SKIP)

    def to_dict(self) -> dict:
        """Serialize the smoke section for the machine-readable report."""
        return {
            "executed": self.executed,
            "reason": self.reason,
            "call_all": self.call_all,
            "summary": {"passed": self.passed, "failed": self.failed, "skipped": self.skipped},
            "checks": [check.to_dict() for check in self.checks],
        }


def synthesize_value(schema: object, depth: int = 0) -> Any:
    """Derive one deterministic sample value from a JSON Schema fragment.

    Preference order: ``default`` > ``const`` > first example > first enum
    entry > first ``anyOf``/``oneOf`` branch > the type's zero value. Nested
    objects recurse (required properties only) down to a shallow bound;
    anything unresolvable becomes None — the server may then reject the call,
    which reports as a skip, never a wrong verdict.
    """
    if depth >= _SYNTHESIS_MAX_DEPTH or not isinstance(schema, dict):
        return None
    if "default" in schema:
        return schema["default"]
    if "const" in schema:
        return schema["const"]
    examples = schema.get("examples")
    if isinstance(examples, list) and examples:
        return examples[0]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    for branch_key in ("anyOf", "oneOf"):
        branches = schema.get(branch_key)
        if isinstance(branches, list) and branches:
            return synthesize_value(branches[0], depth + 1)
    declared = schema.get("type")
    if isinstance(declared, list) and declared:
        declared = declared[0]
    zero_values: dict[str, Any] = {"string": "", "number": 0, "integer": 0, "boolean": False, "array": [], "null": None}
    if declared == "object":
        return _synthesize_object(schema, depth + 1)
    return zero_values.get(declared) if isinstance(declared, str) else None


def _synthesize_object(schema: dict[str, Any], depth: int) -> dict[str, Any]:
    """Build an object with a sample value for each required, declared property."""
    properties = schema.get("properties")
    required = schema.get("required")
    if not isinstance(properties, dict) or not isinstance(required, list):
        return {}
    # Required entries must be strings before any dict lookup: a model-accepted
    # but malformed schema (e.g. required: [[]]) would otherwise raise TypeError
    # and abort the whole smoke run from the invalid-arguments path, which
    # synthesizes outside its try.
    return {
        name: synthesize_value(properties.get(name), depth)
        for name in required
        if isinstance(name, str) and isinstance(properties.get(name), dict)
    }


def synthesize_arguments(input_schema: object) -> dict[str, Any]:
    """Derive deterministic, schema-satisfying ``tools/call`` arguments.

    Required properties only: optional ones add nothing to whether the call
    can be exercised, and fewer synthesized values mean fewer chances to feed
    a tool something its runtime validation rejects.
    """
    if not isinstance(input_schema, dict):
        return {}
    return _synthesize_object(input_schema, 0)


_WRONG_TYPED_VALUES: dict[str, Any] = {
    "string": 42,
    "number": "not-a-number",
    "integer": "not-an-integer",
    "boolean": "not-a-boolean",
    "array": {"invalid": True},
    "object": "not-an-object",
    "null": 0,
}
"""For each single declared JSON type, a value violating it."""


def synthesize_invalid_arguments(input_schema: object) -> dict[str, Any] | None:
    """Derive arguments that violate the tool's input schema, or None.

    Valid arguments with exactly one deliberate violation: the first declared
    property with a single, violable type gets a value of the wrong type. A
    schema that constrains nothing (no typed properties — e.g. the bare
    ``{"type": "object"}``) offers nothing to violate, and the check must
    skip rather than send arguments the server is entitled to accept.
    """
    if not isinstance(input_schema, dict):
        return None
    properties = input_schema.get("properties")
    if not isinstance(properties, dict):
        return None
    for name, subschema in properties.items():
        if not isinstance(subschema, dict):
            continue
        declared = subschema.get("type")
        if isinstance(declared, str) and declared in _WRONG_TYPED_VALUES:
            arguments = synthesize_arguments(input_schema)
            arguments[name] = _WRONG_TYPED_VALUES[declared]
            return arguments
    return None


def _tool_skip_reason(tool: Tool, *, call_all: bool) -> str | None:
    """Why this tool is not callable, or None when it is.

    The safety default calls only tools that affirmatively annotate
    ``readOnlyHint: true`` — an absent annotation defaults to false per the
    spec, so unannotated tools are skipped, never called. That skipped
    coverage is the visible cost of not annotating.
    """
    if call_all:
        return None
    annotations = tool.annotations
    if annotations is not None and annotations.read_only_hint is True:
        return None
    return _SAFETY_SKIP_REASON


async def _check_structured_content(session: ClientSession, tool: Tool, skip_reason: str | None) -> SmokeCheckResult:
    """Verify a tool honors its declared ``outputSchema`` when actually called."""
    details = {"basis": BASIS_OUTPUT_SCHEMA}

    def result(verdict: SmokeVerdict, message: str, **extra: Any) -> SmokeCheckResult:
        return SmokeCheckResult(CHECK_STRUCTURED_CONTENT, verdict, message, tool.name, {**details, **extra})

    if skip_reason is not None:
        return result(SmokeVerdict.SKIP, skip_reason)
    # `is None`, not truthiness: an empty {} is a declared, valid schema that
    # anything conforms to, but the spec still requires structuredContent to
    # be PRESENT for it — the check must run.
    if tool.output_schema is None:
        return result(SmokeVerdict.SKIP, "no outputSchema declared — nothing to verify against")
    try:
        # The SDK validates a successful result's structuredContent against
        # the declared outputSchema and raises RuntimeError on a violation —
        # the exact failure a schema-compiling client would hit in production.
        call_result = await session.call_tool(
            tool.name,
            synthesize_arguments(tool.input_schema),
            read_timeout_seconds=SMOKE_CALL_TIMEOUT_S,
            allow_input_required=True,
            allow_claimed=True,
        )
    except RuntimeError as exc:
        # The SDK's message embeds jsonschema's multi-line validation dump;
        # its first line carries the diagnosis and the rest is noise in a
        # log line or a JSON report field.
        first_line = str(exc).partition("\n")[0]
        return result(SmokeVerdict.FAIL, f"declared outputSchema is not honored: {first_line}")
    except MCPError as exc:
        return result(
            SmokeVerdict.SKIP,
            f"tools/call answered JSON-RPC error {exc.code} — the schema could not be exercised "
            "(the server may have rejected the synthesized arguments)",
            error_code=exc.code,
        )
    except Exception as exc:  # noqa: BLE001 — a smoke check never aborts the run
        return result(SmokeVerdict.SKIP, f"tools/call raised {type(exc).__name__} — the schema could not be exercised")
    if not isinstance(call_result, CallToolResult):
        return result(SmokeVerdict.SKIP, "tool requested interactive input — not judgeable in an unattended run")
    if call_result.is_error:
        return result(
            SmokeVerdict.SKIP,
            "tool returned an error result (an upstream outage, or the synthesized arguments were rejected) — "
            "someone else's outage must not fail the build",
        )
    return result(SmokeVerdict.PASS, "structuredContent conforms to the declared outputSchema")


async def _check_invalid_arguments(session: ClientSession, tool: Tool, skip_reason: str | None) -> SmokeCheckResult:
    """Verify a tool rejects deliberately schema-invalid arguments."""
    details = {"basis": BASIS_ERROR_HANDLING}

    def result(verdict: SmokeVerdict, message: str, **extra: Any) -> SmokeCheckResult:
        return SmokeCheckResult(CHECK_INVALID_ARGUMENTS, verdict, message, tool.name, {**details, **extra})

    if skip_reason is not None:
        return result(SmokeVerdict.SKIP, skip_reason)
    try:
        invalid_arguments = synthesize_invalid_arguments(tool.input_schema)
    except Exception as exc:  # noqa: BLE001 — a smoke check never aborts the run
        return result(
            SmokeVerdict.SKIP,
            f"could not derive schema-invalid arguments ({type(exc).__name__}) — nothing invalid to send",
        )
    if invalid_arguments is None:
        return result(SmokeVerdict.SKIP, "inputSchema declares no typed property to violate — nothing invalid to send")
    try:
        call_result = await session.call_tool(
            tool.name,
            invalid_arguments,
            read_timeout_seconds=SMOKE_CALL_TIMEOUT_S,
            allow_input_required=True,
            allow_claimed=True,
        )
    except MCPError as exc:
        if exc.code == REQUEST_TIMEOUT:
            return result(
                SmokeVerdict.FAIL,
                f"no answer within {SMOKE_CALL_TIMEOUT_S:.0f}s of a schema-invalid call — a hang, not a rejection",
                error_code=exc.code,
            )
        if exc.code == CONNECTION_CLOSED:
            # The SDK reports a dead transport as this MCPError — a crash,
            # not the server rejecting anything.
            return result(
                SmokeVerdict.FAIL,
                "connection closed on a schema-invalid call — a crash, not a rejection",
                error_code=exc.code,
            )
        if exc.code == ERROR_INTERNAL:
            # Same stance as the unknown-tool check: an internal error means
            # the server tried to run the call and broke, not that it
            # rejected the arguments.
            return result(
                SmokeVerdict.FAIL,
                f"answered JSON-RPC internal error {exc.code} to schema-invalid arguments — a server-side "
                "crash, not a rejection",
                error_code=exc.code,
            )
        return result(SmokeVerdict.PASS, f"rejected with JSON-RPC error {exc.code}", error_code=exc.code)
    except RuntimeError:
        # The SDK's output-schema validation fired, meaning the server
        # produced a (broken) success result for schema-invalid input.
        return result(SmokeVerdict.FAIL, "accepted schema-invalid arguments (returned a result, not a rejection)")
    except Exception as exc:  # noqa: BLE001 — a smoke check never aborts the run
        return result(SmokeVerdict.FAIL, f"tools/call with schema-invalid arguments crashed: {type(exc).__name__}")
    if isinstance(call_result, CallToolResult) and call_result.is_error:
        return result(SmokeVerdict.PASS, "rejected with an isError tool result")
    if not isinstance(call_result, CallToolResult):
        return result(SmokeVerdict.FAIL, "accepted schema-invalid arguments (requested further input, not a rejection)")
    return result(SmokeVerdict.FAIL, "accepted schema-invalid arguments (returned a success result)")


def derive_unknown_tool_name(tools: Sequence[Tool]) -> str:
    """Derive a deterministic tool name provably absent from the catalog.

    The base name is fixed for determinism, but it is a *legal* MCP tool name
    a server could really expose — and calling a real tool here would bypass
    the readOnlyHint safety default. Deterministic suffixes sidestep any
    collision; the input is the server's own catalog, so the same server
    state still yields the same call.
    """
    existing = {tool.name for tool in tools}
    candidate = UNKNOWN_TOOL_NAME
    suffix = 2
    while candidate in existing:
        candidate = f"{UNKNOWN_TOOL_NAME}_{suffix}"
        suffix += 1
    return candidate


async def _check_unknown_tool(session: ClientSession, unknown_name: str) -> SmokeCheckResult:
    """Verify the server rejects a nonexistent tool name with a protocol error."""
    details = {"basis": BASIS_UNKNOWN_TOOL, "requested_tool": unknown_name}

    def result(verdict: SmokeVerdict, message: str, **extra: Any) -> SmokeCheckResult:
        return SmokeCheckResult(CHECK_UNKNOWN_TOOL, verdict, message, None, {**details, **extra})

    try:
        call_result = await session.call_tool(
            unknown_name,
            {},
            read_timeout_seconds=SMOKE_CALL_TIMEOUT_S,
            allow_input_required=True,
            allow_claimed=True,
        )
    except MCPError as exc:
        # The spec's unknown-tool example is -32602, but the code is
        # exemplary, not mandated — any JSON-RPC error the server sends is a
        # rejection. The failures are the non-rejections: a hang, a dead
        # transport (the SDK surfaces it as CONNECTION_CLOSED), and an
        # internal error (the server tried to execute the name and broke —
        # the "500" this check exists to catch).
        if exc.code == REQUEST_TIMEOUT:
            return result(
                SmokeVerdict.FAIL,
                f"no answer within {SMOKE_CALL_TIMEOUT_S:.0f}s of calling a nonexistent tool — a hang, not a rejection",
                error_code=exc.code,
            )
        if exc.code == CONNECTION_CLOSED:
            return result(
                SmokeVerdict.FAIL,
                "connection closed on a nonexistent tool call — a crash, not a rejection",
                error_code=exc.code,
            )
        if exc.code == ERROR_INTERNAL:
            return result(
                SmokeVerdict.FAIL,
                f"answered JSON-RPC internal error {exc.code} — a server-side crash, not a rejection "
                f"(the spec's unknown-tool example is {ERROR_INVALID_PARAMS})",
                error_code=exc.code,
            )
        return result(SmokeVerdict.PASS, f"rejected with JSON-RPC error {exc.code}", error_code=exc.code)
    except Exception as exc:  # noqa: BLE001 — a smoke check never aborts the run
        return result(SmokeVerdict.FAIL, f"tools/call on a nonexistent tool crashed: {type(exc).__name__}")
    if isinstance(call_result, CallToolResult) and call_result.is_error:
        return result(
            SmokeVerdict.FAIL,
            "reported a tool execution error (isError) for a nonexistent tool — the spec's unknown-tool "
            "example is a protocol error, and an isError result claims the tool exists and ran",
        )
    return result(SmokeVerdict.FAIL, "answered a nonexistent tool name with a result instead of rejecting it")


async def run_smoke_checks(
    session: ClientSession,
    tools: Sequence[Tool] | None,
    *,
    call_all: bool,
    catalog_complete: bool,
) -> SmokeReport:
    """Run every smoke check sequentially on the audit's established session.

    Sequential on purpose: one in-flight ``tools/call`` at a time keeps the
    server's observed behavior attributable to one request, and keeps the
    order of calls deterministic.

    Args:
        session: The live session the audit connected (never closed by the
            auditor; the CLI's cleanup closes it afterwards).
        tools: The audit's collected tool listing (None when listing failed).
        call_all: Lift the readOnlyHint safety default (--call-all).
        catalog_complete: Whether ``tools`` is the server's complete catalog.
            The unknown-tool check calls a name chosen for being absent from
            it; with a missing or incomplete catalog, nonexistence cannot be
            established and the probe could invoke a real, unannotated tool —
            so that check skips instead.

    """
    report = SmokeReport(executed=True, call_all=call_all)
    for tool in tools or []:
        skip_reason = _tool_skip_reason(tool, call_all=call_all)
        report.checks.append(await _check_structured_content(session, tool, skip_reason))
    for tool in tools or []:
        skip_reason = _tool_skip_reason(tool, call_all=call_all)
        report.checks.append(await _check_invalid_arguments(session, tool, skip_reason))
    if tools is None or not catalog_complete:
        report.checks.append(
            SmokeCheckResult(
                CHECK_UNKNOWN_TOOL,
                SmokeVerdict.SKIP,
                "tool catalog unavailable or incomplete — a name cannot be proven nonexistent, and calling a "
                "possibly-real tool would bypass the safety default",
                None,
                {"basis": BASIS_UNKNOWN_TOOL},
            )
        )
    else:
        report.checks.append(await _check_unknown_tool(session, derive_unknown_tool_name(tools)))
    return report
