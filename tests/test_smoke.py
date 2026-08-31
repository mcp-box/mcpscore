"""Tests for the --smoke check module.

Covers the deterministic argument synthesis, the verdict logic of each check
against a scripted fake session (every pass/fail/skip branch), and the
report/serialization shapes. The CLI wiring (flags, exit code 4, the smoke
report section) is tested in test_cli.py; the real-process integration runs
in test_smoke_stdio_e2e.py against a fixture server.
"""

from __future__ import annotations

from typing import Any

from mcp.shared.exceptions import MCPError
from mcp_types import REQUEST_TIMEOUT, CallToolResult, Tool, ToolAnnotations
import pytest

from mcpscore.smoke import (
    CHECK_INVALID_ARGUMENTS,
    CHECK_STRUCTURED_CONTENT,
    CHECK_UNKNOWN_TOOL,
    SMOKE_CALL_TIMEOUT_S,
    UNKNOWN_TOOL_NAME,
    SmokeCheckResult,
    SmokeReport,
    SmokeVerdict,
    run_smoke_checks,
    synthesize_arguments,
    synthesize_invalid_arguments,
    synthesize_value,
)

ERROR_INVALID_PARAMS = -32602
ERROR_METHOD_NOT_FOUND = -32601
ERROR_INTERNAL = -32603


class FakeSession:
    """Scripted stand-in for mcp.ClientSession.call_tool.

    ``behaviors`` maps a tool name to either an exception instance (raised) or
    a return value. Records every call for assertions on order, arguments,
    and the safety default.
    """

    def __init__(self, behaviors: dict[str, Any] | None = None, default: Any = None) -> None:
        self.behaviors = behaviors or {}
        self.default = default if default is not None else CallToolResult(content=[])
        self.calls: list[tuple[str, dict[str, Any] | None]] = []

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: float | None = None,
        **kwargs: Any,
    ) -> Any:
        assert read_timeout_seconds == SMOKE_CALL_TIMEOUT_S
        assert kwargs == {"allow_input_required": True, "allow_claimed": True}
        self.calls.append((name, arguments))
        behavior = self.behaviors.get(name, self.default)
        if isinstance(behavior, BaseException):
            raise behavior
        return behavior


def read_only_tool(
    name: str = "reader",
    *,
    input_schema: dict[str, Any] | None = None,
    output_schema: dict[str, Any] | None = None,
) -> Tool:
    return Tool(
        name=name,
        input_schema=input_schema or {"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]},
        output_schema=output_schema,
        annotations=ToolAnnotations(read_only_hint=True),
    )


OUTPUT_SCHEMA = {"type": "object", "properties": {"result": {"type": "string"}}, "required": ["result"]}


async def single_check(session: FakeSession, tool: Tool, check_id: str, *, call_all: bool = False) -> SmokeCheckResult:
    """Run the smoke suite for one tool and return its result for one check."""
    report = await run_smoke_checks(session, [tool], call_all=call_all)  # type: ignore[arg-type]
    matches = [check for check in report.checks if check.check_id == check_id]
    assert len(matches) == 1
    return matches[0]


class TestSynthesizeValue:
    """The deterministic sample-value derivation, hint by hint."""

    @pytest.mark.parametrize(
        ("schema", "expected"),
        [
            ({"type": "integer", "default": 7}, 7),
            ({"type": "string", "const": "fixed"}, "fixed"),
            ({"type": "string", "examples": ["first", "second"]}, "first"),
            ({"type": "string", "enum": ["red", "green"]}, "red"),
            ({"anyOf": [{"type": "integer"}, {"type": "string"}]}, 0),
            ({"oneOf": [{"type": "boolean"}]}, False),
            ({"type": "string"}, ""),
            ({"type": "number"}, 0),
            ({"type": "integer"}, 0),
            ({"type": "boolean"}, False),
            ({"type": "array"}, []),
            ({"type": "null"}, None),
            ({"type": ["string", "integer"]}, ""),
            ({"type": []}, None),
            ({}, None),
            ("not-a-schema", None),
        ],
    )
    def test_hint_preference_and_zero_values(self, schema: Any, expected: Any) -> None:
        assert synthesize_value(schema) == expected

    def test_default_wins_over_every_other_hint(self) -> None:
        schema = {"default": "d", "const": "c", "examples": ["e"], "enum": ["n"], "type": "string"}
        assert synthesize_value(schema) == "d"

    def test_empty_examples_and_enum_fall_through_to_type(self) -> None:
        assert synthesize_value({"type": "integer", "examples": [], "enum": []}) == 0

    def test_nested_object_recurses_required_properties_only(self) -> None:
        schema = {
            "type": "object",
            "properties": {"inner": {"type": "string"}, "optional": {"type": "integer"}},
            "required": ["inner"],
        }
        assert synthesize_value(schema) == {"inner": ""}

    def test_recursion_depth_is_bounded(self) -> None:
        schema: dict[str, Any] = {"type": "string"}
        for _ in range(10):
            schema = {"type": "object", "properties": {"n": schema}, "required": ["n"]}
        value = synthesize_value(schema)
        # The bound truncates the nesting to None instead of recursing forever.
        depth = 0
        while isinstance(value, dict):
            value = value.get("n")
            depth += 1
        assert value is None
        assert depth < 10


class TestSynthesizeArguments:
    def test_object_schema_yields_required_arguments(self) -> None:
        schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}, "count": {"type": "integer", "default": 3}},
            "required": ["name", "count"],
        }
        assert synthesize_arguments(schema) == {"name": "", "count": 3}

    @pytest.mark.parametrize("schema", [None, "x", {"type": "object"}, {"type": "object", "properties": {}}])
    def test_unconstrained_or_invalid_schemas_yield_empty_arguments(self, schema: Any) -> None:
        assert synthesize_arguments(schema) == {}

    def test_required_name_without_a_property_schema_is_omitted(self) -> None:
        schema = {"type": "object", "properties": {"a": {"type": "string"}, "b": True}, "required": ["a", "b", "c"]}
        assert synthesize_arguments(schema) == {"a": ""}


class TestSynthesizeInvalidArguments:
    @pytest.mark.parametrize(
        ("declared", "wrong"),
        [
            ("string", 42),
            ("number", "not-a-number"),
            ("integer", "not-an-integer"),
            ("boolean", "not-a-boolean"),
            ("array", {"invalid": True}),
            ("object", "not-an-object"),
            ("null", 0),
        ],
    )
    def test_first_typed_property_gets_a_wrong_typed_value(self, declared: str, wrong: Any) -> None:
        schema = {"type": "object", "properties": {"p": {"type": declared}}, "required": ["p"]}
        assert synthesize_invalid_arguments(schema) == {"p": wrong}

    def test_other_required_properties_stay_valid(self) -> None:
        schema = {
            "type": "object",
            "properties": {"first": {"type": "string"}, "second": {"type": "integer"}},
            "required": ["first", "second"],
        }
        assert synthesize_invalid_arguments(schema) == {"first": 42, "second": 0}

    @pytest.mark.parametrize(
        "schema",
        [
            None,
            {"type": "object"},
            {"type": "object", "properties": {}},
            {"type": "object", "properties": {"untyped": {}}},
            {"type": "object", "properties": {"union": {"type": ["string", "integer"]}}},
            {"type": "object", "properties": {"bool_schema": True}},
        ],
    )
    def test_nothing_violable_yields_none(self, schema: Any) -> None:
        assert synthesize_invalid_arguments(schema) is None


class TestStructuredContentCheck:
    async def test_conforming_result_passes(self) -> None:
        tool = read_only_tool(output_schema=OUTPUT_SCHEMA)
        session = FakeSession({"reader": CallToolResult(content=[], structured_content={"result": "ok"})})
        check = await single_check(session, tool, CHECK_STRUCTURED_CONTENT)
        assert check.verdict is SmokeVerdict.PASS
        assert check.tool_name == "reader"

    async def test_sdk_validation_error_fails(self) -> None:
        tool = read_only_tool(output_schema=OUTPUT_SCHEMA)
        session = FakeSession({"reader": RuntimeError("Invalid structured content returned by tool reader")})
        check = await single_check(session, tool, CHECK_STRUCTURED_CONTENT)
        assert check.verdict is SmokeVerdict.FAIL
        assert "not honored" in check.message

    async def test_no_output_schema_skips(self) -> None:
        session = FakeSession()
        check = await single_check(session, read_only_tool(), CHECK_STRUCTURED_CONTENT)
        assert check.verdict is SmokeVerdict.SKIP
        assert "no outputSchema" in check.message
        # The tool is never called with valid arguments: only the
        # invalid-arguments check (wrong-typed q) touched it.
        assert ("reader", {"q": ""}) not in session.calls

    async def test_error_result_skips_as_possible_outage(self) -> None:
        tool = read_only_tool(output_schema=OUTPUT_SCHEMA)
        session = FakeSession({"reader": CallToolResult(content=[], is_error=True)})
        check = await single_check(session, tool, CHECK_STRUCTURED_CONTENT)
        assert check.verdict is SmokeVerdict.SKIP
        assert "outage" in check.message

    async def test_jsonrpc_error_skips_with_code(self) -> None:
        tool = read_only_tool(output_schema=OUTPUT_SCHEMA)
        session = FakeSession({"reader": MCPError(code=ERROR_INVALID_PARAMS, message="bad args")})
        check = await single_check(session, tool, CHECK_STRUCTURED_CONTENT)
        assert check.verdict is SmokeVerdict.SKIP
        assert check.details["error_code"] == ERROR_INVALID_PARAMS

    async def test_transport_exception_skips(self) -> None:
        tool = read_only_tool(output_schema=OUTPUT_SCHEMA)
        session = FakeSession({"reader": ConnectionError("boom")})
        check = await single_check(session, tool, CHECK_STRUCTURED_CONTENT)
        assert check.verdict is SmokeVerdict.SKIP
        assert "ConnectionError" in check.message

    async def test_interactive_result_skips(self) -> None:
        tool = read_only_tool(output_schema=OUTPUT_SCHEMA)
        session = FakeSession({"reader": object()})
        check = await single_check(session, tool, CHECK_STRUCTURED_CONTENT)
        assert check.verdict is SmokeVerdict.SKIP
        assert "interactive" in check.message

    async def test_synthesized_arguments_are_sent(self) -> None:
        tool = read_only_tool(output_schema=OUTPUT_SCHEMA)
        session = FakeSession({"reader": CallToolResult(content=[], structured_content={"result": "ok"})})
        await single_check(session, tool, CHECK_STRUCTURED_CONTENT)
        assert ("reader", {"q": ""}) in session.calls


class TestInvalidArgumentsCheck:
    async def test_jsonrpc_rejection_passes(self) -> None:
        session = FakeSession({"reader": MCPError(code=ERROR_INVALID_PARAMS, message="bad args")})
        check = await single_check(session, read_only_tool(), CHECK_INVALID_ARGUMENTS)
        assert check.verdict is SmokeVerdict.PASS
        assert check.details["error_code"] == ERROR_INVALID_PARAMS

    async def test_is_error_rejection_passes(self) -> None:
        session = FakeSession({"reader": CallToolResult(content=[], is_error=True)})
        check = await single_check(session, read_only_tool(), CHECK_INVALID_ARGUMENTS)
        assert check.verdict is SmokeVerdict.PASS
        assert "isError" in check.message

    async def test_success_result_fails(self) -> None:
        session = FakeSession({"reader": CallToolResult(content=[])})
        check = await single_check(session, read_only_tool(), CHECK_INVALID_ARGUMENTS)
        assert check.verdict is SmokeVerdict.FAIL
        assert "accepted schema-invalid arguments" in check.message

    async def test_timeout_fails_as_hang(self) -> None:
        session = FakeSession({"reader": MCPError(code=REQUEST_TIMEOUT, message="timed out")})
        check = await single_check(session, read_only_tool(), CHECK_INVALID_ARGUMENTS)
        assert check.verdict is SmokeVerdict.FAIL
        assert "hang" in check.message

    async def test_sdk_validation_error_fails_as_acceptance(self) -> None:
        # The server produced a (schema-violating) success result for invalid
        # input — the defect is the acceptance, not the content.
        session = FakeSession({"reader": RuntimeError("Invalid structured content")})
        check = await single_check(session, read_only_tool(), CHECK_INVALID_ARGUMENTS)
        assert check.verdict is SmokeVerdict.FAIL
        assert "accepted schema-invalid arguments" in check.message

    async def test_transport_crash_fails(self) -> None:
        session = FakeSession({"reader": ConnectionError("boom")})
        check = await single_check(session, read_only_tool(), CHECK_INVALID_ARGUMENTS)
        assert check.verdict is SmokeVerdict.FAIL
        assert "crashed" in check.message

    async def test_interactive_result_fails(self) -> None:
        session = FakeSession({"reader": object()})
        check = await single_check(session, read_only_tool(), CHECK_INVALID_ARGUMENTS)
        assert check.verdict is SmokeVerdict.FAIL
        assert "further input" in check.message

    async def test_unconstrained_schema_skips(self) -> None:
        tool = read_only_tool(input_schema={"type": "object"})
        session = FakeSession()
        check = await single_check(session, tool, CHECK_INVALID_ARGUMENTS)
        assert check.verdict is SmokeVerdict.SKIP
        assert "nothing invalid to send" in check.message

    async def test_wrong_typed_value_is_sent(self) -> None:
        session = FakeSession({"reader": MCPError(code=ERROR_INVALID_PARAMS, message="bad args")})
        await single_check(session, read_only_tool(), CHECK_INVALID_ARGUMENTS)
        assert ("reader", {"q": 42}) in session.calls


class TestUnknownToolCheck:
    @pytest.mark.parametrize("code", [ERROR_INVALID_PARAMS, ERROR_METHOD_NOT_FOUND])
    async def test_protocol_error_passes(self, code: int) -> None:
        session = FakeSession(default=MCPError(code=code, message="Unknown tool"))
        report = await run_smoke_checks(session, None, call_all=False)  # type: ignore[arg-type]
        (check,) = report.checks
        assert check.check_id == CHECK_UNKNOWN_TOOL
        assert check.verdict is SmokeVerdict.PASS
        assert check.tool_name is None
        assert session.calls == [(UNKNOWN_TOOL_NAME, {})]

    async def test_other_error_code_fails(self) -> None:
        session = FakeSession(default=MCPError(code=ERROR_INTERNAL, message="oops"))
        report = await run_smoke_checks(session, None, call_all=False)  # type: ignore[arg-type]
        assert report.checks[0].verdict is SmokeVerdict.FAIL
        assert str(ERROR_INTERNAL) in report.checks[0].message

    async def test_timeout_fails_as_hang(self) -> None:
        session = FakeSession(default=MCPError(code=REQUEST_TIMEOUT, message="timed out"))
        report = await run_smoke_checks(session, None, call_all=False)  # type: ignore[arg-type]
        assert report.checks[0].verdict is SmokeVerdict.FAIL
        assert "hang" in report.checks[0].message

    async def test_success_result_fails(self) -> None:
        session = FakeSession(default=CallToolResult(content=[]))
        report = await run_smoke_checks(session, None, call_all=False)  # type: ignore[arg-type]
        assert report.checks[0].verdict is SmokeVerdict.FAIL
        assert "instead of rejecting" in report.checks[0].message

    async def test_is_error_result_fails(self) -> None:
        session = FakeSession(default=CallToolResult(content=[], is_error=True))
        report = await run_smoke_checks(session, None, call_all=False)  # type: ignore[arg-type]
        assert report.checks[0].verdict is SmokeVerdict.FAIL
        assert "isError" in report.checks[0].message

    async def test_transport_crash_fails(self) -> None:
        session = FakeSession(default=ConnectionError("boom"))
        report = await run_smoke_checks(session, None, call_all=False)  # type: ignore[arg-type]
        assert report.checks[0].verdict is SmokeVerdict.FAIL
        assert "crashed" in report.checks[0].message


class TestSafetyDefault:
    """Only readOnlyHint: true tools are called unless --call-all lifts it."""

    @pytest.mark.parametrize(
        "annotations",
        [None, ToolAnnotations(), ToolAnnotations(read_only_hint=False), ToolAnnotations(destructive_hint=False)],
    )
    async def test_tools_without_the_hint_are_skipped_not_called(self, annotations: ToolAnnotations | None) -> None:
        tool = Tool(
            name="writer", input_schema={"type": "object"}, output_schema=OUTPUT_SCHEMA, annotations=annotations
        )
        session = FakeSession()
        report = await run_smoke_checks(session, [tool], call_all=False)  # type: ignore[arg-type]
        per_tool = [check for check in report.checks if check.tool_name == "writer"]
        assert len(per_tool) == 2
        assert all(check.verdict is SmokeVerdict.SKIP for check in per_tool)
        assert all("--call-all" in check.message for check in per_tool)
        assert session.calls == [(UNKNOWN_TOOL_NAME, {})]  # only the server-level check called anything

    async def test_call_all_lifts_the_default(self) -> None:
        tool = Tool(
            name="writer",
            input_schema={"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]},
            output_schema=OUTPUT_SCHEMA,
        )
        session = FakeSession({"writer": CallToolResult(content=[], structured_content={"result": "ok"})})
        report = await run_smoke_checks(session, [tool], call_all=True)  # type: ignore[arg-type]
        assert report.call_all is True
        called_tools = {name for name, _ in session.calls}
        assert "writer" in called_tools


class TestRunSmokeChecks:
    async def test_checks_are_grouped_and_ordered(self) -> None:
        tools = [read_only_tool("alpha", output_schema=OUTPUT_SCHEMA), read_only_tool("beta")]
        session = FakeSession(
            {
                "alpha": CallToolResult(content=[], structured_content={"result": "ok"}),
                "beta": MCPError(code=ERROR_INVALID_PARAMS, message="bad"),
            },
            default=MCPError(code=ERROR_INVALID_PARAMS, message="Unknown tool"),
        )
        report = await run_smoke_checks(session, tools, call_all=False)  # type: ignore[arg-type]
        assert [(check.check_id, check.tool_name) for check in report.checks] == [
            (CHECK_STRUCTURED_CONTENT, "alpha"),
            (CHECK_STRUCTURED_CONTENT, "beta"),
            (CHECK_INVALID_ARGUMENTS, "alpha"),
            (CHECK_INVALID_ARGUMENTS, "beta"),
            (CHECK_UNKNOWN_TOOL, None),
        ]
        assert report.executed is True
        assert report.reason is None

    async def test_counts_and_to_dict(self) -> None:
        tools = [read_only_tool("alpha", output_schema=OUTPUT_SCHEMA)]
        session = FakeSession(
            {"alpha": CallToolResult(content=[], structured_content={"result": "ok"})},
            default=MCPError(code=ERROR_INVALID_PARAMS, message="Unknown tool"),
        )
        report = await run_smoke_checks(session, tools, call_all=False)  # type: ignore[arg-type]
        # alpha: structured-content pass; invalid-arguments... alpha returns a
        # success result for the invalid call → fail. Unknown tool → pass.
        assert (report.passed, report.failed, report.skipped) == (2, 1, 0)

        payload = report.to_dict()
        assert payload["executed"] is True
        assert payload["call_all"] is False
        assert payload["summary"] == {"passed": 2, "failed": 1, "skipped": 0}
        assert len(payload["checks"]) == 3
        first = payload["checks"][0]
        assert first == {
            "check_id": CHECK_STRUCTURED_CONTENT,
            "tool_name": "alpha",
            "verdict": "pass",
            "message": first["message"],
            "details": first["details"],
        }
        assert "basis" in first["details"]

    async def test_not_executed_report(self) -> None:
        report = SmokeReport.not_executed("no session")
        assert report.executed is False
        assert report.reason == "no session"
        assert (report.passed, report.failed, report.skipped) == (0, 0, 0)
        payload = report.to_dict()
        assert payload["executed"] is False
        assert payload["reason"] == "no session"
        assert payload["checks"] == []
