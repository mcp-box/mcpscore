"""The raw ``tools/call`` the opt-in boundary probes share, reduced to what their verdicts need."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import TYPE_CHECKING, Any

from mcp.shared.exceptions import MCPError
from mcp_types import CONNECTION_CLOSED, REQUEST_TIMEOUT

from .mcp_client import RawRequest, RawResult
from .smoke import SMOKE_CALL_TIMEOUT_S

if TYPE_CHECKING:
    from mcp import ClientSession


@dataclass(frozen=True)
class ProbeCallOutcome:
    """What one probe call produced, reduced to what the verdicts need."""

    answered: bool
    """The server answered (a result or a JSON-RPC error), so the call counts as made."""

    text: str | None = None
    """The whole result or JSON-RPC error serialized, for marker search; None when there was no answer."""

    is_error: bool = False
    error_code: int | None = None
    failure: str | None = None
    """Why the call could not be judged (timeout, closed connection, client-side error)."""


async def call_tool_raw(session: ClientSession, tool: str, arguments: dict[str, Any]) -> ProbeCallOutcome:
    """Call ``tool`` once and classify the answer; never raises."""
    # A raw tools/call, not session.call_tool: the SDK validates a result against the
    # tool's outputSchema and raises on a mismatch, which would discard the evidence.
    request = RawRequest(method="tools/call", params={"name": tool, "arguments": arguments})
    try:
        raw = await session.send_request(request, RawResult, request_read_timeout_seconds=SMOKE_CALL_TIMEOUT_S)
    except MCPError as exc:
        if exc.code == REQUEST_TIMEOUT:
            return ProbeCallOutcome(answered=False, failure=f"no answer within {SMOKE_CALL_TIMEOUT_S:.0f}s")
        if exc.code == CONNECTION_CLOSED:
            return ProbeCallOutcome(answered=False, failure="connection closed during tools/call")
        # The error's message and data are searched for markers like a result is.
        text = json.dumps({"message": exc.message, "data": exc.data}, default=str)
        return ProbeCallOutcome(answered=True, text=text, is_error=True, error_code=exc.code)
    except Exception as exc:  # noqa: BLE001 — a smoke check never aborts the run
        return ProbeCallOutcome(answered=False, failure=f"tools/call raised {type(exc).__name__}")
    result = dict(raw.model_extra or {})
    text = json.dumps(result, default=str)
    if "content" not in result and "structuredContent" not in result:
        return ProbeCallOutcome(answered=True, text=text, failure="the answer is not a tool result")
    return ProbeCallOutcome(answered=True, text=text, is_error=result.get("isError") is True)


def observed_call(outcome: ProbeCallOutcome) -> dict[str, Any]:
    """Describe the call in the ``details`` every probe result carries."""
    observed: dict[str, Any] = {"called": outcome.answered}
    if outcome.error_code is not None:
        observed["error_code"] = outcome.error_code
    return observed


def rejection_message(outcome: ProbeCallOutcome) -> str:
    """Say how the server refused a call: a JSON-RPC error or an ``isError`` result."""
    if outcome.error_code is not None:
        return f"rejected with JSON-RPC error {outcome.error_code}"
    return "rejected with an isError tool result"
