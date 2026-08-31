"""Stdlib-only legacy MCP stdio server for the real-process smoke-mode test.

Speaks enough of the legacy (stateful) protocol over newline-delimited
JSON-RPC to complete the initialize handshake, list a small tool catalog, and
answer ``tools/call`` — the surface the ``--smoke`` checks exercise. Each tool
scripts one smoke outcome:

- ``honest``    — readOnlyHint, outputSchema honored, invalid args rejected.
- ``dishonest`` — readOnlyHint, structuredContent violates its outputSchema.
- ``sloppy``    — readOnlyHint, no outputSchema, accepts schema-invalid args.
- ``writer``    — unannotated: the safety default must never call it (calling
  it is wired to crash the process so a violation cannot pass unnoticed).

Unknown tool names are rejected with the spec's exemplary protocol error
(-32602). Deliberately stdlib-only, like its sibling fixtures: the point is a
fixed, readable wire contract, not a re-test of the MCP SDK.

Not a test module (no ``test_`` prefix): pytest never collects it; it is only
ever launched as a subprocess.
"""

from __future__ import annotations

import json
import sys
from typing import Any

STRING_ARG_SCHEMA = {
    "type": "object",
    "properties": {"q": {"type": "string"}},
    "required": ["q"],
}

RESULT_SCHEMA = {
    "type": "object",
    "properties": {"result": {"type": "string"}},
    "required": ["result"],
}

READ_ONLY = {"readOnlyHint": True}

TOOLS = [
    {"name": "honest", "inputSchema": STRING_ARG_SCHEMA, "outputSchema": RESULT_SCHEMA, "annotations": READ_ONLY},
    {"name": "dishonest", "inputSchema": STRING_ARG_SCHEMA, "outputSchema": RESULT_SCHEMA, "annotations": READ_ONLY},
    {"name": "sloppy", "inputSchema": STRING_ARG_SCHEMA, "annotations": READ_ONLY},
    {"name": "writer", "inputSchema": STRING_ARG_SCHEMA, "outputSchema": RESULT_SCHEMA},
]


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _tool_result(request_id: Any, structured: dict[str, Any] | None) -> dict[str, Any]:
    result: dict[str, Any] = {"content": [{"type": "text", "text": json.dumps(structured or {})}]}
    if structured is not None:
        result["structuredContent"] = structured
    return _result(request_id, result)


def _handle_call(request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
    name = params.get("name")
    arguments = params.get("arguments") or {}

    if name == "writer":
        # The safety default must never let this run; dying loudly turns a
        # violation into an unmistakable transport failure in the test.
        sys.exit(13)

    if name not in ("honest", "dishonest", "sloppy"):
        return _error(request_id, -32602, f"Unknown tool: {name}")

    if name == "sloppy":  # accepts anything, returns a bare success
        return _tool_result(request_id, None)
    if not isinstance(arguments.get("q"), str):
        return _error(request_id, -32602, "Invalid arguments: q must be a string")
    if name == "dishonest":
        return _tool_result(request_id, {"wrong_key": 1})
    return _tool_result(request_id, {"result": "ok"})


def _handle(message: dict[str, Any]) -> dict[str, Any] | None:
    request_id = message.get("id")
    if request_id is None:  # a notification: nothing to answer
        return None
    method = message.get("method")
    params = message.get("params") or {}

    if method == "initialize":
        return _result(
            request_id,
            {
                "protocolVersion": params["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "stdio-smoke-server", "version": "1.0.0"},
            },
        )
    if method == "tools/list":
        return _result(request_id, {"tools": TOOLS})
    if method == "tools/call":
        return _handle_call(request_id, params)
    return _error(request_id, -32601, "Method not found")


def main() -> None:
    """Serve one request per line until stdin closes."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict):
            continue
        response = _handle(message)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
