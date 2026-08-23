"""Minimal stdlib-only stdio server for the real-process probe tests.

Answers the stateless (2026-07-28) requests the transport-agnostic probes
send, over newline-delimited JSON-RPC on stdin/stdout. Set
``MCPSCORE_PROBE_LEGACY=1`` to make it a legacy-only server that rejects every
modern request — the negative case that proves the probes distinguish a server
which speaks the modern lifecycle from one which does not.

Deliberately stdlib-only and hand-rolled rather than built on the MCP SDK: the
point is to exercise mcpscore's own probe transport against a fixed, readable
wire contract. An SDK-backed fixture would re-test the SDK, and would move
under it on upgrade.

Not a test module (no ``test_`` prefix): pytest never collects it; it is only
ever launched as a subprocess.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

PROTOCOL_VERSION = "2026-07-28"
META_PREFIX = "io.modelcontextprotocol/"
REQUIRED_META_KEYS = (
    f"{META_PREFIX}protocolVersion",
    f"{META_PREFIX}clientCapabilities",
)

TOOLS = [{"name": "add", "description": "Add two numbers.", "inputSchema": {"type": "object"}}]

CACHE_HINTS: dict[str, Any] = {"resultType": "complete", "ttlMs": 0, "cacheScope": "private"}


def _error(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _handle(message: dict[str, Any]) -> dict[str, Any] | None:
    """Route one JSON-RPC request to its modern response."""
    request_id = message.get("id")
    if request_id is None:  # a notification: nothing to answer
        return None
    method = message.get("method")
    params = message.get("params") or {}
    meta = params.get("_meta") or {}

    if os.environ.get("MCPSCORE_PROBE_LEGACY") == "1":
        # A legacy-only server: it has no idea what these requests are.
        return _error(request_id, -32601, "Method not found")

    missing = [key for key in REQUIRED_META_KEYS if key not in meta]
    if missing:
        return _error(request_id, -32602, f"params._meta is missing required key(s): {', '.join(missing)}")

    requested = meta[f"{META_PREFIX}protocolVersion"]
    if requested != PROTOCOL_VERSION:
        return _error(
            request_id,
            -32022,
            "Unsupported protocol version",
            {"supported": [PROTOCOL_VERSION], "requested": requested},
        )

    if str(params.get("cursor", "")).startswith("mcpscore-invalid-cursor-"):
        return _error(request_id, -32602, "Invalid cursor")

    if method == "server/discover":
        return _result(request_id, {"supportedVersions": [PROTOCOL_VERSION], **CACHE_HINTS})
    if method == "tools/list":
        return _result(request_id, {"tools": TOOLS, **CACHE_HINTS})
    if method == "resources/read":
        return _error(request_id, -32602, "Resource not found")
    # Everything else — including `ping`, removed in 2026-07-28 — is unknown.
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
