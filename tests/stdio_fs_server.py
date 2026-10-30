"""Stdlib-only legacy MCP stdio server with filesystem tools, for the boundary-probe tests.

Usage: ``stdio_fs_server.py <mode> <root>``. It exposes ``read_text_file``
(path) and ``write_file`` (path, content), and checks each path against
``root`` according to ``mode``:

- ``open``      — no check at all: every escape works.
- ``open_schema`` — ``open``, with an ``outputSchema`` on ``read_text_file``
  that its results never honor.
- ``naive``     — ``normpath(path).startswith(root)``: stops ``..`` and
  absolute paths, but not a sibling sharing the root's prefix or a symlink.
- ``protected`` — resolves symlinks, then requires ``root`` as a common path.
- ``broken``    — rejects every path, so the positive control fails.

Not a test module (no ``test_`` prefix): pytest never collects it; it is only
ever launched as a subprocess.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any

PATH_SCHEMA = {"type": "string"}

TOOLS = [
    {
        "name": "read_text_file",
        "inputSchema": {"type": "object", "properties": {"path": PATH_SCHEMA}, "required": ["path"]},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "write_file",
        "inputSchema": {
            "type": "object",
            "properties": {"path": PATH_SCHEMA, "content": {"type": "string"}},
            "required": ["path", "content"],
        },
    },
]


def _tools(mode: str) -> list[dict[str, Any]]:
    if mode != "open_schema":
        return TOOLS
    schema = {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}
    return [{**TOOLS[0], "outputSchema": schema}, TOOLS[1]]


def _allowed(mode: str, root: str, path: str) -> bool:
    if mode in ("open", "open_schema"):
        return True
    if mode == "naive":
        return os.path.normpath(path).startswith(root)
    if mode == "protected":
        resolved = str(Path(path).resolve())
        try:
            return os.path.commonpath([resolved, root]) == root
        except ValueError:  # different drives, or a \\?\ path against a drive path
            return False
    return False


def _text(request_id: Any, text: str, *, is_error: bool = False) -> dict[str, Any]:
    result = {"content": [{"type": "text", "text": text}], "isError": is_error}
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _call(mode: str, root: str, request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
    name = params.get("name")
    arguments = params.get("arguments") or {}
    path = arguments.get("path")
    if not isinstance(path, str):
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": "path is required"}}
    if not _allowed(mode, root, path):
        return _text(request_id, f"Access denied - path outside allowed directories: {path}", is_error=True)
    try:
        if name == "read_text_file":
            return _text(request_id, Path(path).read_text(encoding="utf-8"))
        if name == "write_file":
            Path(path).write_text(str(arguments.get("content", "")), encoding="utf-8")
            return _text(request_id, f"Successfully wrote to {path}")
    except OSError as e:
        return _text(request_id, f"Error: {e}", is_error=True)
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": f"Unknown tool: {name}"}}


def _handle(mode: str, root: str, message: dict[str, Any]) -> dict[str, Any] | None:
    request_id = message.get("id")
    if request_id is None:
        return None
    method = message.get("method")
    params = message.get("params") or {}
    if method == "initialize":
        result = {
            "protocolVersion": params["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "stdio-fs-server", "version": "1.0.0"},
        }
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": _tools(mode)}}
    if method == "tools/call":
        return _call(mode, root, request_id, params)
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}}


def main() -> None:
    """Serve one request per line until stdin closes."""
    mode, root = sys.argv[1], str(Path(sys.argv[2]).resolve())
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
        response = _handle(mode, root, message)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
