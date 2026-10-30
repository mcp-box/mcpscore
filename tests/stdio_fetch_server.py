"""Stdlib-only legacy MCP stdio server with one URL-fetching tool, for the network-boundary probe tests.

Usage: ``stdio_fetch_server.py <mode> <allowed_origin>``, where
``env:NAME`` reads the origin from that environment variable. It exposes
``fetch`` (url) and decides whether to fetch according to ``mode``:

- ``open``          — no check at all, redirects followed.
- ``prefix``        — ``url.startswith(allowed_origin)``, redirects followed:
  fooled by userinfo and by a redirect.
- ``parsed``        — scheme, host and port parsed and compared, redirects
  followed: fooled only by a redirect.
- ``protected``     — ``parsed``, plus no userinfo or backslash, and
  redirects refused.
- ``deny_naive``    — refuses the host strings ``127.0.0.1`` and ``localhost``
  only: other spellings of loopback get through.
- ``deny_resolved`` — resolves the host and refuses loopback, private,
  link-local and unspecified addresses; redirects refused.
- ``broken``        — refuses every URL, so the positive control fails.

Not a test module (no ``test_`` prefix): pytest never collects it; it is only
ever launched as a subprocess.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import socket
import sys
from typing import Any
from urllib.parse import urljoin, urlsplit

MAX_REDIRECTS = 3

TOOLS = [
    {
        "name": "fetch",
        "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
        "annotations": {"readOnlyHint": True, "openWorldHint": True},
    }
]


def _same_origin(url: str, allowed: str) -> bool:
    try:
        parts, want = urlsplit(url), urlsplit(allowed)
        return (parts.scheme, parts.hostname, parts.port) == (want.scheme, want.hostname, want.port)
    except ValueError:
        return False


def _resolves_private(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return True
    for info in infos:
        address = ipaddress.ip_address(str(info[4][0]).split("%")[0])
        if address.is_loopback or address.is_private or address.is_link_local or address.is_unspecified:
            return True
        mapped = getattr(address, "ipv4_mapped", None)
        if mapped is not None and (mapped.is_loopback or mapped.is_private):
            return True
    return False


def _allowed(mode: str, allowed: str, url: str) -> tuple[bool, bool]:
    """Return (may fetch, follow redirects)."""
    if mode == "open":
        return True, True
    if mode == "prefix":
        return url.startswith(allowed), True
    if mode == "parsed":
        return _same_origin(url, allowed), True
    if mode == "protected":
        netloc = urlsplit(url).netloc
        return _same_origin(url, allowed) and "@" not in netloc and "\\" not in url, False
    if mode == "deny_naive":
        return urlsplit(url).hostname not in ("127.0.0.1", "localhost"), True
    if mode == "deny_resolved":
        return not _resolves_private(url), False
    return False, False


def _text(request_id: Any, text: str, *, is_error: bool = False) -> dict[str, Any]:
    result = {"content": [{"type": "text", "text": text}], "isError": is_error}
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _call(mode: str, allowed: str, request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
    url = (params.get("arguments") or {}).get("url")
    if params.get("name") != "fetch" or not isinstance(url, str):
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": "fetch needs a url"}}
    may_fetch, follow = _allowed(mode, allowed, url)
    if not may_fetch:
        return _text(request_id, f"Refused: {url} is not an allowed destination", is_error=True)
    try:
        status, body = _fetch(url, follow=follow)
    except (OSError, ValueError, http.client.HTTPException) as e:
        return _text(request_id, f"Fetch failed: {type(e).__name__}", is_error=True)
    if status in (301, 302, 303, 307, 308):
        return _text(request_id, "Refused to follow a redirect", is_error=True)
    return _text(request_id, body[:200])


def _fetch(url: str, *, follow: bool) -> tuple[int, str]:
    """GET ``url`` the way an RFC 3986 client does: connect to the parsed host and port."""
    for _ in range(MAX_REDIRECTS + 1):
        parts = urlsplit(url)
        connection = http.client.HTTPConnection(parts.hostname or "", parts.port or 80, timeout=5)
        try:
            connection.request("GET", parts.path or "/")
            response = connection.getresponse()
            body = response.read().decode("utf-8", "replace")
            location = response.getheader("Location")
        finally:
            connection.close()
        if not (follow and location and response.status in (301, 302, 303, 307, 308)):
            return response.status, body
        url = urljoin(url, location)
    return 310, ""


def _handle(mode: str, allowed: str, message: dict[str, Any]) -> dict[str, Any] | None:
    request_id = message.get("id")
    if request_id is None:
        return None
    method = message.get("method")
    params = message.get("params") or {}
    if method == "initialize":
        result = {
            "protocolVersion": params["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "stdio-fetch-server", "version": "1.0.0"},
        }
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        return _call(mode, allowed, request_id, params)
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}}


def main() -> None:
    """Serve one request per line until stdin closes."""
    mode, allowed = sys.argv[1], sys.argv[2]
    if allowed.startswith("env:"):
        allowed = os.environ[allowed.removeprefix("env:")]
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
        response = _handle(mode, allowed, message)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
