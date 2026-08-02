"""Minimal stdlib-only MCP stdio server for the real-process e2e test.

Speaks just enough of the legacy (stateful) protocol for a client to complete
the initialize handshake over newline-delimited JSON-RPC on stdio. It echoes
the ``MCPSCORE_E2E_ENV`` environment variable back as its serverInfo.version,
so the test can prove that ``StdioCommand.env`` values genuinely reach the
launched process — through the SDK's environment handling, not a mock.

Not a test module (no ``test_`` prefix): pytest never collects it; it is only
ever run as a subprocess via ``--stdio``-style launching.
"""

from __future__ import annotations

import json
import os
import sys


def main() -> None:
    """Serve initialize (echoing the requested protocol version) until EOF."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        message = json.loads(line)
        if message.get("method") == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "protocolVersion": message["params"]["protocolVersion"],
                    "capabilities": {},
                    "serverInfo": {
                        "name": "stdio-e2e-server",
                        "version": os.environ.get("MCPSCORE_E2E_ENV", "env-var-missing"),
                    },
                },
            }
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
        elif "id" in message:  # any other request: method not found
            error = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {"code": -32601, "message": "Method not found"},
            }
            sys.stdout.write(json.dumps(error) + "\n")
            sys.stdout.flush()
        # Notifications (no id) are ignored.


if __name__ == "__main__":
    main()
