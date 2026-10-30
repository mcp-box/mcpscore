"""Network boundary smoke check: does a URL-fetching tool stay away from destinations its policy denies?

Opt-in twice over: it runs under ``--smoke`` only when the configuration has a
``[smoke.network]`` table naming the tool, its URL argument and the server's
declared policy, and only against a ``--stdio`` server. mcpscore starts two
local HTTP listeners and asks the tool to fetch URLs that reach the denied
one directly, through other spellings of its address, through URL-parser
confusion, and through a redirect from the allowed one::

    allowed  http://127.0.0.1:<allowed-port>   the origin the server may fetch
             /control                          positive control
             /redirect                         302 to the denied listener
    denied   127.0.0.1 and ::1, <denied-port>  any request here is the failure

Evidence is the denied listener's request log, never the tool's word: a
vector fails when a request reached it during the call. Two policies:

- ``allowlist`` — the server is given ``{mcpscore_allowed_origin}`` (in its
  ``--stdio`` command or an ``--env`` value) as the one origin it may fetch.
  A positive control fetch of the allowed origin must reach it first;
  afterwards a vector passes when nothing reached the denied listener.
- ``deny-private`` — the server refuses loopback and private addresses, so
  it cannot fetch the local allowed origin either and no positive control is
  possible. A request reaching the denied listener still fails; no request
  is reported as not assessed, never as a pass.

No real cloud metadata endpoint, internal service or third-party callback
is ever contacted: every destination is a listener on this machine. Results
join the smoke report under ``smoke_network_boundary`` and never enter the
score. Ports are shown as ``<allowed-port>``/``<denied-port>`` in the report.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import socketserver
import threading
from typing import TYPE_CHECKING, Any, ClassVar, cast

from .smoke import SmokeCheckResult, SmokeVerdict
from .smoke_probe import call_tool_raw, observed_call, rejection_message

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mcp import ClientSession
    from mcp_types import Tool

CHECK_NETWORK_BOUNDARY = "smoke_network_boundary"

ALLOWED_ORIGIN_PLACEHOLDER = "{mcpscore_allowed_origin}"
"""Replaced in the ``--stdio`` command and ``--env`` values with the allowed listener's origin."""

POLICY_ALLOWLIST = "allowlist"
POLICY_DENY_PRIVATE = "deny-private"
POLICIES = (POLICY_ALLOWLIST, POLICY_DENY_PRIVATE)

BASIS_NETWORK_BOUNDARY = (
    "MCP 2025-11-25 Tools §Security Considerations (servers MUST validate all tool inputs and implement proper "
    "access controls); Security Best Practices §Server-Side Request Forgery (block private ranges including "
    "encoded forms, validate redirect targets); OWASP SSRF Prevention Cheat Sheet"
)

CONTROL_MARKER = "mcpscore-network-control-allowed-origin"
"""Body of the allowed listener's control response."""

DENIED_MARKER = "mcpscore-network-canary-denied-destination"
"""Body of every denied listener response."""

CONTROL_PATH = "/control"
REDIRECT_PATH = "/redirect"

_MAX_LOGGED_REQUESTS = 5
_MAX_LOGGED_PATH = 120
_LISTENER_ATTEMPTS = 20
_POLL_INTERVAL_S = 0.05


@dataclass(frozen=True)
class NetworkProbeConfig:
    """The ``[smoke.network]`` table: which tool to exercise, how to pass it a URL, and its declared policy.

    Naming the tool here is the consent to call it, whatever its annotations say.
    """

    tool: str
    policy: str
    url_argument: str = "url"


@dataclass(frozen=True)
class NetworkVector:
    """One way of asking the tool for a denied destination."""

    name: str
    template: str | None
    """URL with ``{allowed}``/``{denied}`` port slots; None when the vector cannot run here."""

    unsupported: str | None = None
    """Why the vector cannot run on this machine."""


_VECTORS: tuple[tuple[str, str], ...] = (
    ("direct", "http://127.0.0.1:{denied}/v/direct"),
    ("localhost_name", "http://localhost:{denied}/v/localhost_name"),
    ("unspecified_address", "http://0.0.0.0:{denied}/v/unspecified_address"),
    ("ipv6_loopback", "http://[::1]:{denied}/v/ipv6_loopback"),
    ("ipv4_mapped_ipv6", "http://[::ffff:127.0.0.1]:{denied}/v/ipv4_mapped_ipv6"),
    ("decimal_ipv4", "http://2130706433:{denied}/v/decimal_ipv4"),
    ("hex_ipv4", "http://0x7f000001:{denied}/v/hex_ipv4"),
    # One octal number: read as decimal it is out of range, so a misparse never reaches a real host.
    ("octal_ipv4", "http://017700000001:{denied}/v/octal_ipv4"),
    ("short_ipv4", "http://127.1:{denied}/v/short_ipv4"),
    # The allowed origin as userinfo: a prefix check sees it, the request goes to the host after "@".
    ("userinfo_confusion", "http://127.0.0.1:{allowed}@127.0.0.1:{denied}/v/userinfo_confusion"),
    # WHATWG parsers end the host at "\", RFC 3986 parsers read "…\@" as userinfo and see the allowed host.
    ("backslash_confusion", "http://127.0.0.1:{denied}\\@127.0.0.1:{allowed}/v/backslash_confusion"),
    ("fragment_confusion", "http://127.0.0.1:{denied}/v/fragment_confusion#@127.0.0.1:{allowed}"),
    ("redirect", "http://127.0.0.1:{allowed}" + REDIRECT_PATH),
)

_NOTHING_REACHED = "no request reached the denied destination"

_UNASSESSED = (
    "no request reached the denied destination, but deny-private has no positive control, so a refusal "
    "cannot be told apart from a tool that fetches nothing; not assessed"
)

_DNS_REBINDING_REASON = (
    "needs control of the server's DNS resolver to change an answer between check and use; not assessed"
)


class _Listener(ThreadingHTTPServer):
    """A local HTTP listener that records every request and answers from ``respond``."""

    daemon_threads = True
    allow_reuse_address = False  # on Windows it would let a second socket share a listening port

    def __init__(self, family: socket.AddressFamily, host: str, port: int, owner: NetworkFixture) -> None:
        self.address_family = family
        self.owner = owner
        self.requests: list[str] = []
        self.lock = threading.Lock()
        super().__init__((host, port), _Handler)
        self.thread = threading.Thread(target=self.serve_forever, args=(_POLL_INTERVAL_S,), daemon=True)

    def server_bind(self) -> None:
        """Bind without HTTPServer's reverse DNS lookup of the address, which can stall for seconds."""
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = str(self.server_address[0]), int(self.server_address[1])

    def stop(self) -> None:
        """Stop serving and close the socket."""
        self.shutdown()
        self.server_close()


class _Handler(BaseHTTPRequestHandler):
    """Records every connection before dispatch, then serves the control, the redirect, or the denied canary.

    Recording happens before the method is looked up, so a request the
    handler has no ``do_*`` method for (TRACE, CONNECT, garbage) still
    counts as having reached the listener.
    """

    protocol_version = "HTTP/1.0"
    _recorded = False

    def _record(self, entry: str) -> None:
        listener = cast("_Listener", self.server)
        with listener.lock:
            listener.requests.append(entry[:_MAX_LOGGED_PATH])
        self._recorded = True

    def parse_request(self) -> bool:
        """Parse the request line and headers, recording the request whatever its method or validity."""
        parsed = super().parse_request()
        self._record(f"{self.command} {self.path}" if parsed else self.requestline or "unparsable request")
        return parsed

    def handle(self) -> None:
        """Serve the connection; a connection that never sent a request line is recorded too."""
        try:
            super().handle()
        finally:
            if not self._recorded:
                self._record("connection without an HTTP request")

    def _answer(self) -> None:
        listener = cast("_Listener", self.server)
        status, headers, body = listener.owner.respond(listener, self.path)
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # BaseHTTPRequestHandler dispatches on these names.
    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _answer  # noqa: N815

    def log_message(self, format: str, *args: Any) -> None:
        """Stay quiet: the request log is the evidence, stderr is not."""


class NetworkFixture:
    """The allowed and denied local listeners, started before the server launches and stopped by ``cleanup``.

    The denied listener binds the same port on 127.0.0.1 and, when this
    machine has IPv6 loopback, on ::1, so a client that resolves
    ``localhost`` to either address still reaches it.
    """

    _IPV6_UNAVAILABLE: ClassVar[str] = "no IPv6 loopback on this machine"

    def __init__(self) -> None:
        """Bind and start both listeners."""
        super().__init__()
        self.allowed = _Listener(socket.AF_INET, "127.0.0.1", 0, self)
        self.denied: list[_Listener] = []
        self.ipv6_error: str | None = None
        try:
            self._bind_denied()
        except BaseException:
            self.allowed.server_close()
            raise
        for listener in (self.allowed, *self.denied):
            listener.thread.start()

    @classmethod
    def create(cls) -> NetworkFixture:
        """Start a fixture on free local ports."""
        return cls()

    def _bind_denied(self) -> None:
        if not socket.has_ipv6:
            self.ipv6_error = self._IPV6_UNAVAILABLE
        else:
            try:
                _Listener(socket.AF_INET6, "::1", 0, self).server_close()
            except OSError:
                self.ipv6_error = self._IPV6_UNAVAILABLE
        for _ in range(_LISTENER_ATTEMPTS):
            ipv4 = _Listener(socket.AF_INET, "127.0.0.1", 0, self)
            if self.ipv6_error is not None:
                self.denied = [ipv4]
                return
            try:
                ipv6 = _Listener(socket.AF_INET6, "::1", ipv4.server_address[1], self)
            except OSError:
                ipv4.server_close()
                continue
            self.denied = [ipv4, ipv6]
            return
        self.ipv6_error = "could not bind the same port on 127.0.0.1 and ::1"
        self.denied = [_Listener(socket.AF_INET, "127.0.0.1", 0, self)]

    @property
    def allowed_port(self) -> int:
        """Port of the allowed listener."""
        return self.allowed.server_address[1]

    @property
    def denied_port(self) -> int:
        """Port of the denied listener."""
        return self.denied[0].server_address[1]

    @property
    def allowed_origin(self) -> str:
        """The origin a server with an allowlist is given through the placeholder."""
        return f"http://127.0.0.1:{self.allowed_port}"

    def substitute(self, value: str) -> str:
        """Replace the allowed-origin placeholder in one command-line token or environment value."""
        return value.replace(ALLOWED_ORIGIN_PLACEHOLDER, self.allowed_origin)

    def url(self, template: str) -> str:
        """Fill a vector template with the real ports."""
        return template.format(allowed=self.allowed_port, denied=self.denied_port)

    @staticmethod
    def display(template: str) -> str:
        """Fill a vector template with port labels, so the report is the same on every run."""
        return template.format(allowed="<allowed-port>", denied="<denied-port>")

    def respond(self, listener: _Listener, path: str) -> tuple[int, dict[str, str], bytes]:
        """Choose the answer to one request on ``listener``."""
        if listener is not self.allowed:
            return 200, {}, DENIED_MARKER.encode("utf-8")
        if path == CONTROL_PATH:
            return 200, {}, CONTROL_MARKER.encode("utf-8")
        if path == REDIRECT_PATH:
            return 302, {"Location": f"http://127.0.0.1:{self.denied_port}/v/redirect"}, b""
        return 404, {}, b""

    def allowed_requests(self) -> list[str]:
        """Every request the allowed listener has seen, in order."""
        with self.allowed.lock:
            return list(self.allowed.requests)

    def denied_requests(self) -> list[str]:
        """Every request the denied listener has seen on either address."""
        seen: list[str] = []
        for listener in self.denied:
            with listener.lock:
                seen.extend(listener.requests)
        return seen

    def vectors(self) -> list[NetworkVector]:
        """Every attempt, in a fixed order; IPv6 loopback only where it exists."""
        vectors = [
            NetworkVector(name, None, self.ipv6_error)
            if name == "ipv6_loopback" and self.ipv6_error is not None
            else NetworkVector(name, template)
            for name, template in _VECTORS
        ]
        vectors.append(NetworkVector("dns_rebinding", None, _DNS_REBINDING_REASON))
        return vectors

    def cleanup(self) -> None:
        """Stop both listeners; best effort, a listener that will not stop is not an audit failure."""
        for listener in (self.allowed, *self.denied):
            with contextlib.suppress(OSError):
                listener.stop()


def _result(
    tool: str | None, vector: str | None, verdict: SmokeVerdict, message: str, **details: Any
) -> SmokeCheckResult:
    base: dict[str, Any] = {"basis": BASIS_NETWORK_BOUNDARY}
    if vector is not None:
        base["vector"] = vector
    return SmokeCheckResult(CHECK_NETWORK_BOUNDARY, verdict, message, tool, {**base, **details})


async def _control(
    session: ClientSession, fixture: NetworkFixture, config: NetworkProbeConfig
) -> tuple[bool, str, bool]:
    """Fetch the allowed origin; return whether it was reached, why not, and whether the server answered."""
    before = len(fixture.allowed_requests())
    outcome = await call_tool_raw(session, config.tool, {config.url_argument: fixture.allowed_origin + CONTROL_PATH})
    reached = any(r.endswith(" " + CONTROL_PATH) for r in fixture.allowed_requests()[before:])
    if reached and outcome.answered:
        return True, "", True
    why = outcome.failure or (rejection_message(outcome) if outcome.is_error else "did not reach the allowed origin")
    return False, why, outcome.answered


async def run_network_checks(
    session: ClientSession,
    tools: Sequence[Tool] | None,
    config: NetworkProbeConfig,
    fixture: NetworkFixture,
) -> list[SmokeCheckResult]:
    """Run every vector against the tool ``config`` names, judged by the policy it declares.

    Sequential, so each request the denied listener records is attributable to
    exactly one call.
    """
    tool = config.tool
    if tool not in {t.name for t in tools or []}:
        return [
            _result(
                tool,
                None,
                SmokeVerdict.SKIP,
                f"{tool!r} is named in [smoke.network] but is not in the server's tool catalog",
                policy=config.policy,
            )
        ]
    vectors = fixture.vectors()
    control_seen: dict[str, Any] = {}
    if config.policy == POLICY_ALLOWLIST:
        reached, why, answered = await _control(session, fixture, config)
        if not reached:
            reason = (
                f"positive control failed: fetching the allowed origin {CONTROL_PATH} {why} — check that the server "
                f"was given {ALLOWED_ORIGIN_PLACEHOLDER} as an allowed origin and that tool and url_argument are right"
            )
            return [
                _result(tool, v.name, SmokeVerdict.SKIP, reason, policy=config.policy, called=answered) for v in vectors
            ]
        # Lets coverage count the tool even when no vector call is answered afterwards.
        control_seen = {"control_called": True}

    results = []
    for vector in vectors:
        if vector.template is None:
            message = vector.unsupported or ""
            results.append(_result(tool, vector.name, SmokeVerdict.SKIP, message, policy=config.policy, **control_seen))
            continue
        before = len(fixture.denied_requests())
        outcome = await call_tool_raw(session, tool, {config.url_argument: fixture.url(vector.template)})
        reached = fixture.denied_requests()[before:]
        details: dict[str, Any] = {
            "policy": config.policy,
            "attempted_url": fixture.display(vector.template),
            **observed_call(outcome),
            **control_seen,
        }
        if reached:
            verdict, message = SmokeVerdict.FAIL, f"a request reached the denied destination ({reached[0]})"
            details["denied_requests"] = reached[:_MAX_LOGGED_REQUESTS]
        elif outcome.failure is not None:
            verdict, message = SmokeVerdict.SKIP, f"{outcome.failure} — the boundary was not exercised"
        elif config.policy == POLICY_DENY_PRIVATE:
            verdict, message = SmokeVerdict.SKIP, _UNASSESSED
        elif outcome.is_error:
            verdict, message = SmokeVerdict.PASS, f"{rejection_message(outcome)}; {_NOTHING_REACHED}"
        else:
            verdict, message = SmokeVerdict.PASS, f"answered; {_NOTHING_REACHED}"
        results.append(_result(tool, vector.name, verdict, message, **details))
    return results


def not_runnable(reason: str) -> list[SmokeCheckResult]:
    """Build the single skip reported when the configured check cannot run at all."""
    return [_result(None, None, SmokeVerdict.SKIP, reason)]
