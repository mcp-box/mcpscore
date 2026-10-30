"""Tests for the network boundary smoke check.

The real-process tests launch ``stdio_fetch_server.py`` with the allowed
origin substituted into its command, the way ``--stdio … {mcpscore_allowed_origin}``
does, and assert the verdict for every vector against open, naively checked
and properly protected servers under both policies.
"""

from __future__ import annotations

import http.client
from pathlib import Path
import socket
import sys
import threading
import time
from typing import TYPE_CHECKING, Any
import urllib.error
import urllib.request

from mcp.shared.exceptions import MCPError
from mcp_types import REQUEST_TIMEOUT, CallToolResult, TextContent, Tool
import pytest

from mcpscore import MCPClient, StdioCommand
from mcpscore.mcp_client import RawRequest, RawResult
from mcpscore.smoke import SmokeVerdict
from mcpscore.smoke_network import (
    ALLOWED_ORIGIN_PLACEHOLDER,
    CHECK_NETWORK_BOUNDARY,
    CONTROL_MARKER,
    DENIED_MARKER,
    POLICY_ALLOWLIST,
    POLICY_DENY_PRIVATE,
    NetworkFixture,
    NetworkProbeConfig,
    _Listener,
    not_runnable,
    run_network_checks,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from mcpscore.smoke import SmokeCheckResult

SERVER = str(Path(__file__).parent / "stdio_fetch_server.py")
ALLOWLIST = NetworkProbeConfig(tool="fetch", policy=POLICY_ALLOWLIST)
DENY_PRIVATE = NetworkProbeConfig(tool="fetch", policy=POLICY_DENY_PRIVATE)
# Other spellings of loopback; whether a given client resolves each one depends on the OS.
ENCODED = {
    "unspecified_address",
    "ipv6_loopback",
    "ipv4_mapped_ipv6",
    "decimal_ipv4",
    "hex_ipv4",
    "octal_ipv4",
    "short_ipv4",
}


@pytest.fixture(autouse=True)
def short_late_grace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("mcpscore.smoke_network._LATE_GRACE_S", 0.05)


@pytest.fixture
def fixture() -> Iterator[NetworkFixture]:
    created = NetworkFixture.create()
    yield created
    created.cleanup()


async def _run(mode: str, fixture: NetworkFixture, config: NetworkProbeConfig) -> list[SmokeCheckResult]:
    command = StdioCommand(command=sys.executable, args=(SERVER, mode, fixture.substitute(ALLOWED_ORIGIN_PLACEHOLDER)))
    client = MCPClient()
    try:
        success, _transport = await client.detect_and_connect(command)
        assert success
        tools = await client.list_tools()
        assert client.session is not None
        return await run_network_checks(client.session, tools, config, fixture)
    finally:
        await client.cleanup()


def _by_verdict(results: list[SmokeCheckResult], verdict: SmokeVerdict) -> set[str]:
    return {r.details["vector"] for r in results if r.verdict is verdict}


def _runnable(fixture: NetworkFixture) -> set[str]:
    return {v.name for v in fixture.vectors() if v.template is not None}


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read()


class TestAgainstRealServers:
    async def test_open_server_fails_under_allowlist(self, fixture: NetworkFixture) -> None:
        results = await _run("open", fixture, ALLOWLIST)

        assert {r.check_id for r in results} == {CHECK_NETWORK_BOUNDARY}
        failed = _by_verdict(results, SmokeVerdict.FAIL)
        assert {"direct", "localhost_name", "userinfo_confusion", "redirect"} <= failed
        direct = next(r for r in results if r.details["vector"] == "direct")
        assert direct.details["denied_requests"] == ["GET /v/direct"]
        assert direct.details["attempted_url"] == "http://127.0.0.1:<denied-port>/v/direct"
        assert direct.message == "a request reached a destination the policy denies (GET /v/direct)"

    async def test_prefix_check_is_fooled_by_userinfo_and_a_redirect(self, fixture: NetworkFixture) -> None:
        results = await _run("prefix", fixture, ALLOWLIST)

        assert _by_verdict(results, SmokeVerdict.FAIL) == {"userinfo_confusion", "redirect"}
        assert "direct" in _by_verdict(results, SmokeVerdict.PASS)

    async def test_parsed_check_is_fooled_only_by_a_redirect(self, fixture: NetworkFixture) -> None:
        results = await _run("parsed", fixture, ALLOWLIST)

        assert _by_verdict(results, SmokeVerdict.FAIL) == {"redirect"}

    async def test_protected_server_passes_every_runnable_vector(self, fixture: NetworkFixture) -> None:
        results = await _run("protected", fixture, ALLOWLIST)

        assert _by_verdict(results, SmokeVerdict.PASS) == _runnable(fixture)
        assert _by_verdict(results, SmokeVerdict.SKIP) == {"dns_rebinding"} | (
            {"ipv6_loopback"} if fixture.ipv6_error else set()
        )
        direct = next(r for r in results if r.details["vector"] == "direct")
        assert direct.message == "rejected with an isError tool result; no request reached the denied destination"
        assert direct.details["control_called"] is True
        assert fixture.denied_requests() == []

    async def test_failed_positive_control_skips_every_vector(self, fixture: NetworkFixture) -> None:
        results = await _run("broken", fixture, ALLOWLIST)

        assert {r.verdict for r in results} == {SmokeVerdict.SKIP}
        assert len(results) == len(fixture.vectors())
        assert all(r.message.startswith("positive control failed: fetching the allowed origin") for r in results)
        assert all(r.details["called"] is True for r in results)

    async def test_open_server_fails_under_deny_private(self, fixture: NetworkFixture) -> None:
        results = await _run("open", fixture, DENY_PRIVATE)

        assert {"direct", "localhost_name", "redirect"} <= _by_verdict(results, SmokeVerdict.FAIL)

    async def test_deny_list_of_host_strings_misses_other_spellings(self, fixture: NetworkFixture) -> None:
        results = await _run("deny_naive", fixture, DENY_PRIVATE)

        failed = _by_verdict(results, SmokeVerdict.FAIL)
        assert failed
        assert failed <= ENCODED
        assert {"direct", "localhost_name"} <= _by_verdict(results, SmokeVerdict.SKIP)

    async def test_deny_private_without_a_hit_is_never_a_pass(self, fixture: NetworkFixture) -> None:
        results = await _run("deny_resolved", fixture, DENY_PRIVATE)

        assert {r.verdict for r in results} == {SmokeVerdict.SKIP}
        direct = next(r for r in results if r.details["vector"] == "direct")
        assert direct.message.endswith("not assessed")
        assert "control_called" not in direct.details

    async def test_unlisted_tool_is_skipped(self, fixture: NetworkFixture) -> None:
        results = await _run("open", fixture, NetworkProbeConfig(tool="download", policy=POLICY_ALLOWLIST))

        (result,) = results
        assert result.verdict is SmokeVerdict.SKIP
        assert result.message == "'download' is named in [smoke.network] but is not in the server's tool catalog"
        assert fixture.allowed_requests() == []


class TestFixture:
    def test_listeners_answer_and_record(self, fixture: NetworkFixture) -> None:
        assert _get(fixture.allowed_origin + "/control") == CONTROL_MARKER.encode()
        assert _get(f"http://127.0.0.1:{fixture.denied_port}/x") == DENIED_MARKER.encode()
        with pytest.raises(urllib.error.HTTPError) as not_found:
            _get(fixture.allowed_origin + "/robots.txt")
        assert not_found.value.code == 404
        not_found.value.close()
        assert _get(fixture.allowed_origin + "/redirect") == DENIED_MARKER.encode()

        assert fixture.allowed_requests() == ["GET /control", "GET /robots.txt", "GET /redirect"]
        assert fixture.denied_requests() == ["GET /x", "GET /v/redirect"]

    @pytest.mark.parametrize(
        ("sent", "recorded"),
        [
            (b"TRACE /t HTTP/1.0\r\n\r\n", "TRACE /t"),
            (b"CONNECT 127.0.0.1:1 HTTP/1.0\r\n\r\n", "CONNECT 127.0.0.1:1"),
            (b"\x16\x03\x01 not http\r\n\r\n", "\x16\x03\x01 not http"),
            (b"", "connection without a complete HTTP request"),
        ],
    )
    def test_every_connection_is_recorded_whatever_it_sends(
        self, fixture: NetworkFixture, sent: bytes, recorded: str
    ) -> None:
        with socket.create_connection(("127.0.0.1", fixture.denied_port), timeout=5) as connection:
            connection.sendall(sent)
            connection.shutdown(socket.SHUT_WR)
            connection.recv(1024)

        deadline = 50
        while not fixture.denied_requests() and deadline:
            time.sleep(0.05)
            deadline -= 1
        assert fixture.denied_requests() == [recorded]

    def test_an_unfinished_request_is_logged_while_the_connection_stays_open(self, fixture: NetworkFixture) -> None:
        with socket.create_connection(("127.0.0.1", fixture.denied_port), timeout=5) as connection:
            connection.sendall(b"GET /half HTTP/1.0\r\nHost: x\r\n")
            deadline = 50
            while fixture.denied_requests() != ["GET /half HTTP/1.0"] and deadline:
                time.sleep(0.05)
                deadline -= 1

            assert fixture.denied_requests() == ["GET /half HTTP/1.0"]

    def test_a_connection_is_logged_before_it_sends_anything(self, fixture: NetworkFixture) -> None:
        with socket.create_connection(("127.0.0.1", fixture.denied_port), timeout=5):
            deadline = 50
            while not fixture.denied_requests() and deadline:
                time.sleep(0.05)
                deadline -= 1

            assert fixture.denied_requests() == ["connection without a complete HTTP request"]

    def test_settle_waits_for_a_connection_not_yet_accepted(self) -> None:
        listener = _Listener(socket.AF_INET, "127.0.0.1", 0, NetworkFixture.__new__(NetworkFixture))
        try:
            with socket.create_connection(listener.server_address[:2], timeout=5):
                late = threading.Timer(0.3, listener.handle_request)
                late.start()
                listener.settle()

                assert listener.since(0) == ["connection without a complete HTTP request"]
                late.join()
        finally:
            listener.server_close()

    def test_settle_gives_up_when_nothing_accepts(self) -> None:
        listener = _Listener(socket.AF_INET, "127.0.0.1", 0, NetworkFixture.__new__(NetworkFixture))
        try:
            with socket.create_connection(listener.server_address[:2], timeout=5):
                started = time.monotonic()
                listener.settle(timeout=0.2)

                assert time.monotonic() - started >= 0.2
                assert listener.since(0) == []
        finally:
            listener.server_close()

    def test_head_requests_get_no_body(self, fixture: NetworkFixture) -> None:
        request = urllib.request.Request(fixture.allowed_origin + "/control", method="HEAD")
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.read() == b""
        assert fixture.allowed_requests() == ["HEAD /control"]

    def test_denied_listener_answers_on_ipv6_loopback_too(self, fixture: NetworkFixture) -> None:
        if fixture.ipv6_error is not None:
            pytest.skip(fixture.ipv6_error)
        assert _get(f"http://[::1]:{fixture.denied_port}/six") == DENIED_MARKER.encode()

    def test_substitution_and_display(self, fixture: NetworkFixture) -> None:
        assert fixture.substitute(f"--allow={ALLOWED_ORIGIN_PLACEHOLDER}") == f"--allow={fixture.allowed_origin}"
        assert fixture.allowed_origin == f"http://127.0.0.1:{fixture.allowed_port}"
        template = "http://127.0.0.1:{allowed}@127.0.0.1:{denied}/"
        assert fixture.url(template) == f"http://127.0.0.1:{fixture.allowed_port}@127.0.0.1:{fixture.denied_port}/"
        assert fixture.display(template) == "http://127.0.0.1:<allowed-port>@127.0.0.1:<denied-port>/"

    def test_cleanup_closes_every_port(self) -> None:
        fixture = NetworkFixture.create()
        ports = (fixture.allowed_port, fixture.denied_port)
        fixture.cleanup()

        for port in ports:
            with socket.socket() as probe, pytest.raises((ConnectionRefusedError, TimeoutError)):
                probe.settimeout(1)
                probe.connect(("127.0.0.1", port))

    def test_without_ipv6_the_ipv6_vector_skips(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(socket, "has_ipv6", False)
        fixture = NetworkFixture.create()
        try:
            assert fixture.ipv6_error == "no IPv6 loopback on this machine"
            assert len(fixture.denied) == 1
            ipv6 = next(v for v in fixture.vectors() if v.name == "ipv6_loopback")
            assert (ipv6.template, ipv6.unsupported) == (None, "no IPv6 loopback on this machine")
        finally:
            fixture.cleanup()

    def test_unbindable_ipv6_loopback_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real = _Listener

        def no_ipv6(family: socket.AddressFamily, host: str, port: int, owner: NetworkFixture) -> object:
            if family == socket.AF_INET6:
                raise OSError("unavailable")
            return real(family, host, port, owner)

        monkeypatch.setattr("mcpscore.smoke_network._Listener", no_ipv6)
        fixture = NetworkFixture.create()
        try:
            assert fixture.ipv6_error == "no IPv6 loopback on this machine"
        finally:
            fixture.cleanup()

    def test_a_port_never_free_on_both_addresses_falls_back_to_ipv4(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real = _Listener

        def busy_ipv6_port(family: socket.AddressFamily, host: str, port: int, owner: NetworkFixture) -> object:
            if family == socket.AF_INET6 and port != 0:
                raise OSError("in use")
            return real(family, host, port, owner)

        monkeypatch.setattr("mcpscore.smoke_network._Listener", busy_ipv6_port)
        monkeypatch.setattr(socket, "has_ipv6", True)
        fixture = NetworkFixture.create()
        try:
            if fixture.ipv6_error == "no IPv6 loopback on this machine":
                pytest.skip(fixture.ipv6_error)
            assert fixture.ipv6_error == "could not bind the same port on 127.0.0.1 and ::1"
            assert len(fixture.denied) == 1
        finally:
            fixture.cleanup()

    def test_a_failed_bind_releases_the_allowed_listener(self, monkeypatch: pytest.MonkeyPatch) -> None:
        closed: list[int] = []
        real_close = _Listener.server_close

        def record_close(listener: Any) -> None:
            closed.append(listener.server_address[1])
            real_close(listener)

        def refuse(_fixture: NetworkFixture) -> None:
            raise OSError("no ports")

        monkeypatch.setattr(_Listener, "server_close", record_close)
        monkeypatch.setattr(NetworkFixture, "_bind_denied", refuse)

        with pytest.raises(OSError, match="no ports"):
            NetworkFixture.create()
        assert len(closed) == 1


def _tool(name: str) -> Tool:
    return Tool(name=name, input_schema={"type": "object"})


def _scripted_session(answer_for: Callable[[str], object]) -> Any:
    """Build a session whose raw ``tools/call`` answers come from ``answer_for(url)``."""

    class Session:
        async def send_request(self, request: RawRequest, *_args: Any, **_kwargs: Any) -> object:
            answer = answer_for(request.params["arguments"]["url"])
            if isinstance(answer, BaseException):
                raise answer
            if isinstance(answer, CallToolResult):
                return RawResult(**answer.model_dump(by_alias=True, mode="json", exclude_none=True))
            return answer

    return Session()


def _ok(text: str = "fetched") -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)])


class TestCallOutcomes:
    async def test_control_that_answers_without_fetching_explains_itself(self, fixture: NetworkFixture) -> None:
        results = await run_network_checks(_scripted_session(lambda _url: _ok()), [_tool("fetch")], ALLOWLIST, fixture)

        assert {r.verdict for r in results} == {SmokeVerdict.SKIP}
        assert results[0].message.startswith(
            "positive control failed: fetching the allowed origin /control did not reach the allowed origin"
        )

    async def test_control_that_times_out_is_not_counted_as_called(self, fixture: NetworkFixture) -> None:
        timeout = MCPError(REQUEST_TIMEOUT, "timed out")
        results = await run_network_checks(
            _scripted_session(lambda _url: timeout), [_tool("fetch")], ALLOWLIST, fixture
        )

        assert "no answer within" in results[0].message
        assert results[0].details["called"] is False

    async def test_unjudgeable_vector_skips_after_a_good_control(self, fixture: NetworkFixture) -> None:
        def answer(url: str) -> object:
            if url.endswith("/control"):
                _get(url)
                return _ok()
            return MCPError(REQUEST_TIMEOUT, "timed out")

        results = await run_network_checks(_scripted_session(answer), [_tool("fetch")], ALLOWLIST, fixture)

        direct = next(r for r in results if r.details["vector"] == "direct")
        assert direct.verdict is SmokeVerdict.SKIP
        assert direct.message.endswith("— the boundary was not exercised")
        assert direct.details["control_called"] is True

    async def test_answer_without_a_request_passes_under_allowlist(self, fixture: NetworkFixture) -> None:
        def answer(url: str) -> object:
            if url.endswith("/control"):
                _get(url)
            return _ok()

        results = await run_network_checks(_scripted_session(answer), [_tool("fetch")], ALLOWLIST, fixture)

        direct = next(r for r in results if r.details["vector"] == "direct")
        assert (direct.verdict, direct.message) == (
            SmokeVerdict.PASS,
            "answered; no request reached the denied destination",
        )

    async def test_a_method_the_listener_does_not_serve_still_fails(self, fixture: NetworkFixture) -> None:
        def answer(url: str) -> object:
            if "/v/direct" in url:
                connection = http.client.HTTPConnection("127.0.0.1", fixture.denied_port, timeout=5)
                connection.request("TRACE", "/v/direct")
                connection.getresponse().read()
                connection.close()
            return _ok()

        results = await run_network_checks(_scripted_session(answer), [_tool("fetch")], DENY_PRIVATE, fixture)

        direct = next(r for r in results if r.details["vector"] == "direct")
        assert (direct.verdict, direct.details["denied_requests"]) == (SmokeVerdict.FAIL, ["TRACE /v/direct"])

    async def test_evidence_is_the_current_vector_s_even_across_both_addresses(self, fixture: NetworkFixture) -> None:
        if fixture.ipv6_error is not None:
            pytest.skip(fixture.ipv6_error)

        def answer(url: str) -> object:
            if "/v/ipv6_loopback" in url:
                _get(url)
            if "/v/ipv4_mapped_ipv6" in url:
                _get(f"http://127.0.0.1:{fixture.denied_port}/v/ipv4_mapped_ipv6")
            return _ok()

        results = await run_network_checks(_scripted_session(answer), [_tool("fetch")], DENY_PRIVATE, fixture)

        evidence = {r.details["vector"]: r.details.get("denied_requests") for r in results}
        assert evidence["ipv6_loopback"] == ["GET /v/ipv6_loopback"]
        assert evidence["ipv4_mapped_ipv6"] == ["GET /v/ipv4_mapped_ipv6"]

    async def test_under_deny_private_the_allowed_listener_is_denied_too(self, fixture: NetworkFixture) -> None:
        def answer(url: str) -> object:
            if url.endswith("/redirect"):
                connection = http.client.HTTPConnection("127.0.0.1", fixture.allowed_port, timeout=5)
                connection.request("GET", "/redirect")
                connection.getresponse().read()
                connection.close()
                return CallToolResult(content=[TextContent(type="text", text="not following")], is_error=True)
            return CallToolResult(content=[TextContent(type="text", text="blocked")], is_error=True)

        deny = await run_network_checks(_scripted_session(answer), [_tool("fetch")], DENY_PRIVATE, fixture)

        redirect = next(r for r in deny if r.details["vector"] == "redirect")
        assert (redirect.verdict, redirect.details["denied_requests"]) == (SmokeVerdict.FAIL, ["GET /redirect"])

    async def test_a_fetch_in_the_background_fails_after_the_last_vector(
        self, fixture: NetworkFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("mcpscore.smoke_network._LATE_GRACE_S", 1.0)
        background: list[threading.Timer] = []

        def answer(url: str) -> object:
            if url.endswith("/control"):
                _get(url)
            elif url.endswith("/redirect"):
                denied = f"http://127.0.0.1:{fixture.denied_port}/v/redirect"
                background.append(threading.Timer(0.2, _get, args=(denied,)))
                background[-1].start()
            return _ok("queued")

        results = await run_network_checks(_scripted_session(answer), [_tool("fetch")], ALLOWLIST, fixture)
        for timer in background:
            timer.join()

        assert _by_verdict(results, SmokeVerdict.FAIL) == {"late_request"}
        late = results[-1]
        assert late.details["denied_requests"] == ["GET /v/redirect"]
        assert late.message.startswith(
            "a request reached a destination the policy denies after the calls returned (GET /v/redirect)"
        )

    async def test_a_request_between_two_windows_is_still_attributed(
        self, fixture: NetworkFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = fixture.reached_since
        injected: list[str] = []

        def then_a_request_arrives(*args: Any, **kwargs: Any) -> Any:
            observed = real(*args, **kwargs)
            if not injected:
                injected.append(url := f"http://127.0.0.1:{fixture.denied_port}/v/between")
                _get(url)
            return observed

        monkeypatch.setattr(fixture, "reached_since", then_a_request_arrives)

        def answer(url: str) -> object:
            if url.endswith("/control"):
                _get(url)
            return _ok()

        results = await run_network_checks(_scripted_session(answer), [_tool("fetch")], ALLOWLIST, fixture)

        failed = [r for r in results if r.verdict is SmokeVerdict.FAIL]
        assert [r.details["denied_requests"] for r in failed] == [["GET /v/between"]]

    @pytest.mark.parametrize("control_works", [True, False])
    async def test_a_control_that_also_reaches_the_denied_listener_fails(
        self, fixture: NetworkFixture, control_works: bool
    ) -> None:
        def answer(url: str) -> object:
            if url.endswith("/control"):
                if control_works:
                    _get(url)
                _get(f"http://127.0.0.1:{fixture.denied_port}/v/during-control")
                return _ok() if control_works else MCPError(REQUEST_TIMEOUT, "timed out")
            return _ok()

        results = await run_network_checks(_scripted_session(answer), [_tool("fetch")], ALLOWLIST, fixture)

        failed = [r for r in results if r.verdict is SmokeVerdict.FAIL]
        assert [(r.details["vector"], r.details["denied_requests"]) for r in failed] == [
            ("positive_control", ["GET /v/during-control"])
        ]
        assert failed[0].message == (
            "fetching the allowed origin also reached a destination the policy denies (GET /v/during-control)"
        )
        assert (results[1].verdict is SmokeVerdict.SKIP) is not control_works

    async def test_a_background_fetch_after_a_failed_control_still_fails(
        self, fixture: NetworkFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("mcpscore.smoke_network._LATE_GRACE_S", 1.0)
        background: list[threading.Timer] = []

        def answer(url: str) -> object:
            denied = f"http://127.0.0.1:{fixture.denied_port}/v/after-control"
            background.append(threading.Timer(0.2, _get, args=(denied,)))
            background[-1].start()
            return _ok("queued")

        results = await run_network_checks(_scripted_session(answer), [_tool("fetch")], ALLOWLIST, fixture)
        for timer in background:
            timer.join()

        assert [r.details["vector"] for r in results if r.verdict is SmokeVerdict.FAIL] == ["late_request"]

    async def test_a_hit_fails_even_when_the_tool_reports_an_error(self, fixture: NetworkFixture) -> None:
        def answer(url: str) -> object:
            if "/v/direct" in url:
                _get(url)
                return CallToolResult(content=[TextContent(type="text", text="blocked")], is_error=True)
            return _ok()

        results = await run_network_checks(_scripted_session(answer), [_tool("fetch")], DENY_PRIVATE, fixture)

        assert _by_verdict(results, SmokeVerdict.FAIL) == {"direct"}


def test_not_runnable_is_one_skip() -> None:
    (result,) = not_runnable("why")

    assert (result.check_id, result.verdict, result.message, result.tool_name) == (
        CHECK_NETWORK_BOUNDARY,
        SmokeVerdict.SKIP,
        "why",
        None,
    )
    assert "vector" not in result.details
