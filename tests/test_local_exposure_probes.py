"""Tests for the probes that judge a local server's DNS-rebinding and network exposure."""

import asyncio
import ipaddress
import json
import socket
from typing import Self
from unittest.mock import patch

import httpx2
import pytest

from mcpscore import probes
from mcpscore.probes import (
    HOST_PROBE_VALUE,
    PROBE_HOST_VALIDATION,
    PROBE_LOCAL_BIND,
    ProbeOutcome,
    _HttpTarget,
    _is_loopback_host,
    _non_loopback_addresses,
    _probe_host_validation,
    _probe_local_bind,
    _tcp_listening,
)

LOCAL_URL = "http://localhost:8000/mcp"


def _discover_result(request_id) -> httpx2.Response:
    return httpx2.Response(
        200,
        json={
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"supportedVersions": ["2026-07-28"], "resultType": "complete"},
        },
    )


def _host_checking_handler(*, checks_host: bool, seen: list[httpx2.Request] | None = None):
    def handler(request: httpx2.Request) -> httpx2.Response:
        if seen is not None:
            seen.append(request)
        body = json.loads(request.content) if request.method == "POST" else {}
        if checks_host and request.headers.get("Host") != "localhost:8000":
            return httpx2.Response(421, text="Invalid Host header")
        return _discover_result(body.get("id"))

    return handler


def _direct_mock(handler):
    """Stand in for the probe's direct client: same handler, carrying the caller's headers."""
    return patch.object(
        probes,
        "_direct_client",
        lambda headers=None: httpx2.AsyncClient(transport=httpx2.MockTransport(handler), headers=headers),
    )


async def _host_probe(handler, url: str = LOCAL_URL, headers: dict[str, str] | None = None):
    async with httpx2.AsyncClient(headers=headers) as caller_client:
        with _direct_mock(handler):
            return await _probe_host_validation(_HttpTarget(caller_client, url))


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("localhost", True),
        ("LOCALHOST.", True),
        ("app.localhost", True),
        ("127.0.0.1", True),
        ("127.8.9.10", True),
        ("::1", True),
        ("[::1]", True),
        ("::ffff:127.0.0.1", True),
        ("0.0.0.0", False),
        ("10.0.0.5", False),
        ("server.local", False),
        ("localhost.example.com", False),
        ("example.com", False),
        (None, False),
        ("", False),
    ],
)
def test_loopback_hosts(host: str | None, expected: bool):
    assert _is_loopback_host(host) is expected


async def test_host_probe_passes_a_server_that_refuses_a_foreign_host():
    seen: list[httpx2.Request] = []
    result = await _host_probe(_host_checking_handler(checks_host=True, seen=seen))

    assert result.outcome is ProbeOutcome.SUPPORTED
    assert result.details["http_status"] == 421
    assert result.details["control_http_status"] == 200
    assert result.details["control_shape"] == "modern"
    control, spoofed = seen
    assert control.headers["Host"] == "localhost:8000"
    assert spoofed.headers["Host"] == f"{HOST_PROBE_VALUE}:8000"
    # Only Host can explain the refusal: neither request carries an Origin.
    assert "Origin" not in control.headers
    assert "Origin" not in spoofed.headers


async def test_host_probe_keeps_the_port_so_only_the_hostname_is_foreign():
    """A server that checks only the port must not pass: a rebound request keeps the port."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        if not request.headers["Host"].endswith(":8000"):
            return httpx2.Response(400, text="bad port")
        return _discover_result(json.loads(request.content).get("id"))

    result = await _host_probe(handler)

    assert result.outcome is ProbeOutcome.UNSUPPORTED
    assert result.details["http_status"] == 200


async def test_host_probe_keeps_the_port_of_a_caller_configured_host():
    seen: list[httpx2.Request] = []
    await _host_probe(_host_checking_handler(checks_host=False, seen=seen), headers={"Host": "localhost:9000"})

    control, spoofed = seen
    assert control.headers["Host"] == "localhost:9000"
    assert spoofed.headers["Host"] == f"{HOST_PROBE_VALUE}:9000"


@pytest.mark.parametrize(
    ("host", "suffix"),
    [("localhost:8000", ":8000"), ("localhost", ""), ("[::1]:8000", ":8000"), ("[::1]", ""), ("host:", "")],
)
def test_port_suffix(host: str, suffix: str):
    assert probes._port_suffix(host) == suffix


async def test_host_probe_omits_the_port_for_a_default_port_target():
    seen: list[httpx2.Request] = []
    await _host_probe(_host_checking_handler(checks_host=False, seen=seen), "http://localhost/mcp")

    assert seen[-1].headers["Host"] == HOST_PROBE_VALUE


def _sse(*events: str) -> bytes:
    return "".join(f"{event}\n\n" for event in events).encode()


async def test_host_probe_reads_a_control_answered_after_an_sse_priming_event():
    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        if request.headers["Host"] != "localhost:8000":
            return httpx2.Response(421)
        result = {"jsonrpc": "2.0", "id": body["id"], "result": {"supportedVersions": ["2026-07-28"]}}
        return httpx2.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=_sse("id: 1\ndata:", f"data: {json.dumps(result)}"),
        )

    result = await _host_probe(handler)

    assert result.outcome is ProbeOutcome.SUPPORTED
    assert result.details["control_http_status"] == 200


async def test_origin_probe_reads_a_control_answered_after_an_sse_priming_event():
    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        if request.headers.get("Origin") is not None:
            return httpx2.Response(403)
        result = {"jsonrpc": "2.0", "id": body["id"], "result": {"supportedVersions": ["2026-07-28"]}}
        return httpx2.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=_sse("id: 1\ndata:", f"data: {json.dumps(result)}"),
        )

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        result = await probes._probe_origin_validation(_HttpTarget(client, "https://server.example/mcp"))

    assert result.outcome is ProbeOutcome.SUPPORTED
    assert result.details["control_shape"] == "modern"


async def test_origin_probe_judges_a_server_whose_discover_answer_is_large():
    instructions = "x" * 100_000

    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        if request.headers.get("Origin") is not None:
            return httpx2.Response(403)
        if body["method"] != "server/discover":
            return httpx2.Response(400)
        result = {"supportedVersions": ["2026-07-28"], "instructions": instructions}
        return httpx2.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})

    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        result = await probes._probe_origin_validation(_HttpTarget(client, "https://server.example/mcp"))

    assert result.outcome is ProbeOutcome.SUPPORTED
    assert result.details["control_shape"] == "modern"


async def test_an_unreadable_control_answer_is_no_evidence(monkeypatch: pytest.MonkeyPatch):
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, headers={"content-type": "application/json"}, content=b" " * 2_000)

    monkeypatch.setattr(probes, "CONTROL_READ_LIMIT", 1_000)
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        result = await probes._probe_origin_validation(_HttpTarget(client, "https://server.example/mcp"))

    assert result.outcome is ProbeOutcome.ERROR
    assert result.details["control_unobservable"] == "capped"
    assert "modern_control_http_status" not in result.details


async def test_an_unreadable_legacy_fallback_answer_is_no_evidence(monkeypatch: pytest.MonkeyPatch):
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "DELETE":
            return httpx2.Response(200)
        if json.loads(request.content)["method"] == "server/discover":
            return httpx2.Response(400)
        return httpx2.Response(200, headers={"content-type": "application/json"}, content=b" " * 2_000)

    monkeypatch.setattr(probes, "CONTROL_READ_LIMIT", 1_000)
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        result = await probes._probe_origin_validation(_HttpTarget(client, "https://server.example/mcp"))

    assert result.outcome is ProbeOutcome.ERROR
    assert result.details["modern_control_http_status"] == 400
    assert result.details["control_unobservable"] == "capped"


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503])
async def test_host_probe_does_not_judge_a_timeout_rate_limit_or_server_error(status: int):
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.headers["Host"].startswith(HOST_PROBE_VALUE):
            return httpx2.Response(status)
        return _discover_result(json.loads(request.content).get("id"))

    result = await _host_probe(handler)

    assert result.outcome is ProbeOutcome.ERROR
    assert result.details["http_status"] == status


@pytest.mark.parametrize(
    ("url", "control_host"), [("http://localhost:80/mcp", "localhost"), ("https://localhost:443/mcp", "localhost")]
)
async def test_host_probe_follows_the_normalized_default_port(url: str, control_host: str):
    seen: list[httpx2.Request] = []
    await _host_probe(_host_checking_handler(checks_host=False, seen=seen), url)

    control, spoofed = seen
    assert control.headers["Host"] == control_host
    assert spoofed.headers["Host"] == HOST_PROBE_VALUE


async def test_host_probe_fails_a_server_that_serves_any_host():
    result = await _host_probe(_host_checking_handler(checks_host=False))

    assert result.outcome is ProbeOutcome.UNSUPPORTED
    assert result.details["http_status"] == 200


async def test_host_probe_drops_a_caller_configured_origin():
    seen: list[httpx2.Request] = []
    result = await _host_probe(
        _host_checking_handler(checks_host=True, seen=seen), headers={"Origin": "http://localhost:8000"}
    )

    assert result.outcome is ProbeOutcome.SUPPORTED
    assert all("Origin" not in request.headers for request in seen)


async def test_host_probe_sends_both_requests_directly_with_the_caller_headers():
    seen: list[httpx2.Request] = []
    result = await _host_probe(
        _host_checking_handler(checks_host=True, seen=seen), headers={"Authorization": "Bearer caller-token"}
    )

    assert result.outcome is ProbeOutcome.SUPPORTED
    assert [request.headers["Authorization"] for request in seen] == ["Bearer caller-token"] * 2


async def test_direct_client_carries_the_given_headers_and_no_proxy(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:3128")
    async with probes._direct_client({"Authorization": "Bearer t"}) as client:
        assert client.trust_env is False
        assert client.headers["Authorization"] == "Bearer t"


async def test_direct_client_keeps_the_configured_ca_trust(monkeypatch: pytest.MonkeyPatch):
    seen: list[bool] = []

    def fake_context(trust_env: bool = True):
        seen.append(trust_env)
        return True

    monkeypatch.setattr(probes, "client_ssl_context", fake_context)
    async with probes._direct_client() as client:
        assert client.trust_env is False
    assert seen == [True]


async def test_host_probe_does_not_judge_a_public_host():
    seen: list[httpx2.Request] = []
    result = await _host_probe(_host_checking_handler(checks_host=False, seen=seen), "https://server.example/mcp")

    assert result.outcome is ProbeOutcome.NOT_APPLICABLE
    assert seen == []


async def test_host_probe_does_not_judge_an_access_controlled_server():
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(401)

    result = await _host_probe(handler)

    assert result.outcome is ProbeOutcome.NOT_APPLICABLE
    assert result.details["reason"] == "control request is access-controlled; Host handling not observable"


async def test_host_probe_judges_a_legacy_server_through_initialize_and_closes_its_sessions():
    deletes: list[tuple[str, str]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "DELETE":
            deletes.append((request.headers["Mcp-Session-Id"], request.headers["Host"]))
            return httpx2.Response(200)
        body = json.loads(request.content)
        if body["method"] != "initialize":
            return httpx2.Response(400, json={"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32600}})
        return httpx2.Response(
            200,
            headers={"Mcp-Session-Id": "sess-1"},
            json={"jsonrpc": "2.0", "id": body["id"], "result": {"protocolVersion": "2025-11-25"}},
        )

    result = await _host_probe(handler)

    assert result.outcome is ProbeOutcome.UNSUPPORTED
    assert result.details["control_shape"] == "legacy-initialize"
    assert result.details["modern_control_http_status"] == 400
    # Each session is closed on the Host that opened it.
    assert deletes == [("sess-1", "localhost:8000"), ("sess-1", f"{HOST_PROBE_VALUE}:8000")]


async def test_host_probe_bounds_a_spoofed_response_that_never_ends(monkeypatch: pytest.MonkeyPatch):
    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.headers["Host"].startswith(HOST_PROBE_VALUE):
            await asyncio.sleep(3600)
        return _discover_result(json.loads(request.content).get("id"))

    monkeypatch.setattr(probes, "PROBE_TIMEOUT_S", 0.05)
    with pytest.raises(httpx2.TimeoutException):
        await _host_probe(handler)


async def test_bind_probe_bounds_a_loopback_control_that_never_ends(monkeypatch: pytest.MonkeyPatch):
    async def handler(request: httpx2.Request) -> httpx2.Response:
        await asyncio.sleep(3600)
        return httpx2.Response(200)

    monkeypatch.setattr(probes, "PROBE_TIMEOUT_S", 0.05)
    monkeypatch.setattr(probes, "_non_loopback_addresses", lambda: ["192.168.1.20"])
    monkeypatch.setattr(
        probes,
        "_direct_client",
        lambda headers=None: httpx2.AsyncClient(transport=httpx2.MockTransport(handler), headers=headers),
    )
    async with httpx2.AsyncClient() as client:
        with pytest.raises(httpx2.TimeoutException):
            await _probe_local_bind(_HttpTarget(client, LOCAL_URL))


async def test_tcp_listening_tells_an_open_port_from_a_closed_one():
    server = await asyncio.start_server(lambda _reader, writer: writer.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        assert await _tcp_listening("127.0.0.1", port) is True
    finally:
        server.close()
        await server.wait_closed()
    # A closed loopback port refuses the connection.
    assert await _tcp_listening("127.0.0.1", port) is False


def test_non_loopback_addresses_skip_loopback_and_link_local():
    for address in _non_loopback_addresses():
        ip = ipaddress.ip_address(address)
        assert not ip.is_loopback
        assert not ip.is_link_local
        assert not ip.is_unspecified


class _FakeSocket:
    """A UDP socket whose source address per family is scripted; None means the family has no route."""

    addresses: dict[int, str | None] = {}

    def __init__(self, family: int, _type: int) -> None:
        self.family = family

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def connect(self, _address: tuple[str, int]) -> None:
        if self.addresses.get(self.family) is None:
            raise OSError("Network is unreachable")

    def getsockname(self) -> tuple[str, int]:
        return (self.addresses[self.family] or "", 0)


@pytest.mark.parametrize(
    ("scripted", "expected"),
    [
        ({socket.AF_INET: "192.168.1.20", socket.AF_INET6: None}, ["192.168.1.20"]),
        ({socket.AF_INET: "127.0.0.1", socket.AF_INET6: "fe80::1%en0"}, []),
        ({socket.AF_INET: "10.0.0.7", socket.AF_INET6: "2001:db8::7"}, ["10.0.0.7", "2001:db8::7"]),
    ],
)
def test_non_loopback_addresses_keep_routable_default_route_addresses(monkeypatch, scripted, expected):
    monkeypatch.setattr(_FakeSocket, "addresses", scripted)
    monkeypatch.setattr(probes.socket, "socket", _FakeSocket)
    assert _non_loopback_addresses() == expected


async def _bind_probe(
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    addresses: list[str],
    states: dict[str, bool | None],
    *,
    serving: set[str] = frozenset(),
    loopback_status: int = 200,
):
    """Run the bind probe with scripted interface addresses, TCP answers and MCP-serving hosts."""
    connects: list[tuple[str, int]] = []
    requests: list[httpx2.Request] = []

    async def fake_listening(host: str, port: int) -> bool | None:
        connects.append((host, port))
        return states.get(host, False)

    def handler(request: httpx2.Request) -> httpx2.Response:
        requests.append(request)
        body = json.loads(request.content)
        host = request.url.host
        if host in serving or (_is_loopback_host(host) and loopback_status == 200):
            return _discover_result(body.get("id"))
        return httpx2.Response(loopback_status if _is_loopback_host(host) else 404)

    monkeypatch.setattr(probes, "_non_loopback_addresses", lambda: addresses)
    monkeypatch.setattr(probes, "_tcp_listening", fake_listening)
    monkeypatch.setattr(
        probes,
        "_direct_client",
        lambda headers=None: httpx2.AsyncClient(transport=httpx2.MockTransport(handler), headers=headers),
    )
    # The caller's client carries credentials; the probe must never use it.
    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(handler), headers={"Authorization": "Bearer caller-secret"}
    ) as caller_client:
        result = await _probe_local_bind(_HttpTarget(caller_client, url))
    return result, connects, requests


async def test_bind_probe_fails_a_server_that_serves_on_another_interface(monkeypatch: pytest.MonkeyPatch):
    result, connects, requests = await _bind_probe(
        monkeypatch,
        LOCAL_URL,
        ["192.168.1.20", "2001:db8::20"],
        {"192.168.1.20": True, "2001:db8::20": False},
        serving={"192.168.1.20"},
    )

    assert result.probe_id == PROBE_LOCAL_BIND
    assert result.outcome is ProbeOutcome.UNSUPPORTED
    assert result.details == {
        "port": 8000,
        "interfaces_checked": 2,
        "interfaces_listening": 1,
        "interfaces_serving": 1,
        "interfaces_unknown": 0,
    }
    assert sorted(connects) == [("192.168.1.20", 8000), ("2001:db8::20", 8000)]
    lan = [request for request in requests if request.url.host == "192.168.1.20"]
    # The network-address control carries the audited URL's Host, so a Host check cannot hide the server.
    assert [request.headers["Host"] for request in lan] == ["localhost:8000"]
    assert str(lan[0].url) == "http://192.168.1.20:8000/mcp"
    # The report records counts, never this machine's addresses.
    assert "192.168.1.20" not in json.dumps(result.details)


async def test_bind_probe_ignores_an_unrelated_listener_on_the_same_port(monkeypatch: pytest.MonkeyPatch):
    result, _, _ = await _bind_probe(monkeypatch, LOCAL_URL, ["192.168.1.20"], {"192.168.1.20": True})

    assert result.outcome is ProbeOutcome.SUPPORTED
    assert result.details["interfaces_listening"] == 1
    assert result.details["interfaces_serving"] == 0


@pytest.mark.parametrize("status", [408, 429, 500, 503])
async def test_bind_probe_counts_an_inconclusive_network_answer_as_unknown(
    monkeypatch: pytest.MonkeyPatch, status: int
):
    async def fake_listening(host: str, port: int) -> bool:
        return True

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.host == "192.168.1.20":
            return httpx2.Response(status)
        return _discover_result(json.loads(request.content).get("id"))

    monkeypatch.setattr(probes, "_non_loopback_addresses", lambda: ["192.168.1.20"])
    monkeypatch.setattr(probes, "_tcp_listening", fake_listening)
    monkeypatch.setattr(
        probes,
        "_direct_client",
        lambda headers=None: httpx2.AsyncClient(transport=httpx2.MockTransport(handler), headers=headers),
    )
    async with httpx2.AsyncClient() as client:
        result = await _probe_local_bind(_HttpTarget(client, LOCAL_URL))

    assert result.outcome is ProbeOutcome.ERROR
    assert result.details["interfaces_unknown"] == 1


async def test_bind_probe_counts_an_inconclusive_modern_answer_before_a_refused_fallback_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
):
    async def fake_listening(host: str, port: int) -> bool:
        return True

    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        if request.url.host != "192.168.1.20":
            return _discover_result(body.get("id"))
        return httpx2.Response(503 if body["method"] == "server/discover" else 400)

    monkeypatch.setattr(probes, "_non_loopback_addresses", lambda: ["192.168.1.20"])
    monkeypatch.setattr(probes, "_tcp_listening", fake_listening)
    monkeypatch.setattr(
        probes,
        "_direct_client",
        lambda headers=None: httpx2.AsyncClient(transport=httpx2.MockTransport(handler), headers=headers),
    )
    async with httpx2.AsyncClient() as client:
        result = await _probe_local_bind(_HttpTarget(client, LOCAL_URL))

    assert result.outcome is ProbeOutcome.ERROR
    assert result.details["interfaces_unknown"] == 1


async def test_bind_probe_counts_an_unreadable_network_answer_as_unknown(monkeypatch: pytest.MonkeyPatch):
    async def fake_listening(host: str, port: int) -> bool:
        return True

    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        if request.url.host != "192.168.1.20":
            return _discover_result(body.get("id"))
        # Over the control read cap, so the replayed control cannot be read.
        return httpx2.Response(200, headers={"content-type": "application/json"}, content=b" " * 2_000)

    monkeypatch.setattr(probes, "CONTROL_READ_LIMIT", 1_000)
    monkeypatch.setattr(probes, "_non_loopback_addresses", lambda: ["192.168.1.20"])
    monkeypatch.setattr(probes, "_tcp_listening", fake_listening)
    monkeypatch.setattr(
        probes,
        "_direct_client",
        lambda headers=None: httpx2.AsyncClient(transport=httpx2.MockTransport(handler), headers=headers),
    )
    async with httpx2.AsyncClient() as client:
        result = await _probe_local_bind(_HttpTarget(client, LOCAL_URL))

    assert result.outcome is ProbeOutcome.ERROR
    assert result.details["interfaces_unknown"] == 1


async def test_host_probe_closes_a_session_whose_spoofed_answer_never_finishes(monkeypatch: pytest.MonkeyPatch):
    deletes: list[tuple[str, str]] = []

    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "DELETE":
            deletes.append((request.headers["Mcp-Session-Id"], request.headers["Host"]))
            return httpx2.Response(200)
        body = json.loads(request.content)
        if body["method"] != "initialize":
            return httpx2.Response(400, json={"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32600}})
        if request.headers["Host"].startswith(HOST_PROBE_VALUE):

            async def stalled():
                yield b": heartbeat\n\n"
                await asyncio.sleep(3600)

            return httpx2.Response(
                200, headers={"Mcp-Session-Id": "sess-2", "content-type": "text/event-stream"}, content=stalled()
            )
        return httpx2.Response(
            200,
            headers={"Mcp-Session-Id": "sess-1"},
            json={"jsonrpc": "2.0", "id": body["id"], "result": {"protocolVersion": "2025-11-25"}},
        )

    monkeypatch.setattr(probes, "PROBE_TIMEOUT_S", 0.1)
    with pytest.raises(httpx2.TimeoutException):
        await _host_probe(handler)

    assert ("sess-2", f"{HOST_PROBE_VALUE}:8000") in deletes


async def test_bind_probe_replays_the_accepted_request_instead_of_falling_back(monkeypatch: pytest.MonkeyPatch):
    """A legacy server on the network address must not stand in for a modern-only audited server."""
    lan_methods: list[str] = []

    async def fake_listening(host: str, port: int) -> bool:
        return True

    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        if request.url.host != "192.168.1.20":
            return _discover_result(body.get("id"))
        lan_methods.append(body["method"])
        if body["method"] == "server/discover":
            return httpx2.Response(400)
        return httpx2.Response(
            200, json={"jsonrpc": "2.0", "id": body["id"], "result": {"protocolVersion": "2025-11-25"}}
        )

    monkeypatch.setattr(probes, "_non_loopback_addresses", lambda: ["192.168.1.20"])
    monkeypatch.setattr(probes, "_tcp_listening", fake_listening)
    monkeypatch.setattr(
        probes,
        "_direct_client",
        lambda headers=None: httpx2.AsyncClient(transport=httpx2.MockTransport(handler), headers=headers),
    )
    async with httpx2.AsyncClient() as client:
        result = await _probe_local_bind(_HttpTarget(client, LOCAL_URL))

    assert result.outcome is ProbeOutcome.SUPPORTED
    assert result.details["interfaces_serving"] == 0
    assert lan_methods == ["server/discover"]


async def test_bind_probe_fails_a_legacy_server_served_on_another_interface_and_closes_its_sessions(
    monkeypatch: pytest.MonkeyPatch,
):
    deletes: list[str] = []

    async def fake_listening(host: str, port: int) -> bool:
        return True

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "DELETE":
            deletes.append(request.url.host)
            return httpx2.Response(200)
        body = json.loads(request.content)
        if body["method"] != "initialize":
            return httpx2.Response(400)
        return httpx2.Response(
            200,
            headers={"Mcp-Session-Id": "sess"},
            json={"jsonrpc": "2.0", "id": body["id"], "result": {"protocolVersion": "2025-11-25"}},
        )

    monkeypatch.setattr(probes, "_non_loopback_addresses", lambda: ["192.168.1.20"])
    monkeypatch.setattr(probes, "_tcp_listening", fake_listening)
    monkeypatch.setattr(
        probes,
        "_direct_client",
        lambda headers=None: httpx2.AsyncClient(transport=httpx2.MockTransport(handler), headers=headers),
    )
    async with httpx2.AsyncClient() as client:
        result = await _probe_local_bind(_HttpTarget(client, LOCAL_URL))

    assert result.outcome is ProbeOutcome.UNSUPPORTED
    assert result.details["interfaces_serving"] == 1
    assert deletes == ["localhost", "192.168.1.20"]


async def test_bind_probe_passes_a_server_bound_to_loopback_only(monkeypatch: pytest.MonkeyPatch):
    result, connects, _ = await _bind_probe(monkeypatch, "http://127.0.0.1/mcp", ["192.168.1.20"], {})

    assert result.outcome is ProbeOutcome.SUPPORTED
    assert result.details["interfaces_serving"] == 0
    assert connects == [("192.168.1.20", 80)]


async def test_bind_probe_with_an_unknown_answer_is_an_error(monkeypatch: pytest.MonkeyPatch):
    result, _, _ = await _bind_probe(
        monkeypatch, LOCAL_URL, ["192.168.1.20", "2001:db8::20"], {"192.168.1.20": False, "2001:db8::20": None}
    )

    assert result.outcome is ProbeOutcome.ERROR
    assert result.details["interfaces_unknown"] == 1


async def test_bind_probe_checks_only_the_target_family(monkeypatch: pytest.MonkeyPatch):
    result, connects, _ = await _bind_probe(monkeypatch, "http://[::1]:8000/mcp", ["192.168.1.20", "2001:db8::20"], {})

    assert result.outcome is ProbeOutcome.SUPPORTED
    assert connects == [("2001:db8::20", 8000)]


async def test_bind_probe_without_an_address_of_the_target_family_is_not_applicable(monkeypatch: pytest.MonkeyPatch):
    result, connects, requests = await _bind_probe(monkeypatch, "http://[::1]:8000/mcp", ["192.168.1.20"], {})

    assert result.outcome is ProbeOutcome.NOT_APPLICABLE
    assert connects == []
    assert requests == []


async def test_bind_probe_does_not_judge_an_access_controlled_server(monkeypatch: pytest.MonkeyPatch):
    result, connects, _ = await _bind_probe(
        monkeypatch, LOCAL_URL, ["192.168.1.20"], {"192.168.1.20": True}, loopback_status=401
    )

    assert result.outcome is ProbeOutcome.NOT_APPLICABLE
    assert connects == []


@pytest.mark.parametrize("url", ["https://localhost:8443/mcp", "https://server.example/mcp"])
async def test_bind_probe_does_not_judge_https_or_public_targets(monkeypatch: pytest.MonkeyPatch, url: str):
    result, connects, requests = await _bind_probe(monkeypatch, url, ["192.168.1.20"], {"192.168.1.20": True})

    assert result.outcome is ProbeOutcome.NOT_APPLICABLE
    assert connects == []
    assert requests == []


async def test_bind_probe_without_a_routable_address_is_not_applicable(monkeypatch: pytest.MonkeyPatch):
    result, connects, _ = await _bind_probe(monkeypatch, LOCAL_URL, [], {})

    assert result.outcome is ProbeOutcome.NOT_APPLICABLE
    assert connects == []


async def test_bind_probe_counts_a_connection_without_an_http_answer_as_unknown(monkeypatch: pytest.MonkeyPatch):
    async def fake_listening(host: str, port: int) -> bool:
        return True

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.host == "192.168.1.20":
            raise httpx2.ReadTimeout("no answer", request=request)
        return _discover_result(json.loads(request.content).get("id"))

    monkeypatch.setattr(probes, "_non_loopback_addresses", lambda: ["192.168.1.20"])
    monkeypatch.setattr(probes, "_tcp_listening", fake_listening)
    monkeypatch.setattr(
        probes,
        "_direct_client",
        lambda headers=None: httpx2.AsyncClient(transport=httpx2.MockTransport(handler), headers=headers),
    )
    async with httpx2.AsyncClient() as client:
        result = await _probe_local_bind(_HttpTarget(client, LOCAL_URL))

    assert result.outcome is ProbeOutcome.ERROR
    assert result.details["interfaces_listening"] == 1
    assert result.details["interfaces_unknown"] == 1


async def test_bind_probe_sends_no_caller_credentials(monkeypatch: pytest.MonkeyPatch):
    _, _, requests = await _bind_probe(
        monkeypatch,
        "http://localhost:8000/mcp?api_key=sk-live-secret&tenant=a",
        ["192.168.1.20"],
        {"192.168.1.20": True},
        serving={"192.168.1.20"},
    )

    assert {request.url.host for request in requests} == {"localhost", "192.168.1.20"}
    for request in requests:
        assert "Authorization" not in request.headers
        assert "api_key" not in str(request.url)
        assert request.url.params["tenant"] == "a"


async def test_bind_probe_sends_no_url_userinfo(monkeypatch: pytest.MonkeyPatch):
    _, _, requests = await _bind_probe(
        monkeypatch,
        "http://user:secret@localhost:8000/mcp",
        ["192.168.1.20"],
        {"192.168.1.20": True},
        serving={"192.168.1.20"},
    )

    assert {request.url.host for request in requests} == {"localhost", "192.168.1.20"}
    for request in requests:
        assert request.headers["Host"] == "localhost:8000"
        assert "Authorization" not in request.headers
        assert "secret" not in str(request.url)


async def test_bind_probe_counts_a_network_answer_that_never_finishes_as_unknown(monkeypatch: pytest.MonkeyPatch):
    async def fake_listening(host: str, port: int) -> bool:
        return True

    async def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        if request.url.host != "192.168.1.20":
            return _discover_result(body.get("id"))

        async def heartbeats():
            while True:
                yield b": heartbeat\n\n"
                await asyncio.sleep(0.01)

        return httpx2.Response(200, headers={"content-type": "text/event-stream"}, content=heartbeats())

    monkeypatch.setattr(probes, "PROBE_TIMEOUT_S", 0.1)
    monkeypatch.setattr(probes, "_non_loopback_addresses", lambda: ["192.168.1.20"])
    monkeypatch.setattr(probes, "_tcp_listening", fake_listening)
    monkeypatch.setattr(
        probes,
        "_direct_client",
        lambda headers=None: httpx2.AsyncClient(transport=httpx2.MockTransport(handler), headers=headers),
    )
    async with httpx2.AsyncClient() as client:
        result = await _probe_local_bind(_HttpTarget(client, LOCAL_URL))

    assert result.outcome is ProbeOutcome.ERROR
    assert result.details["interfaces_unknown"] == 1


async def test_bind_probe_closes_a_session_a_stalled_network_answer_issued(monkeypatch: pytest.MonkeyPatch):
    deletes: list[str] = []

    async def fake_listening(host: str, port: int) -> bool:
        return True

    async def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "DELETE":
            deletes.append(f"{request.url.host}/{request.headers['Mcp-Session-Id']}")
            return httpx2.Response(200)
        body = json.loads(request.content)
        if body["method"] != "initialize":
            return httpx2.Response(400)
        if request.url.host != "192.168.1.20":
            # A legacy-only server on loopback, so the replayed control is its initialize.
            return httpx2.Response(
                200, json={"jsonrpc": "2.0", "id": body["id"], "result": {"protocolVersion": "2025-11-25"}}
            )

        async def heartbeats():
            while True:
                yield b": heartbeat\n\n"
                await asyncio.sleep(0.01)

        return httpx2.Response(
            200, headers={"content-type": "text/event-stream", "Mcp-Session-Id": "lan-1"}, content=heartbeats()
        )

    monkeypatch.setattr(probes, "PROBE_TIMEOUT_S", 0.1)
    # An outer confirmation deadline shorter than the request's own would cancel it before its cleanup runs.
    monkeypatch.setattr(probes, "LOCAL_BIND_CONFIRM_TIMEOUT_S", 0.05, raising=False)
    monkeypatch.setattr(probes, "_non_loopback_addresses", lambda: ["192.168.1.20"])
    monkeypatch.setattr(probes, "_tcp_listening", fake_listening)
    monkeypatch.setattr(
        probes,
        "_direct_client",
        lambda headers=None: httpx2.AsyncClient(transport=httpx2.MockTransport(handler), headers=headers),
    )
    async with httpx2.AsyncClient() as client:
        result = await _probe_local_bind(_HttpTarget(client, LOCAL_URL))

    assert result.outcome is ProbeOutcome.ERROR
    assert deletes == ["192.168.1.20/lan-1"]


async def test_bind_probe_sends_the_normalized_host_for_an_explicit_default_port(monkeypatch: pytest.MonkeyPatch):
    _, _, requests = await _bind_probe(
        monkeypatch, "http://localhost:80/mcp", ["192.168.1.20"], {"192.168.1.20": True}, serving={"192.168.1.20"}
    )

    assert {request.headers["Host"] for request in requests} == {"localhost"}


async def test_bind_probe_leaves_a_server_that_refuses_the_url_host_unjudged(monkeypatch: pytest.MonkeyPatch):
    """A server that serves only a caller-chosen Host refuses both controls alike, so it is not judged."""
    result, connects, _ = await _bind_probe(
        monkeypatch, LOCAL_URL, ["192.168.1.20"], {"192.168.1.20": True}, loopback_status=421
    )

    assert result.outcome is ProbeOutcome.NOT_APPLICABLE
    assert connects == []


async def test_direct_client_ignores_environment_proxies(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:3128")
    async with probes._direct_client() as client:
        assert client.trust_env is False
        assert dict(client.headers).get("authorization") is None


async def test_tcp_listening_reports_a_timeout_as_unknown(monkeypatch: pytest.MonkeyPatch):
    async def never_connects(host: str, port: int):
        raise TimeoutError

    monkeypatch.setattr(probes.asyncio, "open_connection", never_connects)
    assert await _tcp_listening("192.168.1.20", 8000) is None


def test_both_probes_are_http_only():
    assert PROBE_HOST_VALIDATION in probes.HTTP_ONLY_PROBE_IDS
    assert PROBE_LOCAL_BIND in probes.HTTP_ONLY_PROBE_IDS


async def test_injected_client_carries_the_local_server_probes(monkeypatch: pytest.MonkeyPatch):
    """With an injected client, the local-server probes send through it and never open a client of their own."""
    seen: list[httpx2.Request] = []
    handler = _host_checking_handler(checks_host=True, seen=seen)

    def no_own_client(headers=None):
        raise AssertionError("a probe opened its own client although one was injected")

    async def no_socket(*args, **kwargs):
        raise AssertionError("a probe opened a socket although a client was injected")

    monkeypatch.setattr(probes, "_direct_client", no_own_client)
    monkeypatch.setattr(probes, "_non_loopback_addresses", lambda: ["192.168.1.20"])
    monkeypatch.setattr(asyncio, "open_connection", no_socket)
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as injected:
        results = await probes.run_all_probes(LOCAL_URL, client=injected)
        assert not injected.is_closed

    assert results[PROBE_HOST_VALIDATION].outcome is ProbeOutcome.SUPPORTED
    # The mock answers on every address, as a server bound to 0.0.0.0 does.
    assert results[PROBE_LOCAL_BIND].outcome is ProbeOutcome.UNSUPPORTED
    assert results[PROBE_LOCAL_BIND].details["interfaces_serving"] == 1
    assert any(request.headers["Host"].startswith(HOST_PROBE_VALUE) for request in seen)
    assert any(request.url.host == "192.168.1.20" for request in seen)


async def test_bind_probe_sends_no_caller_credentials_through_an_injected_client(monkeypatch: pytest.MonkeyPatch):
    seen: list[httpx2.Request] = []
    monkeypatch.setattr(probes, "_non_loopback_addresses", lambda: ["192.168.1.20"])
    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(_host_checking_handler(checks_host=False, seen=seen)),
        headers={"Authorization": "Bearer caller-secret", "X-API-Key": "caller-key", "Host": "other.example"},
        cookies={"session": "caller-cookie"},
        auth=httpx2.BasicAuth("caller", "password"),
        params={"api_key": "caller-param", "tenant": "caller-tenant"},
    ) as injected:
        result = await _probe_local_bind(_HttpTarget(injected, LOCAL_URL, injected=True))
        assert injected.headers["X-API-Key"] == "caller-key"

    assert result.outcome is ProbeOutcome.UNSUPPORTED
    assert {request.url.host for request in seen} == {"localhost", "192.168.1.20"}
    for request in seen:
        assert "Authorization" not in request.headers
        assert "X-API-Key" not in request.headers
        assert "Cookie" not in request.headers
        assert "User-Agent" in request.headers
        assert request.url.query == b""
        # The URL's own authority, not the injected client's Host default.
        assert request.headers["Host"] == "localhost:8000"


async def test_credential_free_session_cleanup_drops_the_client_defaults():
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(204)

    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(handler),
        headers={"Authorization": "Bearer caller-secret", "X-API-Key": "caller-key"},
        auth=httpx2.BasicAuth("caller", "password"),
    ) as client:
        target = _HttpTarget(client, f"{LOCAL_URL}?token=abc123secretvalue&page=2", credential_free=True)
        issued = probes._HttpProbeResponse(status_code=200, headers={"mcp-session-id": "s1"}, payload=None)
        await target.end_session(issued, {"Host": "localhost:8000"})

    assert [request.method for request in seen] == ["DELETE"]
    assert "Authorization" not in seen[0].headers
    assert "X-API-Key" not in seen[0].headers
    assert seen[0].headers["Mcp-Session-Id"] == "s1"
    assert seen[0].headers["Host"] == "localhost:8000"
    assert str(seen[0].url) == "http://localhost:8000/mcp?page=2"
