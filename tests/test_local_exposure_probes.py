"""Tests for the probes that judge a local server's DNS-rebinding and network exposure."""

import asyncio
import ipaddress
import json
import socket
from typing import Self

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


async def _host_probe(handler, url: str = LOCAL_URL):
    async with httpx2.AsyncClient(transport=httpx2.MockTransport(handler)) as client:
        return await _probe_host_validation(_HttpTarget(client, url))


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
    assert spoofed.headers["Host"] == HOST_PROBE_VALUE
    # Only Host can explain the refusal: neither request carries an Origin.
    assert "Origin" not in control.headers
    assert "Origin" not in spoofed.headers


async def test_host_probe_fails_a_server_that_serves_any_host():
    result = await _host_probe(_host_checking_handler(checks_host=False))

    assert result.outcome is ProbeOutcome.UNSUPPORTED
    assert result.details["http_status"] == 200


async def test_host_probe_drops_a_caller_configured_origin():
    seen: list[httpx2.Request] = []
    handler = _host_checking_handler(checks_host=True, seen=seen)
    async with httpx2.AsyncClient(
        transport=httpx2.MockTransport(handler), headers={"Origin": "http://localhost:8000"}
    ) as client:
        result = await _probe_host_validation(_HttpTarget(client, LOCAL_URL))

    assert result.outcome is ProbeOutcome.SUPPORTED
    assert all("Origin" not in request.headers for request in seen)


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
    deletes: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.method == "DELETE":
            deletes.append(request.headers["Mcp-Session-Id"])
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
    assert deletes == ["sess-1", "sess-1"]


async def test_tcp_listening_tells_an_open_port_from_a_closed_one():
    server = await asyncio.start_server(lambda _reader, writer: writer.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        assert await _tcp_listening("127.0.0.1", port) is True
    finally:
        server.close()
        await server.wait_closed()
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


async def _bind_probe(monkeypatch: pytest.MonkeyPatch, url: str, addresses: list[str], listening: set[str]):
    calls: list[tuple[str, int]] = []

    async def fake_listening(host: str, port: int) -> bool:
        calls.append((host, port))
        return host in listening

    monkeypatch.setattr(probes, "_non_loopback_addresses", lambda: addresses)
    monkeypatch.setattr(probes, "_tcp_listening", fake_listening)
    async with httpx2.AsyncClient() as client:
        result = await _probe_local_bind(_HttpTarget(client, url))
    return result, calls


async def test_bind_probe_fails_a_server_reachable_on_another_interface(monkeypatch: pytest.MonkeyPatch):
    result, calls = await _bind_probe(
        monkeypatch, LOCAL_URL, ["192.168.1.20", "2001:db8::20"], listening={"192.168.1.20"}
    )

    assert result.probe_id == PROBE_LOCAL_BIND
    assert result.outcome is ProbeOutcome.UNSUPPORTED
    assert result.details == {"port": 8000, "interfaces_checked": 2, "interfaces_reachable": 1}
    assert sorted(calls) == [("192.168.1.20", 8000), ("2001:db8::20", 8000)]
    # The report records counts, never this machine's addresses.
    assert "192.168.1.20" not in json.dumps(result.details)


async def test_bind_probe_passes_a_server_bound_to_loopback_only(monkeypatch: pytest.MonkeyPatch):
    result, _ = await _bind_probe(monkeypatch, "http://127.0.0.1/mcp", ["192.168.1.20"], listening=set())

    assert result.outcome is ProbeOutcome.SUPPORTED
    assert result.details == {"port": 80, "interfaces_checked": 1, "interfaces_reachable": 0}


async def test_bind_probe_uses_the_https_default_port(monkeypatch: pytest.MonkeyPatch):
    _, calls = await _bind_probe(monkeypatch, "https://[::1]/mcp", ["192.168.1.20"], listening=set())

    assert calls == [("192.168.1.20", 443)]


async def test_bind_probe_without_a_routable_address_is_not_applicable(monkeypatch: pytest.MonkeyPatch):
    result, calls = await _bind_probe(monkeypatch, LOCAL_URL, [], listening=set())

    assert result.outcome is ProbeOutcome.NOT_APPLICABLE
    assert calls == []


async def test_bind_probe_does_not_judge_a_public_host(monkeypatch: pytest.MonkeyPatch):
    result, calls = await _bind_probe(monkeypatch, "https://server.example/mcp", ["192.168.1.20"], {"192.168.1.20"})

    assert result.outcome is ProbeOutcome.NOT_APPLICABLE
    assert calls == []


def test_both_probes_are_http_only():
    assert PROBE_HOST_VALIDATION in probes.HTTP_ONLY_PROBE_IDS
    assert PROBE_LOCAL_BIND in probes.HTTP_ONLY_PROBE_IDS
