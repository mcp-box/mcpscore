"""Tests for CLI stderr: quiet by default, full detail under --verbose."""

from collections.abc import Iterator
import logging
import re
from unittest.mock import patch

import httpx2
import pytest

from mcpscore.cli import build_parser, configure_logging
from mcpscore.enums import MCPTransportType
from mcpscore.mcp_client import MCPClient
from mcpscore.probes import PROBE_IDS, _ProbeFailureLog, failure_cause, run_all_probes

URL = "https://example.com/mcp"
_LOGGERS = ("mcpscore", "httpx2", "httpcore2")


@pytest.fixture(autouse=True)
def _restore_logger_levels() -> Iterator[None]:
    levels = {name: logging.getLogger(name).level for name in _LOGGERS}
    yield
    for name, level in levels.items():
        logging.getLogger(name).setLevel(level)


class TestFailureCause:
    def test_unwraps_a_single_exception_group(self):
        assert failure_cause(ExceptionGroup("task group", [ValueError("real cause")])) == "real cause"

    def test_follows_an_exception_passed_as_the_only_argument(self):
        # httpcore wraps the ssl error this way, and str() of the wrapper is a tuple repr.
        inner = OSError("certificate is expired")
        assert failure_cause(httpx2.ConnectError(inner)) == "certificate is expired"  # type: ignore[arg-type]

    def test_follows_raise_from(self):
        outer = RuntimeError("wrapper")
        outer.__cause__ = ConnectionRefusedError(61, "Connection refused")
        assert failure_cause(outer) == "[Errno 61] Connection refused"

    def test_keeps_a_multi_exception_group_whole(self):
        group = ExceptionGroup("two failures", [ValueError("a"), ValueError("b")])
        assert failure_cause(group) == str(group)

    def test_collapses_whitespace_and_falls_back_to_the_type_name(self):
        assert failure_cause(ValueError("line one\n  line two")) == "line one line two"
        assert failure_cause(TimeoutError()) == "TimeoutError"


class TestConfigureLogging:
    def test_default_hides_http_request_lines_and_debug(self):
        configure_logging()
        assert not logging.getLogger("httpx2").isEnabledFor(logging.INFO)
        assert not logging.getLogger("httpcore2").isEnabledFor(logging.INFO)
        assert not logging.getLogger("mcpscore.probes").isEnabledFor(logging.DEBUG)

    def test_verbose_restores_http_request_lines_and_debug(self):
        configure_logging(verbose=True)
        assert logging.getLogger("httpx2").isEnabledFor(logging.INFO)
        assert logging.getLogger("mcpscore.probes").isEnabledFor(logging.DEBUG)

    @pytest.mark.parametrize("flag", ["-v", "--verbose"])
    def test_flag_parses(self, flag):
        assert build_parser().parse_args([flag, URL]).verbose is True
        assert build_parser().parse_args([URL]).verbose is False


class TestConnectionFailureLogging:
    async def test_unreachable_logs_one_line_without_traceback(self, caplog):
        client = MCPClient()
        with (
            patch("mcpscore.mcp_client.streamable_http_client") as mock_http,
            caplog.at_level(logging.INFO, logger="mcpscore"),
        ):
            mock_http.return_value.__aenter__.side_effect = httpx2.ConnectError("certificate is expired")
            assert await client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, URL) is False

        errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
        assert [r.getMessage() for r in errors] == [f"Server unreachable: {URL} (certificate is expired)"]
        assert all(r.exc_info is None for r in caplog.records)
        assert "Traceback" not in caplog.text

    async def test_traceback_stays_available_at_debug(self, caplog):
        client = MCPClient()
        with (
            patch("mcpscore.mcp_client.streamable_http_client") as mock_http,
            caplog.at_level(logging.DEBUG, logger="mcpscore"),
        ):
            mock_http.return_value.__aenter__.side_effect = httpx2.ConnectError("refused")
            await client.connect_to_server(MCPTransportType.STREAMABLE_HTTP, URL)

        assert any(r.levelno == logging.DEBUG and r.exc_info for r in caplog.records)

    async def test_unclassified_failure_logs_the_cause_without_traceback(self, caplog):
        client = MCPClient()
        with (
            patch("mcpscore.mcp_client.sse_client") as mock_sse,
            caplog.at_level(logging.INFO, logger="mcpscore"),
        ):
            mock_sse.return_value.__aenter__.side_effect = ExceptionGroup("tg", [RuntimeError("bad stream")])
            assert await client.connect_to_server(MCPTransportType.SSE, URL) is False

        assert "SSE connection failed: bad stream" in caplog.text
        assert "Traceback" not in caplog.text


class TestProbeFailureCollapsing:
    async def test_a_shared_cause_is_logged_once_with_a_count(self, caplog):
        def refuse(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("certificate is expired", request=request)

        with caplog.at_level(logging.INFO, logger="mcpscore"):
            async with (
                httpx2.AsyncClient(transport=httpx2.MockTransport(refuse)) as client,
                httpx2.AsyncClient(transport=httpx2.MockTransport(refuse)) as fresh_client,
            ):
                results = await run_all_probes(URL, client=client, fresh_client=fresh_client)

        assert set(results) == set(PROBE_IDS)
        lines = [r.getMessage() for r in caplog.records if "failed against" in r.getMessage()]
        assert len(lines) == 1
        assert re.fullmatch(rf"\d+ probes failed against {re.escape(URL)}: certificate is expired", lines[0])

    async def test_per_probe_lines_stay_available_at_debug(self, caplog):
        def refuse(request: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("refused", request=request)

        with caplog.at_level(logging.DEBUG, logger="mcpscore"):
            async with httpx2.AsyncClient(transport=httpx2.MockTransport(refuse)) as client:
                await run_all_probes(URL, client=client)

        assert any(r.levelno == logging.DEBUG and r.getMessage().startswith("Probe ") for r in caplog.records)

    def test_a_single_failure_names_the_probe(self, caplog):
        failures = _ProbeFailureLog(URL)
        failures.record("probe_origin_validation", ValueError("origin refused"))
        failures.record("probe_unknown_method", ValueError("timed out"))
        failures.record("probe_unknown_version", ValueError("timed out"))
        with caplog.at_level(logging.INFO, logger="mcpscore"):
            failures.flush()

        assert [r.getMessage() for r in caplog.records] == [
            f"Probe probe_origin_validation failed against {URL}: origin refused",
            f"2 probes failed against {URL}: timed out",
        ]
