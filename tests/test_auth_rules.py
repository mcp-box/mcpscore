"""Tests for the auth-posture rules (RFC 9728 protected resource metadata)."""

from mcpscore.probes import PROBE_AUTH_METADATA, PROBE_UNAUTHENTICATED, ProbeOutcome, ProbeResult
from mcpscore.rules import AuditData
from mcpscore.rules.auth import (
    AuthAuthorizationServersHttpsRule,
    AuthProtectedResourceMetadataRule,
    AuthWwwAuthenticateRule,
)
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE

URL = "https://server.example/mcp"
METADATA_URL = "https://server.example/.well-known/oauth-protected-resource/mcp"

ALL_RULES = (AuthWwwAuthenticateRule, AuthProtectedResourceMetadataRule, AuthAuthorizationServersHttpsRule)


def _unauth(status: int = 401, www_authenticate: str | None = 'Bearer resource_metadata="..."') -> ProbeResult:
    return ProbeResult(
        PROBE_UNAUTHENTICATED,
        ProbeOutcome.SUPPORTED,
        {"http_status": status, "www_authenticate": www_authenticate},
    )


def _metadata(
    outcome: ProbeOutcome = ProbeOutcome.SUPPORTED,
    resource: str = URL,
    servers: list | None = None,
) -> ProbeResult:
    details = {"urls_tried": [METADATA_URL], "http_status": 200}
    if outcome is ProbeOutcome.SUPPORTED:
        details |= {
            "metadata_url": METADATA_URL,
            "resource": resource,
            "authorization_servers": servers,
        }
    return ProbeResult(PROBE_AUTH_METADATA, outcome, details)


def _data(unauth: ProbeResult | None, metadata: ProbeResult | None = None) -> AuditData:
    probes = {}
    if unauth is not None:
        probes[PROBE_UNAUTHENTICATED] = unauth
    if metadata is not None:
        probes[PROBE_AUTH_METADATA] = metadata
    return AuditData(url=URL, probes=probes or None)


class TestSkipGating:
    def test_all_rules_skip_without_probes(self):
        for rule_cls in ALL_RULES:
            assert rule_cls().skip_reason(AuditData()) == SKIP_REASON_INSUFFICIENT_DATA

    def test_all_rules_skip_when_probe_errored(self):
        errored = ProbeResult(PROBE_UNAUTHENTICATED, ProbeOutcome.ERROR, {"exception": "ConnectError"})
        for rule_cls in ALL_RULES:
            assert rule_cls().skip_reason(_data(errored, _metadata())) == SKIP_REASON_INSUFFICIENT_DATA

    def test_all_rules_skip_for_open_servers(self):
        """A server serving anonymous requests (HTTP 200) has no auth posture to grade."""
        for rule_cls in ALL_RULES:
            assert rule_cls().skip_reason(_data(_unauth(status=200), _metadata())) == SKIP_REASON_NOT_APPLICABLE

    def test_rules_run_for_auth_gated_servers(self):
        for rule_cls in ALL_RULES:
            assert rule_cls().skip_reason(_data(_unauth(), _metadata())) is None

    def test_metadata_rules_skip_without_the_metadata_probe(self):
        data = _data(_unauth())
        assert AuthProtectedResourceMetadataRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA
        assert AuthAuthorizationServersHttpsRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_servers_rule_skips_when_metadata_absent(self):
        """Absent metadata is the metadata rule's finding — no double-counting."""
        data = _data(_unauth(), _metadata(outcome=ProbeOutcome.UNSUPPORTED))
        assert AuthAuthorizationServersHttpsRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA
        assert AuthProtectedResourceMetadataRule().skip_reason(data) is None


class TestWwwAuthenticate:
    def test_challenge_present_passes(self):
        result = AuthWwwAuthenticateRule().check(_data(_unauth()))
        assert result.passed is True
        assert "WWW-Authenticate" in result.message

    def test_missing_challenge_fails(self):
        result = AuthWwwAuthenticateRule().check(_data(_unauth(www_authenticate=None)))
        assert result.passed is False

    def test_blank_challenge_fails(self):
        result = AuthWwwAuthenticateRule().check(_data(_unauth(www_authenticate="  ")))
        assert result.passed is False


class TestProtectedResourceMetadata:
    def test_matching_metadata_passes(self):
        result = AuthProtectedResourceMetadataRule().check(_data(_unauth(), _metadata()))
        assert result.passed is True
        assert result.details is not None
        assert result.details["resource_matches"] is True

    def test_trailing_slash_difference_still_matches(self):
        result = AuthProtectedResourceMetadataRule().check(_data(_unauth(), _metadata(resource=URL + "/")))
        assert result.passed is True

    def test_absent_metadata_fails(self):
        data = _data(_unauth(), _metadata(outcome=ProbeOutcome.UNSUPPORTED))
        result = AuthProtectedResourceMetadataRule().check(data)
        assert result.passed is False
        assert "No RFC 9728" in result.message

    def test_mismatched_resource_fails(self):
        data = _data(_unauth(), _metadata(resource="https://other.example/mcp"))
        result = AuthProtectedResourceMetadataRule().check(data)
        assert result.passed is False
        assert "does not match" in result.message


class TestAuthorizationServersHttps:
    def test_all_https_passes(self):
        data = _data(_unauth(), _metadata(servers=["https://auth.example", "https://sso.example"]))
        result = AuthAuthorizationServersHttpsRule().check(data)
        assert result.passed is True

    def test_empty_list_fails(self):
        result = AuthAuthorizationServersHttpsRule().check(_data(_unauth(), _metadata(servers=[])))
        assert result.passed is False
        assert "no authorization servers" in result.message

    def test_plain_http_entry_fails(self):
        data = _data(_unauth(), _metadata(servers=["https://auth.example", "http://insecure.example"]))
        result = AuthAuthorizationServersHttpsRule().check(data)
        assert result.passed is False
        assert result.details is not None
        assert result.details["invalid"] == ["http://insecure.example"]

    def test_non_string_entries_fail(self):
        """A non-empty list with no valid HTTPS strings must not pass (regression: it did)."""
        data = _data(_unauth(), _metadata(servers=[None, 123]))
        result = AuthAuthorizationServersHttpsRule().check(data)
        assert result.passed is False
        assert result.details is not None
        assert result.details["invalid"] == [None, 123]
