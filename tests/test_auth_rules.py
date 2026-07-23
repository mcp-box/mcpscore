"""Tests for the auth-posture rules (RFC 9728 protected resource metadata)."""

from mcpscore.probes import PROBE_AUTH_METADATA, PROBE_UNAUTHENTICATED, ProbeOutcome, ProbeResult
from mcpscore.rules import AuditData
from mcpscore.rules.auth import (
    AuthAuthorizationServersHttpsRule,
    AuthChallengeReferencesMetadataRule,
    AuthMetadataHttpsRule,
    AuthProtectedResourceMetadataRule,
    AuthScopesAdvertisedRule,
    AuthServerMetadataPresentRule,
    AuthServerPkceRule,
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
    **extra: object,
) -> ProbeResult:
    details: dict = {"urls_tried": [METADATA_URL], "http_status": 200}
    if outcome is ProbeOutcome.SUPPORTED:
        details |= {
            "metadata_url": METADATA_URL,
            "resource": resource,
            "authorization_servers": servers,
        }
        details |= extra
    return ProbeResult(PROBE_AUTH_METADATA, outcome, details)


def _full_metadata(**extra: object) -> ProbeResult:
    """Build a good-posture metadata probe: HTTPS servers, AS metadata, scopes, PKCE."""
    base: dict = {
        "servers": ["https://auth.example"],
        "scopes_supported": ["read", "write"],
        "auth_server_issuer": "https://auth.example",
        "auth_server_metadata_present": True,
        "auth_server_has_endpoints": True,
        "auth_server_pkce_s256": True,
    }
    base |= extra
    return _metadata(**base)


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

    def test_rules_run_for_403_gated_servers(self):
        """A 403 challenge is an access-controlled server too — rules run (matches partial trigger)."""
        for rule_cls in ALL_RULES:
            assert rule_cls().skip_reason(_data(_unauth(status=403), _metadata())) is None

    def test_metadata_rules_skip_without_the_metadata_probe(self):
        data = _data(_unauth())
        assert AuthProtectedResourceMetadataRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA
        assert AuthAuthorizationServersHttpsRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_servers_rule_skips_when_metadata_absent(self):
        """Absent metadata is the metadata rule's finding — no double-counting."""
        data = _data(_unauth(), _metadata(outcome=ProbeOutcome.UNSUPPORTED))
        assert AuthAuthorizationServersHttpsRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA
        assert AuthProtectedResourceMetadataRule().skip_reason(data) is None

    def test_metadata_detail_rules_skip_when_metadata_unsupported(self):
        """The deeper metadata rules have nothing to inspect without the document."""
        data = _data(_unauth(), _metadata(outcome=ProbeOutcome.UNSUPPORTED))
        assert AuthMetadataHttpsRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA
        assert AuthScopesAdvertisedRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_as_metadata_rule_skips_without_an_issuer(self):
        """No authorization server listed → the servers rule's finding, not this one's."""
        data = _data(_unauth(), _full_metadata(auth_server_issuer=None))
        assert AuthServerMetadataPresentRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_pkce_rule_skips_when_as_metadata_unreachable(self):
        """Unreachable RFC 8414 metadata is the presence rule's finding — no double-counting."""
        data = _data(_unauth(), _full_metadata(auth_server_metadata_present=False))
        assert AuthServerPkceRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_deep_as_rules_run_with_full_metadata(self):
        data = _data(_unauth(), _full_metadata())
        assert AuthServerMetadataPresentRule().skip_reason(data) is None
        assert AuthServerPkceRule().skip_reason(data) is None


class TestCitations:
    def test_every_rule_cites_a_specific_section(self):
        """details["basis"] is a per-rule, section-level citation (report contract)."""
        data = _data(_unauth(), _full_metadata())
        for rule_cls in (
            AuthWwwAuthenticateRule,
            AuthProtectedResourceMetadataRule,
            AuthAuthorizationServersHttpsRule,
            AuthChallengeReferencesMetadataRule,
            AuthMetadataHttpsRule,
            AuthScopesAdvertisedRule,
            AuthServerMetadataPresentRule,
            AuthServerPkceRule,
        ):
            details = rule_cls().check(data).details
            assert details is not None
            basis = details["basis"]
            assert "§" in basis, f"{rule_cls.rule_id} basis lacks a section-level citation: {basis!r}"


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


class TestChallengeReferencesMetadata:
    def test_passes_when_challenge_points_at_metadata(self):
        unauth = _unauth(www_authenticate=f'Bearer resource_metadata="{METADATA_URL}"')
        result = AuthChallengeReferencesMetadataRule().check(_data(unauth, _full_metadata()))
        assert result.passed is True

    def test_fails_without_resource_metadata_param(self):
        unauth = _unauth(www_authenticate='Bearer realm="mcp"')
        result = AuthChallengeReferencesMetadataRule().check(_data(unauth, _full_metadata()))
        assert result.passed is False

    def test_fails_on_cross_origin_reference(self):
        unauth = _unauth(www_authenticate='Bearer resource_metadata="https://evil.example/.well-known/x"')
        result = AuthChallengeReferencesMetadataRule().check(_data(unauth, _full_metadata()))
        assert result.passed is False
        assert "not on this server's origin" in result.message

    def test_passes_on_same_origin_different_path(self):
        # Root PRM form in the header while the probe discovered the path-aware
        # form — both valid RFC 9728 locations on the same origin.
        unauth = _unauth(
            www_authenticate='Bearer resource_metadata="https://server.example/.well-known/oauth-protected-resource"'
        )
        result = AuthChallengeReferencesMetadataRule().check(_data(unauth, _full_metadata()))
        assert result.passed is True

    def test_skips_when_no_challenge_header(self):
        # No metadata probe needed: this rule requires only the unauthenticated probe.
        data = _data(_unauth(www_authenticate=None))
        assert AuthChallengeReferencesMetadataRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA


class TestMetadataHttps:
    def test_passes_for_https(self):
        result = AuthMetadataHttpsRule().check(_data(_unauth(), _full_metadata()))
        assert result.passed is True

    def test_fails_for_http_resource(self):
        meta = _full_metadata(resource="http://server.example/mcp")
        result = AuthMetadataHttpsRule().check(_data(_unauth(), meta))
        assert result.passed is False


class TestScopesAdvertised:
    def test_passes_with_scopes(self):
        result = AuthScopesAdvertisedRule().check(_data(_unauth(), _full_metadata()))
        assert result.passed is True

    def test_fails_without_scopes(self):
        result = AuthScopesAdvertisedRule().check(_data(_unauth(), _full_metadata(scopes_supported=None)))
        assert result.passed is False


class TestAuthServerMetadataPresent:
    def test_passes_with_endpoints(self):
        result = AuthServerMetadataPresentRule().check(_data(_unauth(), _full_metadata()))
        assert result.passed is True

    def test_fails_when_absent(self):
        meta = _full_metadata(auth_server_metadata_present=False, auth_server_has_endpoints=False)
        result = AuthServerMetadataPresentRule().check(_data(_unauth(), meta))
        assert result.passed is False

    def test_fails_without_endpoints(self):
        meta = _full_metadata(auth_server_has_endpoints=False)
        result = AuthServerMetadataPresentRule().check(_data(_unauth(), meta))
        assert result.passed is False
        assert "endpoint" in result.message

    def test_skips_when_no_authorization_server(self):
        meta = _full_metadata(servers=[], auth_server_issuer=None)
        assert AuthServerMetadataPresentRule().skip_reason(_data(_unauth(), meta)) == SKIP_REASON_INSUFFICIENT_DATA


class TestAuthServerPkce:
    def test_passes_with_s256(self):
        result = AuthServerPkceRule().check(_data(_unauth(), _full_metadata()))
        assert result.passed is True

    def test_fails_without_s256(self):
        result = AuthServerPkceRule().check(_data(_unauth(), _full_metadata(auth_server_pkce_s256=False)))
        assert result.passed is False

    def test_skips_when_no_as_metadata(self):
        meta = _full_metadata(auth_server_metadata_present=False)
        assert AuthServerPkceRule().skip_reason(_data(_unauth(), meta)) == SKIP_REASON_INSUFFICIENT_DATA
