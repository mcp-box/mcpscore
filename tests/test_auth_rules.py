"""Tests for the auth-posture rules (RFC 9728 protected resource metadata)."""

import time

import pytest

from mcpscore.probes import (
    PROBE_AUTH_METADATA,
    PROBE_INVALID_TOKEN,
    PROBE_UNAUTHENTICATED,
    ProbeOutcome,
    ProbeResult,
    www_authenticate_param,
)
from mcpscore.rules import AuditData
from mcpscore.rules.auth import (
    AuthAuthorizationServersHttpsRule,
    AuthChallengeReferencesMetadataRule,
    AuthClientRegistrationAdvertisedRule,
    AuthInvalidTokenRejectedRule,
    AuthMetadataHttpsRule,
    AuthProtectedResourceMetadataRule,
    AuthScopesAdvertisedRule,
    AuthServerMetadataPresentRule,
    AuthServerPkceRule,
    AuthWwwAuthenticateRule,
)
from mcpscore.rules.base import SKIP_REASON_INSUFFICIENT_DATA, SKIP_REASON_NOT_APPLICABLE, RuleSeverity

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
        "auth_server_cimd_supported": True,
        "auth_server_registration_endpoint": True,
    }
    base |= extra
    return _metadata(**base)


def _token(outcome: ProbeOutcome = ProbeOutcome.SUPPORTED, status: int | None = 401) -> ProbeResult:
    return ProbeResult(PROBE_INVALID_TOKEN, outcome, {"http_status": status})


def _data(
    unauth: ProbeResult | None, metadata: ProbeResult | None = None, token: ProbeResult | None = None
) -> AuditData:
    probes = {}
    if unauth is not None:
        probes[PROBE_UNAUTHENTICATED] = unauth
    if metadata is not None:
        probes[PROBE_AUTH_METADATA] = metadata
    probes[PROBE_INVALID_TOKEN] = token or _token()
    return AuditData(url=URL, probes=probes)


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
            AuthClientRegistrationAdvertisedRule,
            AuthInvalidTokenRejectedRule,
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
        assert "No usable RFC 9728" in result.message

    def test_mismatched_resource_fails(self):
        data = _data(_unauth(), _metadata(resource="https://other.example/mcp"))
        result = AuthProtectedResourceMetadataRule().check(data)
        assert result.passed is False
        assert "does not match" in result.message


class TestAuthorizationServersHttps:
    def test_uppercase_scheme_passes(self):
        data = _data(_unauth(), _metadata(servers=["HTTPS://auth.example"]))
        assert AuthAuthorizationServersHttpsRule().check(data).passed is True

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


def _challenged(
    url: str = METADATA_URL, *, status: int | None = 200, resource: str | None = URL, **observed: object
) -> ProbeResult:
    """Build a metadata probe that followed the challenge's resource_metadata URL."""
    probe = _full_metadata()
    probe.details["challenge_metadata_url"] = url
    if status is not None:
        probe.details["challenge_metadata_http_status"] = status
        probe.details["challenge_metadata_resource"] = resource
    probe.details.update(observed)
    return probe


def _versioned(unauth: ProbeResult, metadata: ProbeResult | None, version: str | None) -> AuditData:
    data = _data(unauth, metadata)
    data.protocol_version = version
    return data


class TestChallengeReferencesMetadata:
    def test_passes_when_challenge_url_serves_metadata(self):
        unauth = _unauth(www_authenticate=f'Bearer resource_metadata="{METADATA_URL}"')
        data = _data(unauth, _challenged())
        assert AuthChallengeReferencesMetadataRule().skip_reason(data) is None
        result = AuthChallengeReferencesMetadataRule().check(data)
        assert result.passed is True

    def test_passes_on_cross_origin_url_that_serves_metadata(self):
        """RFC 9728 §5.1 does not require the metadata on the server's origin."""
        elsewhere = "https://metadata.example/prm/mcp"
        unauth = _unauth(www_authenticate=f'Bearer resource_metadata="{elsewhere}"')
        result = AuthChallengeReferencesMetadataRule().check(_data(unauth, _challenged(elsewhere)))
        assert result.passed is True

    def test_fails_when_challenge_url_serves_no_metadata(self):
        unauth = _unauth(www_authenticate=f'Bearer resource_metadata="{METADATA_URL}"')
        result = AuthChallengeReferencesMetadataRule().check(_data(unauth, _challenged(status=404, resource=None)))
        assert result.passed is False
        assert "did not serve RFC 9728 metadata (HTTP 404)" in result.message

    def test_fails_on_url_that_is_not_http(self):
        unauth = _unauth(www_authenticate='Bearer resource_metadata="/.well-known/oauth-protected-resource"')
        data = _data(
            unauth, _challenged("/.well-known/oauth-protected-resource", status=None, challenge_metadata_invalid=True)
        )
        assert AuthChallengeReferencesMetadataRule().skip_reason(data) is None
        result = AuthChallengeReferencesMetadataRule().check(data)
        assert result.passed is False
        assert "not an absolute http(s) URL" in result.message

    def test_fails_on_url_at_a_non_public_address(self):
        internal = "http://169.254.169.254/latest"
        unauth = _unauth(www_authenticate=f'Bearer resource_metadata="{internal}"')
        data = _data(unauth, _challenged(internal, status=None, challenge_metadata_blocked=True))
        assert AuthChallengeReferencesMetadataRule().skip_reason(data) is None
        result = AuthChallengeReferencesMetadataRule().check(data)
        assert result.passed is False
        assert "non-public address" in result.message

    @pytest.mark.parametrize("error", ["ConnectError", "DNSTimeout"])
    def test_skips_when_challenge_url_was_unreachable(self, error: str):
        unauth = _unauth(www_authenticate=f'Bearer resource_metadata="{METADATA_URL}"')
        data = _data(unauth, _challenged(status=None, challenge_metadata_error=error))
        assert AuthChallengeReferencesMetadataRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_skips_when_the_probe_did_not_follow_the_challenge(self):
        unauth = _unauth(www_authenticate=f'Bearer resource_metadata="{METADATA_URL}"')
        assert AuthChallengeReferencesMetadataRule().skip_reason(_data(unauth)) == SKIP_REASON_INSUFFICIENT_DATA
        assert (
            AuthChallengeReferencesMetadataRule().skip_reason(_data(unauth, _full_metadata()))
            == SKIP_REASON_INSUFFICIENT_DATA
        )

    def test_skips_when_no_challenge_header(self):
        data = _data(_unauth(www_authenticate=None))
        assert AuthChallengeReferencesMetadataRule().skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_missing_parameter_is_not_applicable_when_well_known_discovery_is_allowed(self):
        """From 2025-11-25 a server may rely on well-known discovery alone."""
        unauth = _unauth(www_authenticate='Bearer realm="mcp"')
        for version in (None, "2025-11-25", "2026-07-28"):
            data = _versioned(unauth, _full_metadata(), version)
            assert AuthChallengeReferencesMetadataRule().skip_reason(data) == SKIP_REASON_NOT_APPLICABLE

    def test_missing_parameter_fails_on_2025_06_18(self):
        unauth = _unauth(www_authenticate='Bearer realm="mcp"')
        data = _versioned(unauth, _full_metadata(), "2025-06-18")
        assert AuthChallengeReferencesMetadataRule().skip_reason(data) is None
        result = AuthChallengeReferencesMetadataRule().check(data)
        assert result.passed is False
        assert "which 2025-06-18 requires" in result.message

    def test_missing_parameter_on_403_is_not_applicable_on_any_version(self):
        """The resource_metadata requirement is attached to 401 responses only."""
        unauth = _unauth(status=403, www_authenticate='Bearer error="insufficient_scope"')
        data = _versioned(unauth, _full_metadata(), "2025-06-18")
        assert AuthChallengeReferencesMetadataRule().skip_reason(data) == SKIP_REASON_NOT_APPLICABLE

    def test_unquoted_parameter_is_followed(self):
        unauth = _unauth(www_authenticate=f'Bearer resource_metadata={METADATA_URL}, error="invalid_token"')
        result = AuthChallengeReferencesMetadataRule().check(_data(unauth, _challenged()))
        assert result.passed is True
        assert result.details is not None
        assert result.details["resource_metadata"] == METADATA_URL


class TestWwwAuthenticateParam:
    def test_quoted_value(self):
        assert www_authenticate_param(f'Bearer resource_metadata="{METADATA_URL}"', "resource_metadata") == METADATA_URL

    def test_unquoted_value(self):
        """Deployed servers send the URL bare; RFC 7235 §2.1 wants it quoted, clients read both."""
        assert www_authenticate_param(f"Bearer resource_metadata={METADATA_URL}", "resource_metadata") == METADATA_URL

    def test_unquoted_value_stops_at_parameter_separator(self):
        header = f'Bearer resource_metadata={METADATA_URL}, error="invalid_token"'
        assert www_authenticate_param(header, "resource_metadata") == METADATA_URL

    def test_param_name_is_matched_case_insensitively(self):
        assert www_authenticate_param(f'Bearer Resource_Metadata="{METADATA_URL}"', "resource_metadata") == METADATA_URL

    def test_parameter_like_text_inside_a_quoted_value_is_ignored(self):
        header = (
            'Bearer error_description="see resource_metadata=https://meta.example/decoy, retry", '
            'resource_metadata="https://meta.example/real"'
        )
        assert www_authenticate_param(header, "resource_metadata") == "https://meta.example/real"

    @pytest.mark.parametrize(
        "filler",
        ["a" * 200_000, "a=" * 100_000, '"' + "a " * 100_000],
        ids=["long-token", "repeated-pairs", "unterminated-quote"],
    )
    def test_long_server_supplied_header_parses_in_linear_time(self, filler: str):
        """A backtracking parser takes minutes on these; the bounded one takes milliseconds."""
        started = time.perf_counter()
        assert www_authenticate_param(f"Bearer {filler}", "resource_metadata") is None
        assert time.perf_counter() - started < 1.0

    def test_quoted_pairs_are_unescaped(self):
        """RFC 7230 §3.2.6: a backslash quotes the next character inside a quoted-string."""
        assert www_authenticate_param('Bearer realm="a \\"q\\" b"', "realm") == 'a "q" b'

    def test_similarly_named_parameter_is_not_mistaken_for_the_real_one(self):
        assert www_authenticate_param('Bearer xresource_metadata="https://evil.example/x"', "resource_metadata") is None


class TestMetadataHttps:
    def test_uppercase_scheme_passes(self):
        meta = _full_metadata(metadata_url="HTTPS://metadata.example/prm")
        assert AuthMetadataHttpsRule().check(_data(_unauth(), meta)).passed is True

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

    def test_passes_and_reports_issuer_differing_only_by_trailing_slash(self):
        meta = _full_metadata(auth_server_issuer_declared="https://auth.example/")
        result = AuthServerMetadataPresentRule().check(_data(_unauth(), meta))
        assert result.passed is True
        assert "trailing slash" in result.message
        assert result.details["declared_issuer"] == "https://auth.example/"

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


class TestAuthClientRegistrationAdvertised:
    @staticmethod
    def _check(version: str | None = "2025-11-25", **flags: object):
        data = _data(_unauth(), _full_metadata(**flags))
        data.protocol_version = version
        return AuthClientRegistrationAdvertisedRule().check(data)

    def test_passes_with_client_id_metadata_documents(self):
        result = self._check(auth_server_registration_endpoint=False)
        assert result.passed is True
        assert "Client ID Metadata Documents" in result.message

    def test_dynamic_registration_alone_passes_and_points_at_cimd(self):
        result = self._check(auth_server_cimd_supported=False)
        assert result.passed is True
        assert "client_id_metadata_document_supported is the recommended path" in result.message

    def test_dynamic_registration_alone_is_the_recommendation_before_2025_11_25(self):
        result = self._check(version="2025-06-18", auth_server_cimd_supported=False)
        assert result.passed is True
        assert "recommended" not in result.message

    @pytest.mark.parametrize("version", ["2025-06-18", "2025-11-25", None])
    def test_fails_with_neither(self, version: str | None):
        result = self._check(version, auth_server_cimd_supported=False, auth_server_registration_endpoint=False)
        assert result.passed is False
        assert result.severity is RuleSeverity.MEDIUM
        assert "only pre-registered clients" in result.message
        assert result.suggested_fix is not None
        assert "client_id_metadata_document_supported" in result.suggested_fix

    def test_skips_when_no_as_metadata(self):
        meta = _full_metadata(auth_server_metadata_present=False)
        rule = AuthClientRegistrationAdvertisedRule()
        assert rule.skip_reason(_data(_unauth(), meta)) == SKIP_REASON_INSUFFICIENT_DATA

    def test_skips_for_open_servers(self):
        rule = AuthClientRegistrationAdvertisedRule()
        assert rule.skip_reason(_data(_unauth(status=200), _full_metadata())) == SKIP_REASON_NOT_APPLICABLE


class TestInvalidTokenRejected:
    rule = AuthInvalidTokenRejectedRule()

    def test_is_high_security(self):
        assert self.rule.severity is RuleSeverity.HIGH
        assert self.rule.group_name == "security"

    def test_401_passes(self):
        result = self.rule.check(_data(_unauth(), token=_token(status=401)))

        assert result.passed
        assert "HTTP 401" in result.message
        assert result.suggested_fix is None

    @pytest.mark.parametrize("status", [400, 403])
    def test_other_refusal_passes_and_names_401(self, status):
        result = self.rule.check(_data(_unauth(), token=_token(status=status)))

        assert result.passed
        assert f"HTTP {status}" in result.message
        assert "spec asks for HTTP 401" in result.message

    @pytest.mark.parametrize("status", [200, 202])
    def test_accepted_token_fails(self, status):
        token = ProbeResult(
            PROBE_INVALID_TOKEN, ProbeOutcome.UNSUPPORTED, {"http_status": status, "method": "initialize"}
        )
        result = self.rule.check(_data(_unauth(401), token=token))

        assert not result.passed
        assert f"initialize answered HTTP {status}" in result.message
        assert "same request without a token gets HTTP 401" in result.message
        assert result.details is not None
        assert result.details["http_status"] == status
        assert result.details["anonymous_http_status"] == 401
        assert result.suggested_fix is not None
        assert "HTTP 401" in result.suggested_fix

    def test_open_server_is_not_applicable(self):
        not_run = ProbeResult(PROBE_INVALID_TOKEN, ProbeOutcome.NOT_APPLICABLE, {"reason": "not refused"})

        assert self.rule.skip_reason(_data(_unauth(200, None), token=not_run)) == SKIP_REASON_NOT_APPLICABLE

    @pytest.mark.parametrize("outcome", [ProbeOutcome.ERROR, ProbeOutcome.NOT_APPLICABLE])
    def test_unobserved_token_answer_is_insufficient_data(self, outcome):
        data = _data(_unauth(), token=ProbeResult(PROBE_INVALID_TOKEN, outcome, {}))

        assert self.rule.skip_reason(data) == SKIP_REASON_INSUFFICIENT_DATA

    def test_failed_anonymous_request_is_insufficient_data(self):
        errored = ProbeResult(PROBE_UNAUTHENTICATED, ProbeOutcome.ERROR, {"exception": "ConnectError"})

        assert self.rule.skip_reason(_data(errored)) == SKIP_REASON_INSUFFICIENT_DATA

    def test_message_uses_the_initialize_control_status(self):
        details = {"http_status": 200, "method": "initialize", "anonymous_http_status": 403}
        token = ProbeResult(PROBE_INVALID_TOKEN, ProbeOutcome.UNSUPPORTED, details)

        result = self.rule.check(_data(_unauth(401), token=token))

        assert "same request without a token gets HTTP 403" in result.message
