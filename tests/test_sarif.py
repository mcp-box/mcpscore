"""Tests for the SARIF 2.1.0 export (``mcpscore.sarif``)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator
import pytest

from mcpscore.sarif import (
    DOCS_URL,
    FINGERPRINT_KEY,
    LEVEL_BY_SEVERITY,
    RULES_URL,
    SARIF_SCHEMA,
    SARIF_VERSION,
    build_sarif,
    display_target,
    fingerprint,
    scrub_urls,
    target_identity,
)

# The SARIF 2.1.0 JSON schema as published on schemastore.org (fetched
# 2026-09-09 from https://json.schemastore.org/sarif-2.1.0.json). Vendored so
# the suite stays hermetic; the OASIS text is the normative one and the two
# agree on everything the export uses.
SCHEMA_PATH = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"


def _result(
    rule_id: str,
    severity: str = "MEDIUM",
    *,
    passed: bool = False,
    details: dict[str, Any] | None = None,
) -> dict:
    """One entry of a report's ``results``, as ``RuleResult.to_dict`` writes it."""
    values = {"CRITICAL": 5, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return {
        "rule_id": rule_id,
        "rule_name": rule_id.replace("_", " ").title(),
        "severity": severity,
        "severity_value": values[severity],
        "passed": passed,
        "message": f"{'✅' if passed else '❌'} {rule_id}",
        "details": details,
    }


def _report(**overrides: Any) -> dict:
    """Build a ``--json``-shaped report (``cli.build_report``) with a mix of outcomes."""
    report: dict = {
        "schema_version": 1,
        "mcpscore_version": "1.14.0",
        "generated_at": "2026-09-09T12:00:00+00:00",
        "target": "https://mcp.example.com/mcp",
        "transport": "streamable-http",
        "score": 80,
        "max_score": 100,
        "authenticated": False,
        "partial": False,
        "partial_reason": None,
        "incomplete_listings": [],
        "server_info": {"name": "example", "version": "1.0"},
        "package": None,
        "summary": {},
        "results": [
            _result("transport_streamable_http", "LOW", passed=True),
            _result("auth_metadata_https", "CRITICAL", details={"basis": "MCP Transports §Security"}),
            _result("tools_description_present_in_all", "HIGH"),
            _result("protocol_version_latest", "MEDIUM"),
            _result("server_icons_present", "LOW"),
        ],
        "skipped_rules": [{"rule_id": "x", "rule_name": "X", "reason": "not-applicable", "group_name": "tools"}],
        "spec": {"negotiated_version": "2025-11-25", "latest_version": "2026-07-28", "era": "legacy"},
        "readiness": {
            "score": 0,
            "max_score": 3,
            "counted_in_main": False,
            "results": [_result("readiness_2026_server_discover", "HIGH", details={"sep": "SEP-1442"})],
        },
    }
    report.update(overrides)
    return report


@pytest.fixture(scope="module")
def validator() -> Draft7Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft7Validator.check_schema(schema)
    # `format` is advisory in JSON Schema: without a checker, an invalid
    # `uri-reference` passes. jsonschema registers the URI checkers only when
    # rfc3986-validator (dev dependency) is importable, so pin that too —
    # otherwise the checker is present and silently skips exactly these.
    checker = Draft7Validator.FORMAT_CHECKER
    assert {"uri", "uri-reference"} <= set(checker.checkers)
    return Draft7Validator(schema, format_checker=checker)


def _run(sarif: dict) -> dict:
    assert len(sarif["runs"]) == 1
    return sarif["runs"][0]


class TestEnvelope:
    def test_declares_sarif_2_1_0(self) -> None:
        sarif = build_sarif(_report())
        assert sarif["version"] == SARIF_VERSION == "2.1.0"
        assert sarif["$schema"] == SARIF_SCHEMA

    def test_driver_names_mcpscore_its_version_and_the_docs(self) -> None:
        driver = _run(build_sarif(_report()))["tool"]["driver"]
        assert driver["name"] == "mcpscore"
        assert driver["version"] == "1.14.0"
        assert driver["informationUri"] == DOCS_URL

    def test_run_properties_carry_the_score_and_audit_mode(self) -> None:
        props = _run(build_sarif(_report(partial=True, partial_reason="auth-gated", authenticated=True)))["properties"]
        assert props == {
            "score": 80,
            "max_score": 100,
            "partial": True,
            "partial_reason": "auth-gated",
            "authenticated": True,
            "transport": "streamable-http",
        }

    def test_no_automation_details(self) -> None:
        # upload-sarif assigns a category per workflow and job when the file
        # carries none, and its `category` input keeps two servers in one job
        # apart; a category derived from the target would only fight that.
        assert "automationDetails" not in _run(build_sarif(_report()))

    def test_validates_against_the_sarif_schema(self, validator: Draft7Validator) -> None:
        errors = list(validator.iter_errors(build_sarif(_report())))
        assert errors == [], [e.message for e in errors]

    def test_json_serializable(self) -> None:
        json.dumps(build_sarif(_report()))


class TestResults:
    def test_only_failed_rules_are_results(self) -> None:
        results = _run(build_sarif(_report()))["results"]
        ids = [r["ruleId"] for r in results]
        assert "transport_streamable_http" not in ids  # passed
        assert "x" not in ids  # skipped
        assert ids == [
            "auth_metadata_https",
            "tools_description_present_in_all",
            "protocol_version_latest",
            "server_icons_present",
            "readiness_2026_server_discover",
        ]

    def test_no_findings_is_an_empty_results_array(
        self, validator: Draft7Validator, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A clean run has no rule to describe, so the registry is not consulted at all.
        def no_registry() -> list:
            raise AssertionError("catalog built for a run without findings")

        monkeypatch.setattr("mcpscore.sarif.create_all_rules", no_registry)
        sarif = build_sarif(_report(results=[_result("a", passed=True)], readiness={"results": []}))
        assert _run(sarif)["results"] == []
        assert _run(sarif)["tool"]["driver"]["rules"] == []
        assert list(validator.iter_errors(sarif)) == []

    @pytest.mark.parametrize(
        ("severity", "level"),
        [("CRITICAL", "error"), ("HIGH", "error"), ("MEDIUM", "warning"), ("LOW", "note")],
    )
    def test_level_follows_severity(self, severity: str, level: str) -> None:
        assert LEVEL_BY_SEVERITY[severity] == level
        sarif = build_sarif(_report(results=[_result("r", severity)], readiness={"results": []}))
        (result,) = _run(sarif)["results"]
        assert result["level"] == level
        assert result["properties"]["severity"] == severity
        assert result["properties"]["counted_in_score"] is True

    def test_unknown_severity_name_is_a_warning(self) -> None:
        odd = {**_result("r"), "severity": "WEIRD"}
        sarif = build_sarif(_report(results=[odd], readiness={"results": []}))
        assert _run(sarif)["results"][0]["level"] == "warning"

    def test_readiness_not_counted_in_score_is_a_note_whatever_its_severity(self) -> None:
        (result,) = [r for r in _run(build_sarif(_report()))["results"] if r["properties"]["readiness"]]
        assert result["properties"]["severity"] == "HIGH"
        assert result["level"] == "note"
        assert result["properties"]["counted_in_score"] is False

    def test_readiness_counted_in_score_keeps_its_severity_level(self) -> None:
        report = _report()
        report["readiness"]["counted_in_main"] = True
        (result,) = [r for r in _run(build_sarif(report))["results"] if r["properties"]["readiness"]]
        assert result["level"] == "error"
        assert result["properties"]["counted_in_score"] is True

    def test_message_comes_from_the_rule_result_and_details_stay_out(self) -> None:
        # Transport and security rules record the audited URL in `details`,
        # credentials included; the upload is readable by everyone with
        # access to the repository's alerts, so details stay in --json.
        result = _run(build_sarif(_report()))["results"][0]
        assert result["message"]["text"] == "❌ auth_metadata_https"
        assert "details" not in result["properties"]

    def test_location_is_a_repository_relative_path_for_the_target(self) -> None:
        run = _run(build_sarif(_report()))
        location = run["results"][0]["locations"][0]["physicalLocation"]
        assert location["artifactLocation"] == {"uri": "mcp.example.com/mcp", "index": 0}
        # GitHub requires all four region fields (its SARIF support tables).
        assert location["region"] == {"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 1}
        assert run["artifacts"][0] == {
            "location": {"uri": "mcp.example.com/mcp"},
            "description": {"text": "https://mcp.example.com/mcp"},
        }

    @pytest.mark.parametrize(
        ("target", "uri"),
        [
            ("https://mcp.example.com/mcp?x=1", "mcp.example.com/mcp"),
            ("https://user:secret@mcp.example.com/mcp?sig=abc", "mcp.example.com/mcp"),
            ("https://mcp.example.com:8443/mcp/", "mcp.example.com%3A8443/mcp"),
            ("https://[::1]:8000/mcp", "%5B%3A%3A1%5D%3A8000/mcp"),
            ("http://localhost:8000/mcp#frag", "localhost%3A8000/mcp"),
            ("/srv/server.py", "srv/server.py"),
            ("./server.py", "server.py"),
            ("../server.py", "server.py"),
            ("../../etc/../server.py", "etc/server.py"),
            ("C:\\srv\\server.py", "srv/server.py"),
            ("/srv/my server.py", "srv/my%20server.py"),
            ("npm:@scope/name@1.2.3", "npm/@scope/name@1.2.3"),
            ("pypi:name==1.2.3", "pypi/name==1.2.3"),
        ],
    )
    def test_every_target_becomes_a_relative_path_without_a_scheme(
        self, target: str, uri: str, validator: Draft7Validator
    ) -> None:
        # upload-sarif hands GitHub a file:// checkout root, and GitHub rejects
        # an upload whose absolute location URIs use another scheme — so no
        # location may start with a slash, parse as `scheme:`, or leave the checkout.
        sarif = build_sarif(_report(target=target))
        location = _run(sarif)["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        assert location["uri"] == uri
        assert not uri.startswith("/")
        assert ":" not in uri.split("/")[0]
        assert ".." not in uri.split("/")
        assert list(validator.iter_errors(sarif)) == []

    def test_rule_index_points_at_the_rule_entry(self) -> None:
        run = _run(build_sarif(_report()))
        for result in run["results"]:
            assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]

    def test_a_rule_reported_twice_has_one_entry_and_two_results(self, validator: Draft7Validator) -> None:
        # SARIF rule ids are unique within the catalog; two findings for one
        # rule (a report that repeats a rule) both point at the same entry.
        sarif = build_sarif(_report(results=[_result("r", "LOW"), _result("r", "LOW")], readiness={"results": []}))
        run = _run(sarif)
        assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == ["r"]
        assert [result["ruleIndex"] for result in run["results"]] == [0, 0]
        assert list(validator.iter_errors(sarif)) == []

    def test_package_and_partial_reason_strings_are_scrubbed(self, validator: Draft7Validator) -> None:
        sarif = build_sarif(
            _report(
                target="npm:example",
                transport=None,
                partial=True,
                partial_reason="gated at https://user:pw@a.example/x?sig=1",
                package={"registry": "npm", "repository_url": "https://token@github.com/o/r?x=1", "withdrawn": False},
                results=[_result("package_repository_declared", "MEDIUM")],
                readiness={"results": []},
            )
        )
        run = _run(sarif)
        assert run["properties"]["partial_reason"] == "gated at https://a.example/x"
        assert run["properties"]["package"] == {
            "registry": "npm",
            "repository_url": "https://github.com/o/r",
            "withdrawn": False,
        }
        assert "transport" not in run["properties"]
        assert run["tool"]["driver"]["rules"][0]["helpUri"] == f"{RULES_URL}#packaging-rules"
        assert list(validator.iter_errors(sarif)) == []

    def test_incomplete_listings_are_declared_on_the_run(self) -> None:
        props = _run(build_sarif(_report(incomplete_listings=["tools", "prompts"])))["properties"]
        assert props["incomplete_listings"] == ["prompts", "tools"]
        assert "incomplete_listings" not in _run(build_sarif(_report()))["properties"]


class TestWhatTheFileShows:
    """The whole rule: a URL's scheme/host/port/path, a command's program name, a path, a coordinate."""

    @pytest.mark.parametrize(
        ("target", "shown"),
        [
            ("https://mcp.example.com/mcp", "https://mcp.example.com/mcp"),
            ("https://user:secret@mcp.example.com:8443/mcp?sig=abc123#frag", "https://mcp.example.com:8443/mcp"),
            ("https://issuer.example:not-a-port/realm", "<invalid-url>"),
            ("./server.py", "./server.py"),
            ("/srv/my server.py", "/srv/my server.py"),  # a path is a path, whitespace or not
            ("npm:@scope/name@1.2.3", "npm:@scope/name@1.2.3"),
        ],
    )
    def test_display_target(self, target: str, shown: str) -> None:
        assert display_target(target) == shown

    @pytest.mark.parametrize(
        ("command_line", "shown"),
        [
            ("python server.py --api-key hunter2", "python"),
            ("/usr/bin/python3.12 -m my_server --token t", "python3.12"),
            ("npx -y @modelcontextprotocol/server-everything", "npx"),
            ("node server.js hunter2", "node"),
            ("server -khunter2", "server"),
            ("'/opt/my server/bin/server' --root /tmp/a", "server"),
            ("server", "server"),
        ],
    )
    def test_display_of_a_stdio_command_is_its_program_name(self, command_line: str, shown: str) -> None:
        # The CLI says whether the target is a command; the string alone cannot.
        assert display_target(command_line, command=True) == shown

    def test_credentials_in_the_target_never_reach_the_file(self) -> None:
        target = "https://user:secret@mcp.example.com:8443/mcp?sig=abc123#frag"
        text = json.dumps(build_sarif(_report(target=target)))
        assert "secret" not in text
        assert "abc123" not in text
        assert "user:" not in text
        assert "user@" not in text

    def test_command_arguments_never_reach_the_file(self) -> None:
        command = "npx --token hunter2 @scope/server --root /tmp/hunter2"
        text = json.dumps(build_sarif(_report(target=command), command=True))
        assert "hunter2" not in text
        assert "@scope/server" not in text
        run = _run(build_sarif(_report(target=command), command=True))
        assert run["artifacts"][0] == {"location": {"uri": "npx"}, "description": {"text": "npx"}}
        assert run["results"][0]["partialFingerprints"] == {FINGERPRINT_KEY: fingerprint("auth_metadata_https", "npx")}

    def test_a_url_that_cannot_be_parsed_never_raises(self) -> None:
        # Auth metadata is server-supplied text; a port that is not a number
        # makes urlsplit raise, and the file must still be written.
        bad = "https://issuer.example:not-a-port/realm"
        odd = {**_result("r"), "message": f"issuer {bad}"}
        sarif = build_sarif(_report(target=bad, results=[odd], readiness={"results": []}))
        assert _run(sarif)["results"][0]["message"]["text"] == "issuer <invalid-url>"

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            (
                (
                    "❌ The challenge's resource_metadata 'https://user:pw@as.example/.well-known/x?sig=abc123#f' "
                    "is not on this server's origin (issuer https://idp.example:8443/realm/, target unchanged)"
                ),
                (
                    "❌ The challenge's resource_metadata 'https://as.example/.well-known/x "
                    "is not on this server's origin (issuer https://idp.example:8443/realm/, target unchanged)"
                ),
            ),
            # A credential with a comma or quote must not survive as a suffix.
            (
                "metadata 'https://as.example/x?token=prefix,secret' rejected",
                # The closing quote goes too: after a query nothing is known to be prose.
                "metadata 'https://as.example/x rejected",
            ),
            ("see https://as.example/x?sig=a'b), then", "see https://as.example/x then"),
            # Closing punctuation after a plain URL stays where it was...
            ("(see https://as.example/path).", "(see https://as.example/path)."),
            # ...but never after a query or fragment: it may be the value itself.
            ("token 'https://a.example/x?token=....' rejected", "token 'https://a.example/x rejected"),
            ("see https://a.example/x#f).", "see https://a.example/x"),
            ("no url here", "no url here"),
        ],
    )
    def test_urls_quoted_in_messages_are_scrubbed(self, text: str, expected: str) -> None:
        assert scrub_urls(text) == expected

    def test_scrubbed_message_lands_in_the_result(self) -> None:
        message = "❌ resource_metadata 'https://user:pw@as.example/x?sig=abc123' is not on this origin"
        odd = {**_result("r"), "message": message}
        text = json.dumps(build_sarif(_report(results=[odd], readiness={"results": []})))
        assert "abc123" not in text
        assert "user:pw" not in text
        assert "https://as.example/x" in text


class TestFingerprints:
    def test_sits_under_the_key_github_reads(self) -> None:
        # GitHub matches alerts on partialFingerprints.primaryLocationLineHash
        # and ignores every other key; upload-sarif keeps a present value.
        assert FINGERPRINT_KEY == "primaryLocationLineHash"
        first = _run(build_sarif(_report()))["results"][0]["partialFingerprints"]
        second = _run(build_sarif(_report(generated_at="2026-09-10T00:00:00+00:00", score=1)))["results"][0][
            "partialFingerprints"
        ]
        assert first == second == {FINGERPRINT_KEY: fingerprint("auth_metadata_https", "https://mcp.example.com/mcp")}

    def test_scheme_is_pinned(self) -> None:
        # Alert de-duplication on GitHub depends on this value never changing
        # for a given rule and target.
        value = fingerprint("r", "t")
        assert len(value) == 32
        int(value, 16)
        assert value == "8e43bffb54fa994ba087a08caabc039f"

    @pytest.mark.parametrize(
        ("left", "right", "same"),
        [
            # One trailing slash is the same server (the engine follows that redirect); two is another path.
            ("https://a.example/mcp/", "https://a.example/mcp", True),
            ("https://a.example/mcp//", "https://a.example/mcp", False),
            ("https://a.example/mcp//", "https://a.example/mcp/", False),
            # Userinfo, query and fragment never enter the identity.
            ("https://user:secret@a.example/mcp", "https://a.example/mcp", True),
            ("https://a.example/mcp?token=a", "https://a.example/mcp?token=b", True),
            ("https://a.example/mcp#a", "https://a.example/mcp#b", True),
            # A path's whitespace is part of it.
            ("/srv/my server.py", "/srv/my server.py", True),
            ("/srv/my server.py", "/srv/my", False),
            # Different servers stay different.
            ("https://a.example/mcp", "https://b.example/mcp", False),
            ("https://a.example/mcp", "https://a.example/other", False),
            ("https://a.example:8443/mcp", "https://a.example/mcp", False),
        ],
    )
    def test_identity(self, left: str, right: str, same: bool) -> None:
        shown_left, shown_right = display_target(left), display_target(right)
        assert (target_identity(shown_left) == target_identity(shown_right)) is same
        assert (fingerprint("r", shown_left) == fingerprint("r", shown_right)) is same

    def test_a_command_is_keyed_on_its_program_name(self) -> None:
        # Arguments never enter the identity; the upload step's `category:` tells servers apart.
        def key(command_line: str) -> str:
            return fingerprint("r", display_target(command_line, command=True))

        assert key("npx -y @a/server") == key("npx -y @b/server")
        assert key("server --root /tmp/a") == key("server --root /tmp/b")
        assert key("npx -y @a/server") != key("uvx a-server")

    def test_rule_changes_the_fingerprint(self) -> None:
        assert fingerprint("a", "https://a.example/mcp") != fingerprint("b", "https://a.example/mcp")


class TestRuleCatalog:
    def test_one_entry_per_failed_rule_in_order(self) -> None:
        rules = _run(build_sarif(_report()))["tool"]["driver"]["rules"]
        assert [r["id"] for r in rules] == [
            "auth_metadata_https",
            "tools_description_present_in_all",
            "protocol_version_latest",
            "server_icons_present",
            "readiness_2026_server_discover",
        ]

    def test_entry_carries_name_description_help_and_default_level(self) -> None:
        rule = _run(build_sarif(_report()))["tool"]["driver"]["rules"][0]
        assert rule["name"] == "AuthMetadataHttps"
        assert rule["shortDescription"] == {"text": "Auth Metadata Https"}
        assert rule["fullDescription"] == {"text": "Auth Metadata Https. Basis: MCP Transports §Security"}
        assert rule["helpUri"] == f"{RULES_URL}#security"
        assert rule["defaultConfiguration"] == {"level": "error"}

    def test_every_rule_carries_the_descriptions_github_requires(self) -> None:
        # shortDescription.text, fullDescription.text and help.text are
        # required by GitHub even though the SARIF schema makes them optional;
        # a rule without a basis (readiness rules cite SEPs instead) still has all three.
        rules = {r["id"]: r for r in _run(build_sarif(_report()))["tool"]["driver"]["rules"]}
        for rule in rules.values():
            assert rule["shortDescription"]["text"]
            assert rule["fullDescription"]["text"]
            assert rule["help"]["text"]
        assert rules["readiness_2026_server_discover"]["fullDescription"] == {"text": "Readiness 2026 Server Discover"}

    def test_security_rules_carry_github_security_severity(self) -> None:
        rules = {r["id"]: r for r in _run(build_sarif(_report()))["tool"]["driver"]["rules"]}
        security = rules["auth_metadata_https"]["properties"]
        assert security["tags"] == ["security"]
        assert security["security-severity"] == "9.0"
        assert "security-severity" not in rules["tools_description_present_in_all"]["properties"]

    def test_group_from_the_registry_when_the_result_has_none(self) -> None:
        rules = {r["id"]: r for r in _run(build_sarif(_report()))["tool"]["driver"]["rules"]}
        assert rules["tools_description_present_in_all"]["properties"]["category"] == "tools"
        assert rules["tools_description_present_in_all"]["helpUri"] == f"{RULES_URL}#tools"
        assert rules["readiness_2026_server_discover"]["helpUri"] == f"{RULES_URL}#readiness-rules"

    def test_basis_falls_back_to_the_registered_rule(self) -> None:
        # protocol_version_latest declares a basis on the rule class; the result here has no details.
        rules = {r["id"]: r for r in _run(build_sarif(_report()))["tool"]["driver"]["rules"]}
        assert "Basis:" in rules["protocol_version_latest"]["fullDescription"]["text"]

    def test_unregistered_rule_still_gets_an_entry(self) -> None:
        sarif = build_sarif(_report(results=[_result("custom_rule_from_elsewhere", "LOW")], readiness={"results": []}))
        (rule,) = _run(sarif)["tool"]["driver"]["rules"]
        assert rule["id"] == "custom_rule_from_elsewhere"
        assert rule["properties"]["category"] == "default"
        assert rule["fullDescription"] == {"text": "Custom Rule From Elsewhere"}
