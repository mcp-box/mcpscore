"""Tests for the CLI side of per-project rule configuration: flags, loading, the gate, the score line."""

import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mcpscore import MCPAuditor, RuleConfig, RuleSeverity
from mcpscore.cli import build_parser, config_qualifier, fail_under_exit_code, load_rule_config, log_audit_outcome
from mcpscore.rules.retired import RETIRED_RULES

KNOWN = "server_icons_present"


def args(*argv: str):
    return build_parser().parse_args(["https://x", *argv])


def report(**overrides) -> dict:
    base = {
        "score": 80,
        "max_score": 85,
        "partial": False,
        "partial_reason": None,
        "summary": {"total": 10, "skipped": 2},
        "spec": {
            "negotiated_version": "2025-11-25",
            "latest_version": "2026-07-28",
            "readiness_target": "2026-07-28",
            "era": "legacy",
        },
        "readiness": {"score": 0, "max_score": 0, "results": [], "skipped": 0, "counted_in_main": False},
    }
    base.update(overrides)
    return base


# --- flags and loading --------------------------------------------------------


def test_flags_parse():
    assert args("--config", "x.toml").config == "x.toml"
    assert args("--no-config").no_config is True
    assert args().config is None
    assert args().no_config is False


def test_no_config_returns_none_even_inside_a_configured_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / "mcpscore.toml").write_text(f'[rules]\n{KNOWN} = "off"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    assert load_rule_config(args("--no-config")) is None


def test_config_and_no_config_together_is_a_usage_error():
    with pytest.raises(ValueError, match="--config and --no-config cannot be combined"):
        load_rule_config(args("--config", "x.toml", "--no-config"))


def test_explicit_config_is_loaded_and_summarised(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    path = tmp_path / "team.toml"
    path.write_text(f'[rules]\n{KNOWN} = "off"\n[gate]\nfail_on = "high"\n', encoding="utf-8")

    with caplog.at_level(logging.INFO, logger="mcpscore.cli"):
        config = load_rule_config(args("--config", str(path)))

    assert config is not None
    assert config.disabled == (KNOWN,)
    assert config.fail_on is RuleSeverity.HIGH
    assert f"Config: {path} — 1 rule off, gate at HIGH" in caplog.text


def test_missing_explicit_config_is_a_usage_error(tmp_path: Path):
    with pytest.raises(ValueError, match="cannot read config file"):
        load_rule_config(args("--config", str(tmp_path / "absent.toml")))


def test_invalid_config_is_a_usage_error(tmp_path: Path):
    path = tmp_path / "mcpscore.toml"
    path.write_text(f'[rules]\n{KNOWN} = "skip"\n', encoding="utf-8")

    with pytest.raises(ValueError, match="expected off, low, medium, high, or critical"):
        load_rule_config(args("--config", str(path)))


def test_discovery_finds_the_nearest_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / "mcpscore.toml").write_text(f'[rules]\n{KNOWN} = "off"\n', encoding="utf-8")
    nested = tmp_path / "src"
    nested.mkdir()
    monkeypatch.chdir(nested)

    config = load_rule_config(args())

    assert config is not None
    assert config.disabled == (KNOWN,)


def test_no_config_anywhere_is_none(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / ".git").mkdir()
    monkeypatch.chdir(tmp_path)

    assert load_rule_config(args()) is None


def test_unknown_and_retired_ids_warn_and_are_ignored(tmp_path: Path, caplog: pytest.LogCaptureFixture):
    retired = RETIRED_RULES[0]
    path = tmp_path / "mcpscore.toml"
    path.write_text(f'[rules]\nnot_a_rule = "off"\n{retired.rule_id} = "low"\n{KNOWN} = "off"\n', encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="mcpscore.cli"):
        config = load_rule_config(args("--config", str(path)))

    assert config is not None
    assert config.overrides == {KNOWN: None}
    assert "Config: unknown rule 'not_a_rule'; ignored" in caplog.text
    assert f"Config: rule '{retired.rule_id}' was retired in mcpscore {retired.version}; ignored" in caplog.text


# --- the gate in the exit-3 path ---------------------------------------------


def test_gate_failures_exit_3_with_the_rules_named(caplog: pytest.LogCaptureFixture):
    gated = report(config={"gate": {"fail_on": "HIGH", "failed": ["a", "b"]}})

    with caplog.at_level(logging.ERROR, logger="mcpscore.cli"):
        code = fail_under_exit_code(args(), gated)

    assert code == 3
    assert 'Gate failed — [gate] fail_on = "high": 2 failed rules at or above HIGH: a, b' in caplog.text


def test_gate_with_nothing_failed_is_clean():
    assert fail_under_exit_code(args(), report(config={"gate": {"fail_on": "HIGH", "failed": []}})) == 0


def test_config_without_a_gate_does_not_gate():
    assert fail_under_exit_code(args(), report(config={"disabled": ["a"]})) == 0


def test_gate_and_fail_under_both_report(caplog: pytest.LogCaptureFixture):
    gated = report(score=10, max_score=100, config={"gate": {"fail_on": "HIGH", "failed": ["a"]}})

    with caplog.at_level(logging.ERROR, logger="mcpscore.cli"):
        code = fail_under_exit_code(args("--fail-under", "50"), gated)

    assert code == 3
    assert "--fail-under 50" in caplog.text
    assert "1 failed rule at or above HIGH: a" in caplog.text


# --- the score line -----------------------------------------------------------


def test_qualifier_is_empty_without_a_config():
    assert config_qualifier(report()) == ""


def test_qualifier_describes_the_config():
    block = {"source": "mcpscore.toml", "disabled": ["a", "b"], "reranked": {"c": {}}, "gate": {"fail_on": "HIGH"}}

    assert config_qualifier(report(config=block)) == " (mcpscore.toml: 2 rules off, 1 re-ranked, gate at HIGH)"
    assert config_qualifier(report(config={"source": "pyproject.toml", "disabled": [], "reranked": {}})) == (
        " (pyproject.toml: no overrides)"
    )


def test_final_score_line_carries_the_qualifier(caplog: pytest.LogCaptureFixture):
    auditor = MagicMock(spec=MCPAuditor)
    auditor.get_audit_report = MagicMock(
        return_value=report(config={"source": "mcpscore.toml", "disabled": ["a"], "reranked": {}})
    )

    with caplog.at_level(logging.INFO, logger="mcpscore.cli"):
        log_audit_outcome(auditor)

    assert "Audit finished. Final score: 80/85 (mcpscore.toml: 1 rule off)" in caplog.text


def test_partial_score_line_carries_the_qualifier(caplog: pytest.LogCaptureFixture):
    auditor = MagicMock(spec=MCPAuditor)
    auditor.get_audit_report = MagicMock(
        return_value=report(
            partial=True,
            partial_reason="gated",
            config={"source": "mcpscore.toml", "disabled": [], "reranked": {"a": {}}},
        )
    )

    with caplog.at_level(logging.INFO, logger="mcpscore.cli"):
        log_audit_outcome(auditor)

    assert "not comparable to a full audit. (mcpscore.toml: 1 re-ranked)" in caplog.text


def test_rule_config_is_exported_for_library_users():
    assert RuleConfig.__name__ == "RuleConfig"


def test_resolve_rule_config_exits_1_on_a_usage_error(caplog: pytest.LogCaptureFixture):
    from mcpscore.cli import resolve_rule_config

    with caplog.at_level(logging.ERROR, logger="mcpscore.cli"), pytest.raises(SystemExit) as exc:
        resolve_rule_config(args("--config", "x.toml", "--no-config"))

    assert exc.value.code == 1
    assert "Usage error: --config and --no-config cannot be combined" in caplog.text


async def test_package_audit_score_line_carries_the_qualifier_and_gates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    """The configuration applies to packaging rules too: same score-line contract, same exit 3."""
    from mcpscore.cli import run_package_audit
    from mcpscore.packages import PackageCoordinate, PackageMetadata, PackageOutcome

    async def fake_fetch(coordinate, client=None):
        # Resolves, versioned, not withdrawn; no repository, license, or description.
        return PackageMetadata(coordinate=coordinate, outcome=PackageOutcome.OK, resolved_version="1.0.0")

    monkeypatch.setattr("mcpscore.mcp_auditor.fetch_package_metadata", fake_fetch)
    config_file = tmp_path / "mcpscore.toml"
    config_file.write_text(
        "[rules]\n"
        'package_description_present = "off"\n'
        'package_license_declared = "critical"\n'
        "[gate]\n"
        'fail_on = "critical"\n',
        encoding="utf-8",
    )
    argv = build_parser().parse_args(["--package", "npm:server", "--config", str(config_file)])
    config = load_rule_config(argv)

    with caplog.at_level(logging.INFO, logger="mcpscore.cli"):
        code = await run_package_audit(argv, PackageCoordinate.parse("npm:server"), config)

    assert code == 3
    # 16 canonical points: -1 for the description rule turned off, +3 for license promoted MEDIUM -> CRITICAL.
    assert f"Final score: 11/18 ({config_file}: 1 rule off, 1 re-ranked, gate at CRITICAL)" in caplog.text
    assert (
        'Gate failed — [gate] fail_on = "critical": 1 failed rule at or above CRITICAL: package_license_declared'
        in caplog.text
    )
