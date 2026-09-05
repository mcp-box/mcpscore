"""Tests for the per-project rule configuration (mcpscore.toml / [tool.mcpscore])."""

import hashlib
from pathlib import Path

import pytest

from mcpscore import ConfigError, RuleConfig, RuleSeverity
from mcpscore.config import CONFIG_FILENAME, PYPROJECT_FILENAME, SKIP_REASON_DISABLED_BY_CONFIG
from mcpscore.rules.registry import all_rule_ids
from mcpscore.rules.retired import RETIRED_RULES

KNOWN_A = "server_icons_present"
KNOWN_B = "tools_title_present_in_all"
KNOWN_C = "readiness_2026_no_get_stream"


def parse(text: str) -> RuleConfig:
    return RuleConfig.parse(text, source="mcpscore.toml")


# --- registry accessor --------------------------------------------------------


def test_all_rule_ids_is_the_registry_view():
    ids = all_rule_ids()

    assert KNOWN_A in ids
    assert KNOWN_B in ids
    assert len(ids) == len(set(ids))
    assert not (set(ids) & {r.rule_id for r in RETIRED_RULES})  # retired ids are never re-registered


# --- values -------------------------------------------------------------------


def test_off_turns_a_rule_off_and_severities_rerank():
    config = parse(f'[rules]\n{KNOWN_A} = "off"\n{KNOWN_B} = "critical"\n{KNOWN_C} = "low"\n')

    assert config.disabled == (KNOWN_A,)
    assert config.reranked == {KNOWN_B: RuleSeverity.CRITICAL, KNOWN_C: RuleSeverity.LOW}
    assert config.overrides[KNOWN_A] is None
    assert config.fail_on is None
    assert config.unknown == ()


@pytest.mark.parametrize("value", ["OFF", "Off", "off"])
def test_off_is_case_insensitive(value: str):
    assert parse(f'[rules]\n{KNOWN_A} = "{value}"\n').disabled == (KNOWN_A,)


@pytest.mark.parametrize(
    ("value", "severity"),
    [
        ("low", RuleSeverity.LOW),
        ("Medium", RuleSeverity.MEDIUM),
        ("HIGH", RuleSeverity.HIGH),
        ("critical", RuleSeverity.CRITICAL),
    ],
)
def test_severity_names_are_case_insensitive(value: str, severity: RuleSeverity):
    assert parse(f'[rules]\n{KNOWN_A} = "{value}"\n').reranked == {KNOWN_A: severity}


@pytest.mark.parametrize("value", ['"skip"', '"disabled"', '"5"', "5", "true", '"critical "'])
def test_invalid_rule_value_is_a_config_error_naming_the_rule_and_the_choices(value: str):
    with pytest.raises(
        ConfigError, match=rf"mcpscore.toml: rule '{KNOWN_A}' has value .*expected off, low, medium, high, or critical"
    ):
        parse(f"[rules]\n{KNOWN_A} = {value}\n")


def test_unknown_rule_ids_are_collected_not_fatal():
    config = parse(f'[rules]\nnot_a_rule = "off"\n{KNOWN_A} = "high"\nanother_typo = "low"\n')

    assert config.unknown == ("not_a_rule", "another_typo")
    assert config.retired == ()
    assert config.overrides == {KNOWN_A: RuleSeverity.HIGH}


def test_retired_rule_ids_are_unknown_and_explained():
    retired = RETIRED_RULES[0]

    config = parse(f'[rules]\n{retired.rule_id} = "off"\n')

    assert config.unknown == (retired.rule_id,)
    assert config.retired == ((retired.rule_id, retired.version),)


def test_invalid_toml_is_a_config_error():
    with pytest.raises(ConfigError, match=r"mcpscore\.toml: not valid TOML"):
        parse("[rules\n")


def test_unexpected_tables_are_a_config_error():
    # A typo'd table name would otherwise silently do nothing.
    with pytest.raises(ConfigError, match=r"unexpected table\(s\) rule; expected \[rules\] and \[gate\]"):
        parse(f'[rule]\n{KNOWN_A} = "off"\n')


def test_rules_must_be_a_table():
    with pytest.raises(ConfigError, match=r"\[rules\] must be a table"):
        parse('rules = "off"\n')


# --- gate ---------------------------------------------------------------------


@pytest.mark.parametrize(("value", "severity"), [("high", RuleSeverity.HIGH), ("CRITICAL", RuleSeverity.CRITICAL)])
def test_gate_fail_on_parses_a_severity(value: str, severity: RuleSeverity):
    assert parse(f'[gate]\nfail_on = "{value}"\n').fail_on is severity


@pytest.mark.parametrize("value", ['"off"', '"severe"', "3"])
def test_gate_fail_on_rejects_non_severities(value: str):
    with pytest.raises(ConfigError, match=r"\[gate\] fail_on has value .*expected low, medium, high, or critical"):
        parse(f"[gate]\nfail_on = {value}\n")


def test_gate_rejects_unknown_keys():
    with pytest.raises(ConfigError, match=r"\[gate\] has unexpected key\(s\) fail_under; expected fail_on"):
        parse('[gate]\nfail_under = "high"\n')


def test_gate_must_be_a_table():
    with pytest.raises(ConfigError, match=r"\[gate\] must be a table"):
        parse('gate = "high"\n')


# --- summary and identity -----------------------------------------------------


def test_summary_counts_what_changed():
    assert parse(f'[rules]\n{KNOWN_A} = "off"\n').summary() == "1 rule off"
    assert (
        parse(f'[rules]\n{KNOWN_A} = "off"\n{KNOWN_B} = "off"\n{KNOWN_C} = "low"\n').summary()
        == "2 rules off, 1 re-ranked"
    )
    assert parse(f'[rules]\n{KNOWN_C} = "low"\n[gate]\nfail_on = "high"\n').summary() == "1 re-ranked, gate at HIGH"
    assert parse("").summary() == "no overrides"


def test_sha256_is_of_the_file_bytes():
    text = f'[rules]\n{KNOWN_A} = "off"\n'

    assert parse(text).sha256 == hashlib.sha256(text.encode()).hexdigest()
    assert parse(text + "\n").sha256 != parse(text).sha256  # any byte change is a new identity


def test_disabled_by_config_skip_reason_is_stable_text():
    assert SKIP_REASON_DISABLED_BY_CONFIG == "disabled-by-config"


# --- pyproject.toml -----------------------------------------------------------


def test_pyproject_tool_table_is_read():
    text = (
        f'[project]\nname = "x"\n\n[tool.mcpscore.rules]\n{KNOWN_A} = "off"\n\n[tool.mcpscore.gate]\nfail_on = "high"\n'
    )

    config = RuleConfig.parse_pyproject(text, source="pyproject.toml")

    assert config is not None
    assert config.disabled == (KNOWN_A,)
    assert config.fail_on is RuleSeverity.HIGH
    assert config.source == "pyproject.toml"


def test_pyproject_without_the_table_is_none():
    assert RuleConfig.parse_pyproject('[project]\nname = "x"\n', source="pyproject.toml") is None
    assert RuleConfig.parse_pyproject("[tool.ruff]\nline-length = 120\n", source="pyproject.toml") is None


def test_pyproject_table_must_be_a_table():
    with pytest.raises(ConfigError, match=r"\[tool.mcpscore\] must be a table"):
        RuleConfig.parse_pyproject('[tool]\nmcpscore = "off"\n', source="pyproject.toml")


# --- load ---------------------------------------------------------------------


def test_load_reads_a_config_file(tmp_path: Path):
    path = tmp_path / CONFIG_FILENAME
    path.write_text(f'[rules]\n{KNOWN_A} = "off"\n', encoding="utf-8")

    config = RuleConfig.load(path)

    assert config.disabled == (KNOWN_A,)
    assert config.source == str(path)
    assert config.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()


def test_load_missing_file_is_a_config_error(tmp_path: Path):
    with pytest.raises(ConfigError, match="cannot read config file"):
        RuleConfig.load(tmp_path / "absent.toml")


def test_load_pyproject_dispatches_to_the_tool_table(tmp_path: Path):
    path = tmp_path / PYPROJECT_FILENAME
    path.write_text(f'[tool.mcpscore.rules]\n{KNOWN_A} = "off"\n', encoding="utf-8")

    assert RuleConfig.load(path).disabled == (KNOWN_A,)


def test_load_pyproject_without_the_table_is_a_config_error(tmp_path: Path):
    path = tmp_path / PYPROJECT_FILENAME
    path.write_text('[project]\nname = "x"\n', encoding="utf-8")

    with pytest.raises(ConfigError, match=r"no \[tool.mcpscore\] table"):
        RuleConfig.load(path)


# --- discovery ----------------------------------------------------------------


def test_discover_returns_none_when_nothing_is_configured(tmp_path: Path):
    (tmp_path / ".git").mkdir()

    assert RuleConfig.discover(tmp_path) is None


def test_discover_prefers_mcpscore_toml_over_pyproject_in_the_same_directory(tmp_path: Path):
    (tmp_path / CONFIG_FILENAME).write_text(f'[rules]\n{KNOWN_A} = "off"\n', encoding="utf-8")
    (tmp_path / PYPROJECT_FILENAME).write_text(f'[tool.mcpscore.rules]\n{KNOWN_B} = "off"\n', encoding="utf-8")

    config = RuleConfig.discover(tmp_path)

    assert config is not None
    assert config.disabled == (KNOWN_A,)


def test_discover_walks_up_to_the_repository_root(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / CONFIG_FILENAME).write_text(f'[rules]\n{KNOWN_A} = "off"\n', encoding="utf-8")
    nested = tmp_path / "packages" / "server"
    nested.mkdir(parents=True)

    config = RuleConfig.discover(nested)

    assert config is not None
    assert config.disabled == (KNOWN_A,)


def test_discover_stops_at_the_repository_root(tmp_path: Path):
    # A config above the repo root belongs to some other checkout.
    (tmp_path / CONFIG_FILENAME).write_text(f'[rules]\n{KNOWN_A} = "off"\n', encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()

    assert RuleConfig.discover(repo) is None


def test_discover_skips_a_pyproject_without_the_table_and_keeps_walking(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / CONFIG_FILENAME).write_text(f'[rules]\n{KNOWN_A} = "off"\n', encoding="utf-8")
    nested = tmp_path / "pkg"
    nested.mkdir()
    (nested / PYPROJECT_FILENAME).write_text('[project]\nname = "x"\n', encoding="utf-8")

    config = RuleConfig.discover(nested)

    assert config is not None
    assert config.disabled == (KNOWN_A,)


def test_discover_names_the_source_relative_to_the_working_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / CONFIG_FILENAME).write_text(f'[rules]\n{KNOWN_A} = "off"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    config = RuleConfig.discover(tmp_path)

    assert config is not None
    assert config.source == CONFIG_FILENAME


def test_pyproject_with_invalid_toml_is_a_config_error():
    with pytest.raises(ConfigError, match=r"pyproject\.toml: not valid TOML"):
        RuleConfig.parse_pyproject("[tool\n", source="pyproject.toml")


def test_discover_finds_a_pyproject_table_when_there_is_no_mcpscore_toml(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / PYPROJECT_FILENAME).write_text(f'[tool.mcpscore.rules]\n{KNOWN_B} = "high"\n', encoding="utf-8")

    config = RuleConfig.discover(tmp_path)

    assert config is not None
    assert config.reranked == {KNOWN_B: RuleSeverity.HIGH}
    assert config.sha256 == hashlib.sha256((tmp_path / PYPROJECT_FILENAME).read_bytes()).hexdigest()


def test_discover_defaults_to_the_working_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / CONFIG_FILENAME).write_text(f'[rules]\n{KNOWN_A} = "off"\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    config = RuleConfig.discover()

    assert config is not None
    assert config.source == CONFIG_FILENAME


def test_discover_names_a_source_outside_the_working_directory_by_absolute_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".git").mkdir()
    (project / CONFIG_FILENAME).write_text(f'[rules]\n{KNOWN_A} = "off"\n', encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    config = RuleConfig.discover(project)

    assert config is not None
    assert config.source == str((project / CONFIG_FILENAME).resolve())


def test_discover_outside_any_repository_walks_to_the_root_and_finds_nothing(tmp_path: Path):
    # No .git anywhere above a temp dir, and no config on the way up: the walk
    # ends at the filesystem root rather than at a repository boundary.
    assert RuleConfig.discover(tmp_path / "nowhere") is None
