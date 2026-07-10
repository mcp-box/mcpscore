"""Tests for scripts/generate_rules_doc.py — the generated rules reference."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import generate_rules_doc

from mcpscore.rules import create_all_rules


def test_generated_page_has_mdx_frontmatter():
    output = generate_rules_doc.generate()
    assert output.startswith("---\ntitle:")
    assert "description:" in output.split("---")[1]


def test_every_registered_rule_appears():
    output = generate_rules_doc.generate()
    for rule in create_all_rules():
        assert f"`{rule.rule_id}`" in output, rule.rule_id


def test_readiness_rules_are_in_their_own_section():
    output = generate_rules_doc.generate()
    assert "## Readiness rules (separate score)" in output
    readiness_section = output.split("## Readiness rules (separate score)")[1]
    assert "`readiness_2026_server_discover`" in readiness_section


def test_single_trailing_newline():
    """The end-of-file-fixer pre-commit hook rejects extra blank lines at EOF."""
    output = generate_rules_doc.generate()
    assert output.endswith("\n")
    assert not output.endswith("\n\n")


def test_committed_reference_matches_the_registry():
    """docs/rules.mdx must be regenerated whenever the registry changes."""
    committed = (Path(__file__).parent.parent / "docs" / "rules.mdx").read_text()
    assert committed == generate_rules_doc.generate()
