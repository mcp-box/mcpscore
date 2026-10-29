"""Tests for scripts/check_docs_freshness.py — stale facts in the hand-written docs."""

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import check_docs_freshness as freshness

from mcpscore.spec import LATEST

CURRENT = (1, 29, 1)
PAGE = Path(freshness.DOCS / "page.mdx")


def messages(text: str, current: tuple[int, int, int] = CURRENT) -> list[str]:
    return [finding.message for finding in freshness.check_text(PAGE, text, current)]


def test_committed_docs_have_no_stale_facts():
    """Bump the docs' version pins when a minor release moves pyproject.toml past them."""
    assert [str(finding) for finding in freshness.check_docs()] == []


@pytest.mark.parametrize(
    "line",
    [
        "Spec: 2025-11-25 negotiated (latest: 2025-11-25) · era: legacy",
        '"spec": { "negotiated_version": "2025-11-25", "latest_version": "2025-11-25" }',
        """"text": "negotiated \\"2025-11-25\\", latest is '2025-11-25', and ..." """,
    ],
)
def test_superseded_latest_revision_is_flagged(line: str):
    assert messages(line) == [f"latest spec revision is {LATEST.version}, not 2025-11-25"]


def test_current_latest_revision_passes():
    assert messages(f"Spec: 2025-11-25 negotiated (latest: {LATEST.version})") == []


@pytest.mark.parametrize(
    "line",
    [
        '    - pip install "mcpscore==1.20.0"',
        '    version: "1.20.0"',
        '  "mcpscore_version": "1.20.0",',
        "npx @mcp-box/mcpscore@1.20.0 https://example.com/mcp",
    ],
)
def test_old_engine_pin_in_a_code_block_is_flagged(line: str):
    assert messages(f"```yaml\n{line}\n```") == ["pins mcpscore 1.20.0; use 1.29 or 1.28"]


@pytest.mark.parametrize("pin", ["1.28.0", "1.29.1", "1.30.0"])
def test_pin_from_the_previous_minor_or_newer_passes(pin: str):
    assert messages(f'```yaml\nversion: "{pin}"\n```') == []


def test_pin_in_prose_is_not_checked():
    assert messages("Measured with mcpscore 1.20.0. Pin `mcpscore==1.20.0` to reproduce.") == []


def test_fence_closes_and_later_prose_is_not_checked():
    text = '```bash\npip install "mcpscore==1.29.1"\n```\n\nOlder: `mcpscore==1.20.0`.'
    assert messages(text) == []


def test_server_version_kwarg_is_not_an_engine_pin():
    assert messages('```python\nmcp = FastMCP("notes", version="1.4.0")\n```') == []


def test_first_minor_of_a_major_accepts_its_own_minor():
    assert messages('```yaml\nversion: "2.0.0"\n```', current=(2, 0, 0)) == []
    assert messages('```yaml\nversion: "1.29.1"\n```', current=(2, 0, 0)) == ["pins mcpscore 1.29.1; use 2.0 or 2.0"]


def test_finding_reports_the_repo_relative_line():
    [finding] = freshness.check_text(PAGE, "intro\n```\nversion: 0.8.0\n```", CURRENT)
    assert str(finding) == "docs/page.mdx:3: pins mcpscore 0.8.0; use 1.29 or 1.28"


def test_generated_rules_page_is_skipped(tmp_path: Path):
    (tmp_path / "rules.mdx").write_text("(latest: 2025-11-25)\n", encoding="utf-8")
    (tmp_path / "guide.mdx").write_text("(latest: 2025-11-25)\n", encoding="utf-8")
    found = freshness.check_docs(tmp_path, CURRENT)
    assert [finding.path.name for finding in found] == ["guide.mdx"]


def test_engine_version_matches_pyproject():
    major, minor, patch = freshness.engine_version()
    assert major >= 1
    assert minor >= 0
    assert patch >= 0


def test_engine_version_rejects_an_unparsable_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "dev"\n', encoding="utf-8")
    monkeypatch.setattr(freshness, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="unparsable version"):
        freshness.engine_version()


def test_main_exit_codes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    monkeypatch.setattr(freshness, "ROOT", tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.29.1"\n', encoding="utf-8")
    (docs / "guide.mdx").write_text(f"(latest: {LATEST.version})\n", encoding="utf-8")
    monkeypatch.setattr(freshness, "DOCS", docs)
    assert freshness.main() == 0

    (docs / "guide.mdx").write_text("```\nmcpscore==1.0.0\n```\n", encoding="utf-8")
    assert freshness.main() == 1
    out = capsys.readouterr()
    assert "docs/guide.mdx:2: pins mcpscore 1.0.0" in out.out
    assert "1 stale fact(s)" in out.err
