"""Tests for scripts/release.py — the release preflight and publish flow.

The release script runs with real git/gh/network in production; here every
external effect is stubbed so the decision logic is verified hermetically.
"""

from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import urllib.error

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import release


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the script at a temporary repo root with a valid CHANGELOG and npm wrapper."""
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "mcpscore"\nversion = "1.2.3"\n')
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n"
        "## [1.2.3] - 2026-07-10\n\nThe notes body.\n\n"
        "## [1.2.2] - 2026-07-01\n\nOlder notes.\n\n"
        "[1.2.3]: https://github.com/mcp-box/mcpscore/compare/v1.2.2...v1.2.3\n"
        "[1.2.2]: https://github.com/mcp-box/mcpscore/releases/tag/v1.2.2\n"
    )
    (tmp_path / "npm").mkdir()
    (tmp_path / "npm" / "package.json").write_text(
        '{"name": "@mcp-box/mcpscore", "version": "1.2.3", "mcpscore": {"pythonVersion": "1.2.3"}}'
    )
    monkeypatch.setattr(release, "ROOT", tmp_path)
    return tmp_path


class TestReadVersion:
    def test_reads_project_version(self, repo: Path):
        assert release.read_version() == "1.2.3"


class TestCheckChangelog:
    def test_extracts_the_matching_section(self, repo: Path):
        assert release.check_changelog("1.2.3") == "The notes body."

    def test_fails_without_a_section(self, repo: Path):
        with pytest.raises(SystemExit):
            release.check_changelog("9.9.9")

    def test_fails_without_the_compare_link(self, repo: Path):
        changelog = repo / "CHANGELOG.md"
        changelog.write_text(changelog.read_text().replace("[1.2.3]: https://", "[nope]: https://"))
        with pytest.raises(SystemExit):
            release.check_changelog("1.2.3")


class TestCheckGitState:
    def _stub_run(self, monkeypatch: pytest.MonkeyPatch, responses: dict[str, str]) -> None:
        def fake_run(*args: str, capture: bool = True) -> str:
            return responses[" ".join(args)]

        monkeypatch.setattr(release, "run", fake_run)

    def test_passes_on_clean_synced_main(self, monkeypatch: pytest.MonkeyPatch):
        self._stub_run(
            monkeypatch,
            {
                "git branch --show-current": "main",
                "git status --porcelain": "",
                "git rev-parse HEAD": "abc123",
                f"gh api repos/{release.REPO}/commits/main --jq .sha": "abc123",
            },
        )
        assert release.check_git_state() == "abc123"

    def test_fails_off_main(self, monkeypatch: pytest.MonkeyPatch):
        self._stub_run(monkeypatch, {"git branch --show-current": "feature"})
        with pytest.raises(SystemExit):
            release.check_git_state()

    def test_prerelease_allowed_off_main(self, monkeypatch: pytest.MonkeyPatch):
        """A pre-release may run from a feature branch, synced against its own origin ref."""
        self._stub_run(
            monkeypatch,
            {
                "git branch --show-current": "feat/sdk-v2",
                "git status --porcelain": "",
                "git rev-parse HEAD": "abc123",
                f"gh api repos/{release.REPO}/commits/feat/sdk-v2 --jq .sha": "abc123",
            },
        )
        assert release.check_git_state(prerelease=True) == "abc123"

    def test_prerelease_off_main_still_requires_sync(self, monkeypatch: pytest.MonkeyPatch):
        self._stub_run(
            monkeypatch,
            {
                "git branch --show-current": "feat/sdk-v2",
                "git status --porcelain": "",
                "git rev-parse HEAD": "abc123",
                f"gh api repos/{release.REPO}/commits/feat/sdk-v2 --jq .sha": "def456",
            },
        )
        with pytest.raises(SystemExit):
            release.check_git_state(prerelease=True)

    def test_fails_on_dirty_tree(self, monkeypatch: pytest.MonkeyPatch):
        self._stub_run(
            monkeypatch,
            {"git branch --show-current": "main", "git status --porcelain": " M file.py"},
        )
        with pytest.raises(SystemExit):
            release.check_git_state()

    def test_fails_when_out_of_sync_with_origin(self, monkeypatch: pytest.MonkeyPatch):
        self._stub_run(
            monkeypatch,
            {
                "git branch --show-current": "main",
                "git status --porcelain": "",
                "git rev-parse HEAD": "abc123",
                f"gh api repos/{release.REPO}/commits/main --jq .sha": "def456",
            },
        )
        with pytest.raises(SystemExit):
            release.check_git_state()


class TestCheckTagAbsent:
    def _stub_gh(self, monkeypatch: pytest.MonkeyPatch, returncode: int, stderr: str = "") -> None:
        def fake_subprocess_run(*args, **kwargs):
            return SimpleNamespace(returncode=returncode, stdout="", stderr=stderr)

        monkeypatch.setattr(subprocess, "run", fake_subprocess_run)

    def test_absent_tag_passes(self, monkeypatch: pytest.MonkeyPatch):
        self._stub_gh(monkeypatch, returncode=1, stderr="gh: Not Found (HTTP 404)")
        release.check_tag_absent("1.2.3")  # must not raise

    def test_existing_tag_fails(self, monkeypatch: pytest.MonkeyPatch):
        self._stub_gh(monkeypatch, returncode=0)
        with pytest.raises(SystemExit):
            release.check_tag_absent("1.2.3")

    def test_non_404_error_fails_instead_of_passing(self, monkeypatch: pytest.MonkeyPatch):
        """An unauthenticated/rate-limited gh must not be mistaken for an absent tag."""
        self._stub_gh(monkeypatch, returncode=1, stderr="gh: HTTP 401 Bad credentials")
        with pytest.raises(SystemExit):
            release.check_tag_absent("1.2.3")


class TestCheckCiGreen:
    def _stub_checks(self, monkeypatch: pytest.MonkeyPatch, runs: list[dict]) -> None:
        import json

        monkeypatch.setattr(release, "run", lambda *_args, **_kwargs: json.dumps(runs))

    @staticmethod
    def _run(name: str, conclusion: str, completed_at: str) -> dict:
        return {
            "name": name,
            "status": "completed",
            "conclusion": conclusion,
            "started_at": completed_at,
            "completed_at": completed_at,
        }

    def test_all_green_passes(self, monkeypatch: pytest.MonkeyPatch):
        self._stub_checks(monkeypatch, [self._run("lint", "success", "2026-07-10T10:00:00Z")])
        release.check_ci_green("abc123")  # must not raise

    def test_failure_blocks(self, monkeypatch: pytest.MonkeyPatch):
        self._stub_checks(monkeypatch, [self._run("test", "failure", "2026-07-10T10:00:00Z")])
        with pytest.raises(SystemExit):
            release.check_ci_green("abc123")

    def test_stale_failed_run_is_superseded_by_newer_success(self, monkeypatch: pytest.MonkeyPatch):
        """A re-run that succeeded must win over the older failed attempt."""
        self._stub_checks(
            monkeypatch,
            [
                self._run("test", "failure", "2026-07-10T10:00:00Z"),
                self._run("test", "success", "2026-07-10T11:00:00Z"),
            ],
        )
        release.check_ci_green("abc123")  # must not raise

    def test_no_checks_blocks(self, monkeypatch: pytest.MonkeyPatch):
        self._stub_checks(monkeypatch, [])
        with pytest.raises(SystemExit):
            release.check_ci_green("abc123")


class TestCreateRelease:
    def test_passes_validated_target_and_cleans_up_notes_file(self, monkeypatch: pytest.MonkeyPatch):
        seen: dict = {}

        def fake_run(*args: str, capture: bool = True) -> str:
            seen["args"] = args
            seen["notes_path"] = Path(args[args.index("--notes-file") + 1])
            seen["notes_existed_during_run"] = seen["notes_path"].exists()
            return ""

        monkeypatch.setattr(release, "run", fake_run)
        release.create_release("1.2.3", "notes body", target="abc123")

        assert "--target" in seen["args"]
        assert seen["args"][seen["args"].index("--target") + 1] == "abc123"
        assert seen["notes_existed_during_run"] is True
        assert not seen["notes_path"].exists()  # cleaned up afterwards

    def test_notes_file_cleaned_up_even_when_gh_fails(self, monkeypatch: pytest.MonkeyPatch):
        seen: dict = {}

        def failing_run(*args: str, capture: bool = True) -> str:
            seen["notes_path"] = Path(args[args.index("--notes-file") + 1])
            raise SystemExit(1)

        monkeypatch.setattr(release, "run", failing_run)
        with pytest.raises(SystemExit):
            release.create_release("1.2.3", "notes body", target="abc123")
        assert not seen["notes_path"].exists()


class TestCheckNpmVersionSync:
    def test_passes_when_wrapper_and_pin_match(self, repo: Path):
        release.check_npm_version_sync("1.2.3")  # must not raise

    def test_fails_on_wrapper_version_drift(self, repo: Path):
        (repo / "npm" / "package.json").write_text(
            '{"name": "@mcp-box/mcpscore", "version": "1.2.2", "mcpscore": {"pythonVersion": "1.2.3"}}'
        )
        with pytest.raises(SystemExit):
            release.check_npm_version_sync("1.2.3")

    def test_fails_on_python_pin_drift(self, repo: Path):
        (repo / "npm" / "package.json").write_text(
            '{"name": "@mcp-box/mcpscore", "version": "1.2.3", "mcpscore": {"pythonVersion": "1.2.2"}}'
        )
        with pytest.raises(SystemExit):
            release.check_npm_version_sync("1.2.3")

    def test_fails_when_manifest_missing(self, repo: Path):
        (repo / "npm" / "package.json").unlink()
        with pytest.raises(SystemExit):
            release.check_npm_version_sync("1.2.3")

    def test_fails_on_invalid_json(self, repo: Path):
        (repo / "npm" / "package.json").write_text("{ not valid json")
        with pytest.raises(SystemExit):
            release.check_npm_version_sync("1.2.3")


class TestWaitForRegistry:
    def test_returns_once_registry_reports_the_version(self, monkeypatch: pytest.MonkeyPatch):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def getcode(self):
                return 200

        monkeypatch.setattr(release.urllib.request, "urlopen", lambda _url, **_kwargs: FakeResponse())
        release.wait_for_registry("PyPI", "https://example/x", "publish.yml")  # must not raise

    def test_times_out_when_version_never_appears(self, monkeypatch: pytest.MonkeyPatch):
        def always_missing(_url, timeout=None):
            raise urllib.error.URLError("boom")

        clock = iter(range(0, 10_000, 60))
        monkeypatch.setattr(release.urllib.request, "urlopen", always_missing)
        monkeypatch.setattr(release.time, "monotonic", lambda: next(clock))
        monkeypatch.setattr(release.time, "sleep", lambda _seconds: None)
        with pytest.raises(SystemExit):
            release.wait_for_registry("npm", "https://example/x", "publish-npm.yml")

    def test_wait_for_publish_polls_both_registries(self, monkeypatch: pytest.MonkeyPatch):
        polled: list[str] = []
        monkeypatch.setattr(release, "wait_for_registry", lambda name, _url, _workflow: polled.append(name))
        release.wait_for_publish("1.2.3")
        assert polled == ["PyPI", "npm"]


class TestMainDryRun:
    def test_dry_run_checks_everything_and_creates_nothing(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ):
        monkeypatch.setattr(sys, "argv", ["release.py", "--dry-run"])
        monkeypatch.setattr(release, "check_git_state", lambda **_kwargs: "abc123")
        monkeypatch.setattr(release, "check_tag_absent", lambda _version: None)
        monkeypatch.setattr(release, "check_ci_green", lambda _sha: None)

        def must_not_be_called(*_args, **_kwargs):
            pytest.fail("create_release must not run in --dry-run")

        monkeypatch.setattr(release, "create_release", must_not_be_called)
        monkeypatch.setattr(release, "wait_for_publish", must_not_be_called)

        release.main()

        out = capsys.readouterr().out
        assert "dry run: all checks passed" in out
        assert "npm wrapper version and Python pin both match" in out

    def test_yes_flag_skips_prompt_and_publishes(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ):
        monkeypatch.setattr(sys, "argv", ["release.py", "--yes"])
        monkeypatch.setattr(release, "check_git_state", lambda **_kwargs: "abc123")
        monkeypatch.setattr(release, "check_tag_absent", lambda _version: None)
        monkeypatch.setattr(release, "check_ci_green", lambda _sha: None)

        created: list[str] = []
        monkeypatch.setattr(release, "create_release", lambda _version, _notes, target: created.append(target))
        monkeypatch.setattr(release, "wait_for_publish", lambda _version: None)

        def no_prompt(*_args, **_kwargs):
            pytest.fail("--yes must not prompt")

        monkeypatch.setattr("builtins.input", no_prompt)

        release.main()
        assert created == ["abc123"]

    def test_eof_at_prompt_aborts_cleanly(self, repo: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(sys, "argv", ["release.py"])
        monkeypatch.setattr(release, "check_git_state", lambda **_kwargs: "abc123")
        monkeypatch.setattr(release, "check_tag_absent", lambda _version: None)
        monkeypatch.setattr(release, "check_ci_green", lambda _sha: None)

        def raise_eof(_prompt):
            raise EOFError

        monkeypatch.setattr("builtins.input", raise_eof)
        with pytest.raises(SystemExit):
            release.main()
