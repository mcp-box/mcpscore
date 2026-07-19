#!/usr/bin/env python3
"""Cut a release: create the GitHub Release that publishes to PyPI and npm.

Usage:
    uv run python scripts/release.py [--dry-run] [--yes]
    make release          # same, with confirmation prompt
    make release-dry-run  # checks only, creates nothing

The version to release is read from pyproject.toml. The script verifies the
repo is actually releasable, extracts the CHANGELOG section as the release
notes, and creates the GitHub Release (tag v<version>) — which triggers both
.github/workflows/publish.yml (PyPI) and publish-npm.yml (npm) via Trusted
Publishing. It then waits until the version is live on both registries.

Checks performed before anything is created:
  1. on `main`, clean working tree, local HEAD == origin/main
  2. CHANGELOG.md has a `## [<version>]` section AND the `[<version>]:`
     compare link at the bottom (the link block is easy to forget)
  3. the npm wrapper (npm/package.json) version and its pinned Python version
     both match pyproject.toml (so the wrapper never ships stale) — skipped
     for PEP 440 pre-releases (e.g. 1.1.0b1), which publish to PyPI only: the
     GitHub Release is marked pre-release and publish-npm.yml skips those
  4. tag v<version> does not already exist on the remote
  5. CI is green for HEAD

Requires: git, gh (authenticated). No third-party Python dependencies.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import tomllib
from typing import NoReturn
import urllib.error
import urllib.request

REPO = "mcp-box/mcpscore"
NPM_PACKAGE = "@mcp-box/mcpscore"
ROOT = Path(__file__).resolve().parent.parent
REGISTRY_WAIT_SECONDS = 300
REGISTRY_REQUEST_TIMEOUT_SECONDS = 15


def run(*args: str, capture: bool = True) -> str:
    try:
        result = subprocess.run(
            args,
            capture_output=capture,
            text=True,
            check=True,
            cwd=ROOT,
        )
    except FileNotFoundError:
        fail(f"required tool not found: {args[0]} — install it and retry")
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        fail(f"command failed: {' '.join(args)}\n  {stderr or e}")
    return (result.stdout or "").strip()


def fail(message: str) -> NoReturn:
    print(f"✗ {message}", file=sys.stderr)
    sys.exit(1)


def ok(message: str) -> None:
    print(f"✓ {message}")


def read_version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as f:
        return tomllib.load(f)["project"]["version"]


def is_prerelease(version: str) -> bool:
    """Whether the version is a PEP 440 pre-release (e.g. 1.1.0b1).

    Pre-releases publish to PyPI only: their versions are not valid npm
    semver, so the npm wrapper sits releases like these out entirely — no
    version-sync check, a GitHub Release marked pre-release (which
    publish-npm.yml skips), and no npm registry wait.
    """
    return re.search(r"\d(a|b|rc)\d+$", version) is not None


def check_git_state() -> str:
    branch = run("git", "branch", "--show-current")
    if branch != "main":
        fail(f"must release from main (currently on '{branch}')")
    if run("git", "status", "--porcelain"):
        fail("working tree is not clean")
    head = run("git", "rev-parse", "HEAD")
    remote_head = run("gh", "api", f"repos/{REPO}/commits/main", "--jq", ".sha")
    if head != remote_head:
        fail(f"local main ({head[:9]}) != origin/main ({remote_head[:9]}) — push or pull first")
    ok(f"on main, clean, in sync with origin ({head[:9]})")
    return head


def check_changelog(version: str) -> str:
    """Verify the CHANGELOG section and link block, and return the section body."""
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    match = re.search(
        rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)",
        changelog,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        fail(f"CHANGELOG.md has no '## [{version}]' section")
    if f"[{version}]: https://" not in changelog:
        fail(f"CHANGELOG.md is missing the '[{version}]: ...' compare link at the bottom")
    ok(f"CHANGELOG has the [{version}] section and compare link")
    return match.group(1).strip()


def check_npm_version_sync(version: str) -> None:
    """Verify the npm wrapper's version and its Python pin both match the release.

    The wrapper is a thin shim over the Python CLI; if either its own version
    or the mcpscore.pythonVersion it installs drifts from pyproject, `npx`
    users get a different tool than `uvx` users. Fail fast rather than ship
    that skew.
    """
    path = ROOT / "npm" / "package.json"
    try:
        package_json = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        fail(f"npm wrapper manifest not found: {path}")
    except json.JSONDecodeError as e:
        fail(f"npm/package.json is not valid JSON: {e}")
    wrapper_version = package_json.get("version")
    pinned_python = package_json.get("mcpscore", {}).get("pythonVersion")
    if wrapper_version != version:
        fail(f"npm/package.json version is {wrapper_version}, expected {version} — bump the wrapper")
    if pinned_python != version:
        fail(f"npm/package.json mcpscore.pythonVersion is {pinned_python}, expected {version} — bump the pin")
    ok(f"npm wrapper version and Python pin both match {version}")


def check_tag_absent(version: str) -> None:
    result = subprocess.run(
        ["gh", "api", f"repos/{REPO}/git/ref/tags/v{version}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        fail(f"tag v{version} already exists on the remote")
    stderr = (result.stderr or "") + (result.stdout or "")
    if "404" not in stderr and "Not Found" not in stderr:
        fail(f"could not verify tag v{version} (gh api error, not a 404):\n  {stderr.strip()}")
    ok(f"tag v{version} is unused")


def check_ci_green(sha: str) -> None:
    raw = run(
        "gh",
        "api",
        f"repos/{REPO}/commits/{sha}/check-runs",
        "--jq",
        "[.check_runs[] | {name, status, conclusion, started_at, completed_at}]",
    )
    runs = json.loads(raw)
    if not runs:
        fail("no CI check runs found for HEAD — has CI finished?")

    latest_runs = {}
    for check in runs:
        timestamp = check["completed_at"] or check["started_at"] or ""
        latest = latest_runs.get(check["name"])
        latest_timestamp = (latest["completed_at"] or latest["started_at"] or "") if latest else ""
        if latest is None or timestamp > latest_timestamp:
            latest_runs[check["name"]] = check

    runs = list(latest_runs.values())
    bad = [r for r in runs if r["status"] != "completed" or r["conclusion"] not in ("success", "skipped", "neutral")]
    if bad:
        details = ", ".join(f"{r['name']}: {r['conclusion'] or r['status']}" for r in bad)
        fail(f"CI is not green for HEAD — {details}")
    ok(f"CI green for HEAD ({len(runs)} checks)")


def create_release(version: str, notes: str, target: str) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False, encoding="utf-8") as f:
        f.write(notes + "\n")
        notes_file = f.name
    # A pre-release must never become the repo's "latest" release, and the
    # --prerelease flag is what publish-npm.yml keys off to skip npm.
    flag = "--prerelease" if is_prerelease(version) else "--latest"
    try:
        run(
            "gh",
            "release",
            "create",
            f"v{version}",
            "--repo",
            REPO,
            "--target",
            target,
            "--title",
            f"v{version}",
            "--notes-file",
            notes_file,
            flag,
        )
    finally:
        Path(notes_file).unlink(missing_ok=True)
    ok(f"GitHub Release v{version} created — publish workflow triggered")


def wait_for_registry(registry: str, url: str, workflow: str) -> None:
    """Poll a registry until it reports the version, or fail after the deadline.

    Args:
        registry: Human name for messages (e.g. "PyPI", "npm").
        url: Version endpoint that returns HTTP 200 once the version is live.
        workflow: Publish workflow filename, cited if the wait times out.

    """
    print(f"… waiting for {registry} to report the release (up to {REGISTRY_WAIT_SECONDS}s)")
    deadline = time.monotonic() + REGISTRY_WAIT_SECONDS
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            with urllib.request.urlopen(  # noqa: S310 — fixed https registry URL
                url,
                timeout=min(REGISTRY_REQUEST_TIMEOUT_SECONDS, remaining),
            ) as response:
                if response.getcode() == 200:
                    ok(f"live on {registry}")
                    return
        except (TimeoutError, urllib.error.URLError):
            # Expected while the registry propagates or on transient network errors; retry until timeout.
            pass
        time.sleep(min(10, max(0, deadline - time.monotonic())))
    fail(
        f"{registry} did not report the release within {REGISTRY_WAIT_SECONDS}s ({url}) — "
        f"check the workflow: https://github.com/{REPO}/actions/workflows/{workflow}"
    )


def wait_for_publish(version: str) -> None:
    """Wait for the release to appear on each targeted registry, then print a smoke test."""
    wait_for_registry("PyPI", f"https://pypi.org/pypi/mcpscore/{version}/json", "publish.yml")
    if is_prerelease(version):
        ok("npm skipped (pre-release publishes to PyPI only)")
        print(f"\nSmoke test:\n  uvx mcpscore=={version} https://mcp.deepwiki.com/mcp")
        return
    # npm requires the scope slash URL-encoded (%2F) — canonical registry form.
    npm_path = NPM_PACKAGE.replace("/", "%2F")
    wait_for_registry("npm", f"https://registry.npmjs.org/{npm_path}/{version}", "publish-npm.yml")
    print(
        f"\nSmoke test:\n"
        f"  uvx mcpscore=={version} https://mcp.deepwiki.com/mcp\n"
        f"  npx {NPM_PACKAGE}@{version} https://mcp.deepwiki.com/mcp"
    )


def _run_preflight(version: str) -> tuple[str, str]:
    """Run every releasable-state check; return (head sha, release notes)."""
    head = check_git_state()
    notes = check_changelog(version)
    if is_prerelease(version):
        ok(f"npm version sync skipped ({version} is a pre-release — PyPI only)")
    else:
        check_npm_version_sync(version)
    check_tag_absent(version)
    check_ci_green(head)
    return head, notes


def _confirm(version: str) -> bool:
    """Prompt for release confirmation; a closed stdin (EOF) counts as 'no'."""
    registries = "PyPI only (pre-release)" if is_prerelease(version) else "PyPI + npm"
    try:
        answer = input(f"Create GitHub Release v{version} and publish to {registries}? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        print("\naborted (no confirmation)")
        return False
    return answer.strip().lower() == "y"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="run all checks, create nothing")
    parser.add_argument("--yes", action="store_true", help="skip the confirmation prompt (for non-interactive use)")
    args = parser.parse_args()

    version = read_version()
    print(f"Releasing mcpscore {version}\n")

    head, notes = _run_preflight(version)

    print(f"\n--- release notes (from CHANGELOG) ---\n{notes}\n--------------------------------------\n")

    if args.dry_run:
        ok(f"dry run: all checks passed — would create release v{version}")
        return

    if not args.yes and not _confirm(version):
        sys.exit(1)

    # Re-check the fast-moving state in case main advanced during the prompt.
    head, notes = _run_preflight(version)

    create_release(version, notes, head)
    wait_for_publish(version)


if __name__ == "__main__":
    main()
