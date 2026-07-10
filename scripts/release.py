#!/usr/bin/env python3
"""Cut a release: create the GitHub Release that triggers PyPI publishing.

Usage:
    uv run python scripts/release.py [--dry-run]
    make release          # same, with confirmation prompt
    make release-dry-run  # checks only, creates nothing

The version to release is read from pyproject.toml. The script verifies the
repo is actually releasable, extracts the CHANGELOG section as the release
notes, and creates the GitHub Release (tag v<version>) — which triggers
.github/workflows/publish.yml to build and publish to PyPI via Trusted
Publishing. It then waits until the version is live on PyPI.

Checks performed before anything is created:
  1. on `main`, clean working tree, local HEAD == origin/main
  2. CHANGELOG.md has a `## [<version>]` section AND the `[<version>]:`
     compare link at the bottom (the link block is easy to forget)
  3. tag v<version> does not already exist on the remote
  4. CI is green for HEAD

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
ROOT = Path(__file__).resolve().parent.parent
PYPI_WAIT_SECONDS = 300
PYPI_REQUEST_TIMEOUT_SECONDS = 15


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
            "--latest",
        )
    finally:
        Path(notes_file).unlink(missing_ok=True)
    ok(f"GitHub Release v{version} created — publish workflow triggered")


def wait_for_pypi(version: str) -> None:
    url = f"https://pypi.org/pypi/mcpscore/{version}/json"
    print(f"… waiting for mcpscore {version} on PyPI (up to {PYPI_WAIT_SECONDS}s)")
    deadline = time.monotonic() + PYPI_WAIT_SECONDS
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            with urllib.request.urlopen(  # noqa: S310 — fixed https URL
                url,
                timeout=min(PYPI_REQUEST_TIMEOUT_SECONDS, remaining),
            ) as response:
                if response.getcode() == 200:
                    ok(f"mcpscore {version} is live on PyPI")
                    print(f"\nSmoke test:\n  uvx mcpscore=={version} https://mcp.deepwiki.com/mcp")
                    return
        except (TimeoutError, urllib.error.URLError):
            # Expected while PyPI propagates or during transient network errors; retry until timeout.
            pass
        time.sleep(min(10, max(0, deadline - time.monotonic())))
    fail(
        f"PyPI did not report {version} within {PYPI_WAIT_SECONDS}s — "
        f"check the workflow: https://github.com/{REPO}/actions/workflows/publish.yml"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="run all checks, create nothing")
    args = parser.parse_args()

    version = read_version()
    print(f"Releasing mcpscore {version}\n")

    head = check_git_state()
    notes = check_changelog(version)
    check_tag_absent(version)
    check_ci_green(head)

    print(f"\n--- release notes (from CHANGELOG) ---\n{notes}\n--------------------------------------\n")

    if args.dry_run:
        ok(f"dry run: all checks passed — would create release v{version}")
        return

    answer = input(f"Create GitHub Release v{version} and publish to PyPI? [y/N] ")
    if answer.strip().lower() != "y":
        print("aborted")
        sys.exit(1)

    head = check_git_state()
    check_tag_absent(version)
    check_ci_green(head)

    create_release(version, notes, head)
    wait_for_pypi(version)


if __name__ == "__main__":
    main()
