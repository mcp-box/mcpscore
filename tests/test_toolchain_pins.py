"""The ruff the pre-commit hook runs must be the ruff `make lint` and CI run.

`pyproject.toml` pins ruff exactly and `.pre-commit-config.yaml` pins the
hook's rev; the comment on the former says they are kept equal, and nothing
enforced it — they drifted two patch versions apart (2026-09-03). A newer ruff
on one side applies a fix the other side rejects: green locally, red on push.
"""

from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parent.parent


def pinned_ruff_version() -> str:
    """Return the exact ruff version pinned in pyproject.toml's dependency groups."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    specs = [
        spec
        for group in data["dependency-groups"].values()
        for spec in group
        if isinstance(spec, str) and re.match(r"ruff\b", spec)
    ]
    assert len(specs) == 1, f"expected exactly one ruff spec, found {specs}"
    match = re.fullmatch(r"ruff==(\d+\.\d+\.\d+)", specs[0])
    assert match, f"ruff must be pinned exactly (ruff==X.Y.Z), found {specs[0]!r}"
    return match.group(1)


def hook_ruff_version() -> str:
    """Return the rev of the astral-sh/ruff-pre-commit hook in .pre-commit-config.yaml."""
    text = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    match = re.search(r"ruff-pre-commit\s*\n(?:\s*#[^\n]*\n)*\s*rev:\s*v(\d+\.\d+\.\d+)", text)
    assert match, "no ruff-pre-commit hook with a vX.Y.Z rev in .pre-commit-config.yaml"
    return match.group(1)


def test_ruff_hook_rev_matches_pyproject_pin() -> None:
    pinned, hook = pinned_ruff_version(), hook_ruff_version()
    assert hook == pinned, (
        f"ruff drift: pyproject.toml pins ruff=={pinned} but .pre-commit-config.yaml "
        f"runs ruff-pre-commit v{hook}. Bump one to match the other."
    )
