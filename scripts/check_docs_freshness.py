"""Fail when the hand-written docs state a fact the code has moved past.

Run via `make docs-check` (and the test suite). Two checks:

- Spec revision: every "latest" revision in example output must be
  ``mcpscore.spec.LATEST``.
- Engine pins: every mcpscore version pinned in a code block must be no older
  than the previous minor release of the version in pyproject.toml. In YAML
  blocks that includes the ``version`` input of a step that uses the action.

Prose mentions of older versions (a measurement, "since 1.1.0") are not
checked; only copy-pasteable examples are.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePath
import re
import sys
import tomllib

import yaml

from mcpscore.spec import LATEST

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
GENERATED = frozenset({"rules.mdx"})

_LATEST_SPEC = re.compile(
    r"""latest(?::|\s+is|"\s*:|_version"\s*:)\s*\\?["']?(\d{4}-\d{2}-\d{2})""",
)
_ENGINE_PIN = re.compile(
    r"""(?:mcpscore==|@mcp-box/mcpscore@|"mcpscore_version":\s*")(\d+)\.(\d+)\.(\d+)""",
)
_ACTION = "mcp-box/mcpscore-action"
_SEMVER = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_YAML_LANGS = frozenset({"yaml", "yml"})
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")


@dataclass(frozen=True)
class Finding:
    """One stale fact: where it is and what it should be."""

    path: PurePath
    line: int
    message: str

    def __str__(self) -> str:
        return f"{self.path.relative_to(ROOT).as_posix()}:{self.line}: {self.message}"


def engine_version() -> tuple[int, int, int]:
    """Return the engine version from pyproject.toml as (major, minor, patch)."""
    with (ROOT / "pyproject.toml").open("rb") as fh:
        version = tomllib.load(fh)["project"]["version"]
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    if match is None:
        msg = f"unparsable version in pyproject.toml: {version!r}"
        raise ValueError(msg)
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def _action_versions(block: str) -> list[tuple[int, str]]:
    """Return (0-based line, value) of each ``with.version`` on a step that uses the action.

    Parsed as YAML so the input belongs to its own step whatever the key order.
    Raises ``yaml.YAMLError`` when the block does not parse.
    """
    found: list[tuple[int, str]] = []
    stack = [yaml.compose(block)]
    while stack:
        node = stack.pop()
        if isinstance(node, yaml.SequenceNode):
            stack.extend(node.value)
        elif isinstance(node, yaml.MappingNode):
            keys = {key.value: value for key, value in node.value if isinstance(key, yaml.ScalarNode)}
            uses, inputs = keys.get("uses"), keys.get("with")
            if (
                isinstance(uses, yaml.ScalarNode)
                and str(uses.value).startswith(_ACTION)
                and isinstance(inputs, yaml.MappingNode)
            ):
                found.extend(
                    (value.start_mark.line, str(value.value))
                    for key, value in inputs.value
                    if isinstance(key, yaml.ScalarNode)
                    and key.value == "version"
                    and isinstance(value, yaml.ScalarNode)
                )
            stack.extend(value for _, value in node.value)
    return found


def _fence_change(line: str, opener: str | None) -> tuple[bool, str | None]:
    """Return whether ``line`` opens or closes a code block, and the opener now in force.

    CommonMark: a block closes only on a run of its own fence character at
    least as long as the opener, with nothing after it, so a shorter fence
    inside a longer block is content.
    """
    match = _FENCE.match(line)
    if match is None:
        return False, opener
    run, rest = match.groups()
    if opener is None:
        if run[0] == "`" and "`" in rest:
            return False, None
        return True, run
    if run[0] == opener[0] and len(run) >= len(opener) and not rest.strip():
        return True, None
    return False, opener


def check_text(path: PurePath, text: str, current: tuple[int, int, int]) -> list[Finding]:
    """Return the stale facts in one page's text."""
    major, minor, _ = current
    oldest = (major, max(minor - 1, 0))
    findings: list[Finding] = []

    def check_pin(number: int, version: str) -> None:
        match = _SEMVER.match(version)
        if match is None:
            return
        pinned = tuple(int(part) for part in match.groups())
        if pinned[:2] < oldest:
            findings.append(
                Finding(
                    path,
                    number,
                    f"pins mcpscore {'.'.join(map(str, pinned))}; use {major}.{minor} or {oldest[0]}.{oldest[1]}",
                ),
            )

    def check_yaml_block(first: int, lines: list[str]) -> None:
        block = "\n".join(lines)
        if _ACTION not in block:
            return
        try:
            versions = _action_versions(block)
        except yaml.YAMLError:
            findings.append(Finding(path, first, "YAML block that uses the action does not parse"))
            return
        for offset, version in versions:
            check_pin(first + offset, version)

    opener: str | None = None
    yaml_start: int | None = None
    yaml_lines: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        was_open = opener is not None
        is_fence, opener = _fence_change(line, opener)
        if is_fence:
            if was_open and yaml_start is not None:
                check_yaml_block(yaml_start, yaml_lines)
            info = _FENCE.match(line)
            lang = info.group(2).split()[:1] if info is not None and not was_open else []
            yaml_start = number + 1 if lang and lang[0].lower() in _YAML_LANGS else None
            yaml_lines = []
            continue
        findings.extend(
            Finding(path, number, f"latest spec revision is {LATEST.version}, not {match.group(1)}")
            for match in _LATEST_SPEC.finditer(line)
            if match.group(1) != LATEST.version
        )
        if opener is None:
            continue
        if yaml_start is not None:
            yaml_lines.append(line)
        for match in _ENGINE_PIN.finditer(line):
            check_pin(number, ".".join(match.groups()))
    if opener is not None and yaml_start is not None:
        check_yaml_block(yaml_start, yaml_lines)
    findings.sort(key=lambda finding: finding.line)
    return findings


def check_docs(docs: Path | None = None, current: tuple[int, int, int] | None = None) -> list[Finding]:
    """Return the stale facts in every hand-written docs page."""
    version = current or engine_version()
    findings: list[Finding] = []
    for path in sorted((docs or DOCS).rglob("*.mdx")):
        if path.name in GENERATED:
            continue
        findings.extend(check_text(path, path.read_text(encoding="utf-8"), version))
    return findings


def main() -> int:
    findings = check_docs()
    for finding in findings:
        print(finding)
    if findings:
        print(f"{len(findings)} stale fact(s) in docs/", file=sys.stderr)
        return 1
    print("docs: no stale spec revisions or engine pins")
    return 0


if __name__ == "__main__":
    sys.exit(main())
