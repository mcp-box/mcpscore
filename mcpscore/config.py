"""Per-project rule configuration: ``mcpscore.toml`` or ``[tool.mcpscore]`` in ``pyproject.toml``.

A team turns rules off and re-ranks the rest by severity name, keyed on
``rule_id``, the way a ``ruff.toml`` works::

    [rules]
    server_websiteurl_present = "off"  # does not run
    tools_title_present_in_all = "critical"  # runs, counts as CRITICAL

    [gate]
    fail_on = "high"  # any failed rule at or above HIGH fails the build

The configuration changes the score for the run that used it and nothing
else: the website and the badge never see one (the backend never constructs
a ``RuleConfig``), and the JSON report records what was applied. Design and
decision: ``project/tech-design/design-rule-config.md``,
``project/decision-records/2026-09-04-rule-config-off-rerank-gate.md``.

Discovery lives here and is used by the CLI only; ``MCPAuditor`` applies a
configuration solely when handed one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import tomllib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

from .rules.base import RuleSeverity
from .rules.registry import all_rule_ids
from .rules.retired import RETIRED_RULES

CONFIG_FILENAME = "mcpscore.toml"
PYPROJECT_FILENAME = "pyproject.toml"
PYPROJECT_TABLE = "mcpscore"  # [tool.mcpscore]

OFF = "off"
"""The one spelling for "this rule does not run"."""

SKIP_REASON_DISABLED_BY_CONFIG = "disabled-by-config"
"""``skipped_rules[].reason`` for a rule the configuration turned off."""

# Hints list the choices ascending, the order people think in; the enum declares them descending.
_SEVERITY_NAMES = tuple(s.name.lower() for s in sorted(RuleSeverity, key=int))
_VALUE_HINT = ", ".join((OFF, *_SEVERITY_NAMES[:-1])) + f", or {_SEVERITY_NAMES[-1]}"
_SEVERITY_HINT = ", ".join(_SEVERITY_NAMES[:-1]) + f", or {_SEVERITY_NAMES[-1]}"


class ConfigError(ValueError):
    """A configuration file that cannot be applied. The CLI reports it as a usage error."""


@dataclass(frozen=True)
class RuleConfig:
    """A parsed, validated configuration.

    Attributes:
        source: Where it came from, as the CLI and the report name it (a path
            relative to the working directory, or absolute for ``--config``).
        sha256: Hex digest of the file's bytes, so two reports with the same
            digest and engine version are comparable.
        overrides: ``rule_id`` to configured severity, or ``None`` for off.
            Only ids the registry knows; unknown ones are in ``unknown``.
        fail_on: The ``[gate]`` threshold, or ``None`` when no gate is set.
        unknown: Configured ids the registry does not have, in file order.
            They warn and are reported, never applied and never fatal, so a
            configuration written for a newer engine still runs on an older one.
        retired: Unknown ids that ``rules/retired.py`` explains, as
            ``(rule_id, version)`` pairs, so the warning can say why.

    """

    source: str
    sha256: str
    overrides: Mapping[str, RuleSeverity | None] = field(default_factory=dict)
    fail_on: RuleSeverity | None = None
    unknown: tuple[str, ...] = ()
    retired: tuple[tuple[str, str], ...] = ()

    @property
    def disabled(self) -> tuple[str, ...]:
        """Rule ids turned off, in file order."""
        return tuple(rule_id for rule_id, severity in self.overrides.items() if severity is None)

    @property
    def reranked(self) -> dict[str, RuleSeverity]:
        """Rule ids given a configured severity, in file order."""
        return {rule_id: severity for rule_id, severity in self.overrides.items() if severity is not None}

    def summary(self) -> str:
        """One clause for the score line, e.g. ``2 rules off, 1 re-ranked``."""
        off, reranked = len(self.disabled), len(self.reranked)
        parts = [f"{off} rule{'s' if off != 1 else ''} off"] if off else []
        if reranked:
            parts.append(f"{reranked} re-ranked")
        if self.fail_on is not None:
            parts.append(f"gate at {self.fail_on.name}")
        return ", ".join(parts) if parts else "no overrides"

    # ---------------------------------------------------------------- parsing

    @classmethod
    def parse(cls, text: str, *, source: str, sha256: str | None = None) -> RuleConfig:
        """Parse a ``mcpscore.toml`` document (``[rules]`` and ``[gate]`` at the top level)."""
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"{source}: not valid TOML: {e}") from e
        return cls._from_tables(data, source=source, sha256=sha256 or _digest(text.encode("utf-8")))

    @classmethod
    def parse_pyproject(cls, text: str, *, source: str, sha256: str | None = None) -> RuleConfig | None:
        """Parse the ``[tool.mcpscore]`` table of a ``pyproject.toml``; None when it has none."""
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"{source}: not valid TOML: {e}") from e
        tool = data.get("tool")
        if not isinstance(tool, dict) or PYPROJECT_TABLE not in tool:
            return None
        table = tool[PYPROJECT_TABLE]
        if not isinstance(table, dict):
            raise ConfigError(f"{source}: [tool.{PYPROJECT_TABLE}] must be a table")
        return cls._from_tables(table, source=source, sha256=sha256 or _digest(text.encode("utf-8")))

    @classmethod
    def load(cls, path: Path, *, source: str | None = None) -> RuleConfig:
        """Load a configuration file by path; a ``pyproject.toml`` is read through its tool table.

        Raises:
            ConfigError: the file is missing, unreadable, invalid TOML, has an
                invalid value, or is a ``pyproject.toml`` with no
                ``[tool.mcpscore]`` table.

        """
        display = source or str(path)
        try:
            raw = path.read_bytes()
        except OSError as e:
            raise ConfigError(f"{display}: cannot read config file: {e.strerror or e}") from e
        text = raw.decode("utf-8")
        digest = _digest(raw)
        if path.name == PYPROJECT_FILENAME:
            config = cls.parse_pyproject(text, source=display, sha256=digest)
            if config is None:
                raise ConfigError(f"{display}: no [tool.{PYPROJECT_TABLE}] table")
            return config
        return cls.parse(text, source=display, sha256=digest)

    @classmethod
    def discover(cls, start: Path | None = None) -> RuleConfig | None:
        """Find the nearest configuration, walking up from ``start`` (default: the working directory).

        In each directory ``mcpscore.toml`` wins over a ``pyproject.toml`` with a
        ``[tool.mcpscore]`` table. The walk stops after the first directory that
        contains ``.git``, so a configuration in one checkout cannot leak into an
        audit run inside another. Returns None when nothing is found.
        """
        here = (start or Path.cwd()).resolve()
        cwd = Path.cwd().resolve()
        for directory in (here, *here.parents):
            candidate = directory / CONFIG_FILENAME
            if candidate.is_file():
                return cls.load(candidate, source=_display(candidate, cwd))
            pyproject = directory / PYPROJECT_FILENAME
            if pyproject.is_file():
                raw = pyproject.read_bytes()
                found = cls.parse_pyproject(raw.decode("utf-8"), source=_display(pyproject, cwd), sha256=_digest(raw))
                if found is not None:
                    return found
            if (directory / ".git").exists():
                break
        return None

    @classmethod
    def _from_tables(cls, data: Mapping[str, Any], *, source: str, sha256: str) -> RuleConfig:
        unexpected = sorted(set(data) - {"rules", "gate"})
        if unexpected:
            raise ConfigError(f"{source}: unexpected table(s) {', '.join(unexpected)}; expected [rules] and [gate]")

        rules = data.get("rules", {})
        if not isinstance(rules, dict):
            raise ConfigError(f"{source}: [rules] must be a table of rule_id = value")
        known = set(all_rule_ids())
        retired_versions = {r.rule_id: r.version for r in RETIRED_RULES}
        overrides: dict[str, RuleSeverity | None] = {}
        unknown: list[str] = []
        retired: list[tuple[str, str]] = []
        for rule_id, value in rules.items():
            severity = _parse_rule_value(rule_id, value, source)
            if rule_id in known:
                overrides[rule_id] = severity
            else:
                unknown.append(rule_id)
                if rule_id in retired_versions:
                    retired.append((rule_id, retired_versions[rule_id]))

        gate = data.get("gate", {})
        if not isinstance(gate, dict):
            raise ConfigError(f"{source}: [gate] must be a table")
        unexpected_gate = sorted(set(gate) - {"fail_on"})
        if unexpected_gate:
            raise ConfigError(f"{source}: [gate] has unexpected key(s) {', '.join(unexpected_gate)}; expected fail_on")
        fail_on: RuleSeverity | None = None
        if "fail_on" in gate:
            fail_on = _parse_severity(gate["fail_on"])
            if fail_on is None:
                raise ConfigError(f"{source}: [gate] fail_on has value {gate['fail_on']!r}; expected {_SEVERITY_HINT}")

        return cls(
            source=source,
            sha256=sha256,
            overrides=overrides,
            fail_on=fail_on,
            unknown=tuple(unknown),
            retired=tuple(retired),
        )


def _parse_rule_value(rule_id: str, value: object, source: str) -> RuleSeverity | None:
    """Return the configured severity for a rule entry, or None for off; raise on anything else."""
    if isinstance(value, str):
        if value.lower() == OFF:
            return None
        severity = _parse_severity(value)
        if severity is not None:
            return severity
    raise ConfigError(f"{source}: rule '{rule_id}' has value {value!r}; expected {_VALUE_HINT}")


def _parse_severity(value: object) -> RuleSeverity | None:
    if not isinstance(value, str):
        return None
    try:
        return RuleSeverity[value.upper()]
    except KeyError:
        return None


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _display(path: Path, cwd: Path) -> str:
    try:
        return str(path.relative_to(cwd))
    except ValueError:
        return str(path)
