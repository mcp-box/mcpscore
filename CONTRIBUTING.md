# Contributing to mcpscore

Thanks for your interest in improving mcpscore! Bug reports, feature
requests, and pull requests are all welcome.

## Development setup

Requirements: Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/mcp-box/mcpscore.git
cd mcpscore
make install        # uv sync + pre-commit hooks (commit and push)
```

## Development workflow

```bash
make format         # Auto-format (ruff)
make lint           # Lint without fixing
make typecheck      # Pyright (0 errors required in mcpscore/)
make test           # Run the test suite
make testcov        # Tests with coverage report (97% minimum enforced)
make all            # Everything CI runs
```

`make all` must pass before a PR — CI runs the same checks on Linux, macOS,
and Windows against Python 3.11–3.13.

## Adding an audit rule

Rules live in `mcpscore/rules/`. To add one:

1. Subclass `BaseRule` in the appropriate module (or a new one), set a unique
   `rule_id`, `group_name`, and ordering, and implement `rule_name`,
   `severity`, and `check()`.
2. Decorate the class with `@register_rule` so it joins the registry.
3. Export it from `mcpscore/rules/__init__.py` (import + `__all__`) — a
   decorated rule whose module is never imported silently vanishes from
   audits (a registry test catches this).
4. Add tests covering the pass path, the fail path, and any
   not-applicable path (e.g. stdio transport).
5. Regenerate the rules reference with `make docs-rules` — `docs/rules.mdx`
   is generated and must never be edited by hand (CI fails on drift) — and
   add a `CHANGELOG.md` entry under `[Unreleased]`.

Severity weights: CRITICAL = 5, HIGH = 3, MEDIUM = 2, LOW = 1. Choose based
on how strongly the MCP specification mandates the behavior — spec
violations are CRITICAL/HIGH, recommendations are MEDIUM/LOW.

Contracts every rule must respect:

- **`rule_id` is a permanent public identifier** — it appears in JSON
  reports, CI waivers, and stored audit history. Never rename or reuse one.
- **Cite the primary source.** Every rule carries a `basis` (or equivalent)
  naming the MCP spec section, RFC, or SEP it enforces — a test rejects
  empty or throwaway citations. Don't cite blog posts; they have disagreed
  with the spec text before.
- **A rule that cannot judge must skip, not fail (and not pass).** Missing
  evidence is a skip with a reason — never a vacuous pass, never a failure
  for having nothing to observe.
- **Obsolete requirements are version-scoped, not deleted**: set
  `max_spec_version` so the rule still judges the revisions where the
  requirement held. Delete a rule only if it was *wrong*, and record it in
  `mcpscore/rules/retired.py` — retired ids are never reused (the registry
  enforces this).
- **Readiness rules score differently**: the `readiness` group reports on
  its own axis and only counts toward the main score for modern-lifecycle
  servers in full audits.
- **Ordering**: rules sort by `(group_order, group_name, rule_order,
  rule_id)` — pick a `rule_order` that reads well next to the rule's
  siblings within its group; the tie-breakers keep everything else
  deterministic.

## Pull request expectations

- Keep PRs focused; separate refactors from behavior changes.
- New code needs tests — coverage must stay at or above 97%, for the project
  total and for the diff of your PR (Codecov enforces both; see codecov.yml).
- Public functions and classes carry type hints and docstrings.
- Update `CHANGELOG.md` under `[Unreleased]`.
- Formatting is automated (`make format`); style debates are out of scope.

## Reporting bugs and requesting features

Use the [issue templates](https://github.com/mcp-box/mcpscore/issues/new/choose).
For security vulnerabilities, see [SECURITY.md](SECURITY.md) — do not open a
public issue.
