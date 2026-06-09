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
make testcov        # Tests with coverage report (95% minimum enforced)
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
3. Export it from `mcpscore/rules/__init__.py` (import + `__all__`).
4. Add tests covering the pass path, the fail path, and any
   not-applicable path (e.g. stdio transport).
5. Document it in the README's "What it audits" section and in
   `CHANGELOG.md` under `[Unreleased]`.

Severity weights: CRITICAL = 5, HIGH = 3, MEDIUM = 2, LOW = 1. Choose based
on how strongly the MCP specification mandates the behavior — spec
violations are CRITICAL/HIGH, recommendations are MEDIUM/LOW.

## Pull request expectations

- Keep PRs focused; separate refactors from behavior changes.
- New code needs tests — coverage must stay at or above 95%.
- Public functions and classes carry type hints and docstrings.
- Update `CHANGELOG.md` under `[Unreleased]`.
- Formatting is automated (`make format`); style debates are out of scope.

## Reporting bugs and requesting features

Use the [issue templates](https://github.com/mcp-box/mcpscore/issues/new/choose).
For security vulnerabilities, see [SECURITY.md](SECURITY.md) — do not open a
public issue.
