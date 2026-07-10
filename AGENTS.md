# Agent instructions for mcpscore

- Run `make all` before handing off — it mirrors CI (lint, typecheck, tests + coverage).
  The gate is `uv run pyright mcpscore/` and `uv run ruff check` — inline IDE
  diagnostics may differ; the commands are authoritative.
- **`rule_id` is a stable public contract**: never rename or reuse one. New rules must
  cite the MCP spec section (or SEP) they enforce in their result `details`.
- Readiness rules (`group_name = "readiness"`) score on a separate axis and must never
  affect the main score. Rules that cannot judge anything return a skip reason —
  they never fail a server for missing observations.
- **Probes must never invoke `tools/call`** against a target server — audits must be
  free of tool side effects. Probes never raise; network failures are
  `ProbeOutcome.ERROR` data.
- `docs/rules.mdx` is generated — edit `scripts/generate_rules_doc.py` and run
  `make docs-rules`, never the file itself. CI fails on drift.
- Docs are MDX served by Mintlify from `docs/` — pages need frontmatter; validate with
  `make docs-check`.
- For each new feature: update the docs and add a CHANGELOG entry (Keep a Changelog
  format). Docstrings: imperative first line, ≤120-char lines.
- Do not commit to `main`; work on a branch. Do not add strategy or planning documents
  to this repository — it is public.
