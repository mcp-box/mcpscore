# Agent instructions for mcpscore

- Run `make all` before handing off — it mirrors CI (lint, typecheck, tests + coverage).
  The gate is `uv run pyright mcpscore/` and `uv run ruff check` — inline IDE
  diagnostics may differ; the commands are authoritative.
- **`rule_id` is a stable public contract**: never rename or reuse one. New rules must
  cite the MCP spec section (or SEP) they enforce in their result `details`.
- **Rule lifecycle — three states, and the choice between them matters:**
  1. **Active** — runs everywhere.
  2. **Version-scoped** — set `min_spec_version`/`max_spec_version` when a rule is
     correct but only for some revisions. Use this for anything the spec removed
     or deprecated: the rule keeps its ID and still judges servers on the
     revisions where the requirement held. **Obsolescence is scoping, not deletion.**
  3. **Retired** — delete the rule *only when it was wrong* (it asserted something
     the spec does not require, or contradicted another rule), and add an entry to
     `mcpscore/rules/retired.py`. That registry generates the "Retired rules" table
     in `docs/rules.mdx`, so an old report or a stale CI waiver stays explainable.
     A retired ID is never reused — a test enforces it.
- Readiness rules (`group_name = "readiness"`) score on the readiness axis; since the
  1.1.0 promotion they ALSO count in the main score, but only for modern-lifecycle
  servers (era modern/dual-era) in full audits — never for legacy servers, never in
  partial audits (`readiness_promoted` in mcp_auditor.py is the single switch).
  Rules that cannot judge anything return a skip reason — they never fail a server
  for missing observations.
- **Probes must never invoke `tools/call`** against a target server — audits must be
  free of tool side effects. Probes never raise; network failures are
  `ProbeOutcome.ERROR` data. The ONE surface allowed to call tools is the opt-in
  `--smoke` mode (`smoke.py`, CLI-only): its results never enter the score, it never
  runs from probes/rules or the web service, and its safety default (readOnlyHint-only
  unless `--call-all`) must not be weakened.
- `docs/rules.mdx` is generated — edit `scripts/generate_rules_doc.py` and run
  `make docs-rules`, never the file itself. CI fails on drift.
- Docs are MDX served by Mintlify from `docs/` — pages need frontmatter; validate with
  `make docs-check`.
- For each new feature: update the docs and add a CHANGELOG entry (Keep a Changelog
  format). Docstrings: imperative first line, ≤120-char lines.
- Do not commit to `main`; work on a branch. Do not add strategy or planning documents
  to this repository — it is public.
- **`docs-live` is a deploy pointer, never a working branch — and never delete it**
  (nor `main`; both are deletion-protected by repository rulesets since 2026-08-27).
  Mintlify serves docs.mcpscore.dev from `docs-live`; `publish-docs.yml`
  force-pushes it to each stable release tag. Deleting it takes the docs site
  down; committing to it gets overwritten at the next release. Docs changes go
  through `main` like everything else and reach the site at the next release.

## Gotchas (learned the hard way)

- **Imports inside the package**: `reportImportCycles` is on, so `from mcpscore import spec`
  inside `mcpscore/rules/` is flagged as a cycle through `__init__.py` even though it runs.
  Import submodules directly (`from mcpscore.spec import ...`), matching the existing
  `from mcpscore.enums import ...` pattern.
- **Unit tests must stay hermetic**: any new network phase in `MCPAuditor.audit()` silently
  makes tests using `https://example.com` URLs hit the live network. Tripwire: a sudden
  pytest wall-time jump (0.6s → 5s+) is a network leak until proven otherwise. Fix pattern:
  autouse conftest fixture stubbing the runner at the consuming module's attribute
  (`monkeypatch.setattr(mcp_auditor, "run_all_probes", ...)`); tests needing real probe
  behavior re-patch or inject an `httpx.MockTransport` client.
- **`MagicMock(spec=SomeClass)` exposes only class-level attributes** — instance attributes
  assigned in `__init__` (e.g. `MCPAuditor.audit_data`) raise `AttributeError`; assign them
  on the mock explicitly. Corollary: adding a method to a spec'd class makes existing mocks
  auto-create it returning a truthy `MagicMock` — check tests whose behavior that flips.
- **Always pass `encoding="utf-8"`** to `read_text`/`write_text`/temp files — Windows
  defaults to the locale codepage and the 3-OS CI matrix exists to catch exactly this.
- **Rule details vs payload**: large payloads (tools lists, DiscoverResult) go in
  `ProbeResult.payload`, excluded from `to_dict()`. Spreading `**probe.details` into rule
  results puts everything in the JSON report — keep `details` small.
- **Spec citations**: don't trust secondary sources — the MCP blog's own RC summary was
  wrong twice vs the spec text, and error codes were renumbered after the RC lock. Cite the
  spec section each rule enforces and re-verify citations against the dated spec URL when a
  revision goes final.
- **Zero-behavior-change refactors need a live invariant**: re-audit the same live server
  (`uv run mcpscore https://mcp.deepwiki.com/mcp`) before and after; the score must be
  identical.
