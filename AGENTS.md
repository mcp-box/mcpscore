# Agent instructions for mcpscore

- Run `make all` before handing off — it mirrors CI (lint, typecheck, tests + coverage).
  The gate is `uv run pyright mcpscore/` and `uv run ruff check` — inline IDE
  diagnostics may differ; the commands are authoritative.
- **`rule_id` is a stable public contract**: never rename or reuse one. New rules must
  cite the MCP spec section (or SEP) they enforce in their result `details`.
- Readiness rules (`group_name = "readiness"`) score on the readiness axis; since the
  1.1.0 promotion they ALSO count in the main score, but only for modern-lifecycle
  servers (era modern/dual-era) in full audits — never for legacy servers, never in
  partial audits (`readiness_promoted` in mcp_auditor.py is the single switch).
  Rules that cannot judge anything return a skip reason — they never fail a server
  for missing observations.
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
