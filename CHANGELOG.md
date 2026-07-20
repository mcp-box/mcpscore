# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0b2] - 2026-07-20

**Pre-release: auth-gated audits and new rules on the SDK v2 line.** Published
as a PyPI pre-release only (`uvx --prerelease=allow mcpscore==1.1.0b2 …`); plain
`pip install mcpscore` keeps resolving the stable 0.x line.

### Added

**Authenticated and partial audits of auth-gated servers** — production MCP
servers behind OAuth 2.x can now be audited:

- `--token <TOKEN>` sends `Authorization: Bearer <TOKEN>`; `--header 'Name: Value'`
  (repeatable) sends arbitrary headers for API-key or custom-auth servers. Both
  also read from the `MCPSCORE_TOKEN` environment variable (CI-friendly). Header
  and token values are never logged or written to the report — only an
  `authenticated` boolean is recorded.
- **Partial audit**: an auth-gated (HTTP 401/403) server audited *without* a
  token no longer exits with an error. Instead the observable surface — the
  auth-posture rules, TLS, and transport — is scored, session-dependent rules
  are skipped as `insufficient-data`, and the report is flagged `partial` (with
  `partial_reason`). A partial score is not comparable to a full audit's.
- Report gains `authenticated`, `partial`, and `partial_reason` fields.

**Auth-posture rules** — the first rules that score auth-gated servers (which
previously could not be audited at all). All observations are read-only; the
rules skip as not-applicable for servers that serve anonymous requests:

- New probe `probe_auth_metadata`: fetches RFC 9728 protected resource
  metadata from its well-known locations (path-aware form first, then
  origin root).
- `auth_www_authenticate` (Security, HIGH): 401 responses must carry a
  `WWW-Authenticate` challenge.
- `auth_protected_resource_metadata` (Security, HIGH): the RFC 9728 metadata
  document exists and its `resource` names this server.
- `auth_authorization_servers_https` (Security, HIGH): the metadata lists at
  least one authorization server and every entry uses HTTPS (skipped when the
  metadata document is absent — that is the previous rule's finding).

**Metadata completeness and consistency rules** (2025-11-25 fields; skipped
for servers on older spec revisions):

- `server_websiteurl_present` (Server Info, LOW): `serverInfo.websiteUrl`
  is present.
- `server_icons_present` (Server Info, LOW): the server declares icons and
  every icon `src` is an `https://` or `data:` URI.
- `tools_execution_consistent` (Tools, MEDIUM): tools declaring
  task-augmented execution (`execution.taskSupport` of `optional`/`required`)
  require the server to declare the `tasks` capability.

Spec citations for the auth rules reference the MCP Authorization spec and
RFC 9728; re-verify against the dated spec URL at the 2026-07-28 release.

## [1.1.0b1] - 2026-07-19

**Pre-release: engine migrated to MCP Python SDK v2 (beta).** Published as a
PyPI pre-release only — plain `pip install mcpscore` keeps resolving the stable
0.x line until SDK 2.0 goes stable. Audit output is unchanged: the same live
server audited before and after the migration produces an identical report
(score and all rule results).

### Changed

- Migrated from MCP Python SDK v1 to `mcp==2.0.0b2` (exact pin — SDK
  pre-releases may break each other, so each mcpscore beta pins the SDK beta it
  was verified against).
- HTTP stack switched from `httpx`/`httpx-sse` to `httpx2` (the SDK v2 HTTP
  client) for both the MCP transports and the readiness probes. TLS is now
  validated against the OS trust store (via `truststore`) instead of certifi's
  bundle.
- Report messages and details keep the MCP spec's wire field names (e.g.
  `listChanged`) even though SDK v2 renamed Python attributes to snake_case —
  the report schema is a public contract and does not follow SDK naming.

### Removed

- The `mcp>=1.28.1,<2` / `httpx>=0.28.1,<1` bounds added in 0.9.0 (this
  line tracks SDK v2 directly; the bounds remain correct for the stable 0.x
  line).

## [0.9.0] - 2026-07-19

### Changed

- Bounded runtime dependencies below their upcoming majors (`mcp>=1.28.1,<2`,
  `httpx>=0.28.1,<1`). MCP Python SDK 2.0 (a breaking rework that replaces
  `httpx` with the separate `httpx2` package) is expected to go stable alongside
  the 2026-07-28 spec release; without the bound, fresh installs would resolve to
  it and break. Migration to SDK v2 is planned separately.

## [0.8.0] - 2026-07-10

**Preview of MCP 2026-07-28 support.** This release audits servers on every spec
revision — including the upcoming stateless lifecycle — and reports how ready a
server is for the next revision. The 2026-07-28 spec is a release candidate until
2026-07-28: readiness rules target the RC and their details may change until the
revision is final.

### Added

**Multi-spec-version engine**

- `mcpscore.spec`: a registry of all MCP spec revisions (2024-11-05 → 2026-07-28
  draft) — lifecycle model, publication status, deprecated features, required
  request headers, JSON Schema dialect defaults. Adding a future revision is one
  registry entry; older revisions are never rewritten.
- Rules can declare the spec-version range they apply to
  (`min_spec_version`/`max_spec_version`); outside it they are **skipped** and
  excluded from both earned and maximum score — never failed. Skips appear in the
  report under `skipped_rules` with a reason (`not-applicable`,
  `insufficient-data`, or `requires-modern-support`) and the rule's group.
- Era detection: the report states whether the server was observed to be
  `legacy` (stateful), `modern` (stateless 2026-07-28), or `dual-era`, following
  the spec's own detection guidance.

**Sessionless probe layer**

- Nine read-only HTTP probes observe behavior outside the negotiated session
  (`server/discover`, stateless requests, `_meta` header validation, error-code
  shapes, unauthenticated behavior, session-ID echo, removed methods). Probes
  never invoke `tools/call` — an audit can never trigger tool side effects.
- Probe outcomes are data, never errors: network failures degrade the dependent
  rules to "could not verify" (skipped) instead of failing the server.

**2026-07-28 readiness pack (preview)** — 12 rules scored on an independent
readiness axis (`readiness.score`/`readiness.max_score` in the report), never
mixed into the main score. Includes two legacy-leakage checks that only run
against servers with modern support (`readiness_2026_no_session_id`,
`readiness_2026_removed_methods`). Every rule cites the SEP it enforces.

**Modern-only server support**

- If the legacy `initialize` handshake fails against an HTTP(S) target but the
  server answers 2026-style stateless requests, mcpscore audits it via probes
  (server info, capabilities, and tools extracted from `server/discover` and
  `tools/list` payloads) instead of reporting a connection failure. Exit code 2
  now means "no legacy *and* no modern support".

**Report and CLI**

- JSON report additions (all backward-compatible): `spec` block
  (negotiated/latest/readiness-target versions + era), `readiness` section
  (score, results, skipped count), `skipped_rules`, and `summary.skipped`
  (main-axis only, keeping the summary internally consistent).
- CLI output gains a readiness section separator, and a closing summary with the
  spec/era line and the separate readiness score.
- Documentation site (Mintlify): scoring methodology with per-rule spec
  citations, and a rules reference generated from the rule registry.

### Changed

- `protocol_version_latest` now passes for servers on a revision *newer* than
  the latest final one (e.g. the 2026-07-28 RC) instead of flagging them as
  behind.
- Protocol-version rules read allowed/deprecated/latest versions from the spec
  registry instead of hardcoded lists (no behavior change).
- New runtime dependency: `jsonschema>=4.21` (JSON Schema 2020-12 validation in
  the readiness pack).

### Known preview caveats

- `protocol_version_allowed` fails for servers speaking *only* the 2026-07-28
  draft (it is not a final revision yet); this resolves in 1.0.0 when the spec
  is published and the registry marks it current.
- Probes are HTTP(S)-only in this release; stdio servers get
  `insufficient-data` skips for probe-backed readiness rules.

## [0.7.0] - 2026-07-01

### Added

Five new spec-compliance / completeness rules (all backward-compatible; they
add to the maximum score, so servers are rewarded for more complete metadata):

- `tools_annotations_present` (Features, MEDIUM): tools should declare behavior
  annotations (`readOnlyHint`/`destructiveHint`/`idempotentHint`/`openWorldHint`)
  so clients can reason about a tool's effects. The display-only `title` hint
  does not count.
- `server_instructions_present` (Compliance, LOW): the server should provide
  `instructions` to help clients use it.
- `resources_description_present` (Compliance, MEDIUM): declared resources
  should have a description.
- `prompts_description_present` (Compliance, MEDIUM): declared prompts should
  have a description.
- `prompts_arguments_documented` (Compliance, LOW): every prompt argument
  should have a description.

Resources and prompts are optional capabilities, so their rules pass as
not-applicable when a server offers none — only the quality of what is actually
declared is graded.

## [0.6.0] - 2026-06-16

### Added

- `MCPClient.last_connection_error`: after a failed connect, exposes a
  `ConnectionFailure` describing *why* it failed — distinguishing an
  auth-gated server (HTTP 401/403) or other HTTP error from an unreachable
  host, a timeout, or a non-MCP endpoint, instead of a flat connection failure.
- `ConnectionFailure` (with an actionable `.message`) and the
  `ConnectionErrorReason` enum, both exported from `mcpscore`.
- Connection failures now recover the HTTP status buffered in the transport's
  teardown `ExceptionGroup`, so an authentication wall surfaces as "requires
  authentication (HTTP 401)" rather than "not a valid MCP server". When
  auto-detect tries multiple transports, the most informative failure is
  reported (e.g. a Streamable HTTP 401 over an SSE 405).

## [0.5.1] - 2026-06-13

- Added a [Mission doc](MISSION.md) to give more context for humans and agents.
- Minor fixes and improvements.

## [0.5.0] - 2026-06-11

### Added

- `--json` CLI flag: emits a machine-readable audit report to stdout
  (schema v1) with per-rule results, while logs go to stderr. Designed for
  CI pipelines and automated tooling.
- `RuleResult.rule_id`: results now carry the stable identifier of the rule
  that produced them (stamped by the auditor), plus `RuleResult.to_dict()`
  for serialization.
- `MCPAuditor.get_audit_report()`: returns the full audit
  (score, max_score, summary, per-rule results) as a dictionary.

### Changed

- The CLI now uses argparse: `mcpscore --help` works, and usage errors keep
  exit code 1 (exit code 2 remains reserved for connection failures).
- `get_audit_summary()`'s `by_severity` breakdown is keyed by severity name
  (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) instead of numeric value, matching
  its documented behavior.
- CLI logging is explicitly directed to stderr, keeping stdout clean for
  `--json` output.

## [0.4.0] - 2026-06-10

### Added

- MCP `initialize` handshake verification during connect: a connection now only
  counts as established once the server completes the MCP handshake. Plain
  HTTPS endpoints that are not MCP servers are rejected with
  "Not a valid MCP server (handshake failed)" instead of a false success.
- `MCPClient.initialize()` returns the handshake result cached at connect time
  instead of re-initializing the session.
- TLS version probing: the auditor now reports the actually negotiated TLS
  version (e.g. `TLSv1.3`) instead of a hardcoded value.
- `CapabilityToolsPresentRule`, `ToolsNamesUniqueRule`, and
  `ToolsNamesValidFormatRule` are now exported from `mcpscore.rules`.

### Changed

- **Python 3.11+ is now supported** (previously 3.13+ only). CI tests against
  3.11, 3.12, and 3.13 on Linux, macOS, and Windows.
- `SSETransportSupportRule` replaced by `StreamableHTTPTransportRule`: the MCP
  specification deprecated standalone SSE in favor of Streamable HTTP, so the
  rule now rewards Streamable HTTP and flags SSE-only servers with migration
  advice (previously it did the opposite).
- Tool schema validation aligned with the MCP specification / JSON Schema:
  `title`, `properties`, and `required` are optional (zero-argument tools are
  valid), top-level `anyOf`/`oneOf`/`allOf`/`$ref` schemas are accepted, and
  properties without a `type` (enum/`$ref`) are valid.
- `outputSchema` is optional per the MCP specification: tools without one are
  no longer penalized; only declared output schemas are validated.
- `AuditData.transport_type` is typed as `MCPTransportType | None`
  (previously `str | None`).

### Fixed

- Failed connection attempts are torn down immediately on their own exit
  stack; previously they leaked into the client lifecycle and could re-raise
  buffered transport errors during `cleanup()`.
- A `CancelledError` leaked by the MCP SDK transport's task group (e.g. when
  the endpoint is not an MCP server) is treated as a failed connection
  instead of escaping to the caller.
- The CLI now always calls `client.cleanup()`, including when the audit
  raises (previously connections leaked on error paths).

## [0.3.0] - 2026-06-08

### Added

- First public release on [PyPI](https://pypi.org/project/mcpscore/).
- Streamable HTTP and SSE transports with automatic transport detection
  (in addition to STDIO for local servers).
- Security rules: TLS enabled, malformed request handling, error data leaks.
- Transport rule: SSE transport support detection.
- Tools rules: unique names and valid name format checks.

[Unreleased]: https://github.com/mcp-box/mcpscore/compare/v1.1.0b2...HEAD
[1.1.0b2]: https://github.com/mcp-box/mcpscore/compare/v1.1.0b1...v1.1.0b2
[1.1.0b1]: https://github.com/mcp-box/mcpscore/compare/v0.9.0...v1.1.0b1
[0.9.0]: https://github.com/mcp-box/mcpscore/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/mcp-box/mcpscore/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/mcp-box/mcpscore/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/mcp-box/mcpscore/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/mcp-box/mcpscore/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/mcp-box/mcpscore/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/mcp-box/mcpscore/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/mcp-box/mcpscore/releases/tag/v0.3.0
