# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-06-19

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

[Unreleased]: https://github.com/mcp-box/mcpscore/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/mcp-box/mcpscore/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/mcp-box/mcpscore/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/mcp-box/mcpscore/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/mcp-box/mcpscore/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/mcp-box/mcpscore/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/mcp-box/mcpscore/releases/tag/v0.3.0
