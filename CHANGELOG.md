# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Three modern Streamable HTTP readiness rules validate security and
  interoperability without invoking tools: invalid foreign `Origin` values must
  receive HTTP 403 (`readiness_2026_origin_validation`), unknown RPC methods
  must receive HTTP 404 with JSON-RPC `-32601`
  (`readiness_2026_unknown_method_error`), and successful requests must return
  `application/json` or `text/event-stream`
  (`readiness_2026_response_content_type`). All three are HIGH. The Origin
  requirement is a spec MUST, and its weight depends on the target: for a
  locally-bound or plain-`http://` server it is the direct DNS-rebinding
  mitigation, while for a remote HTTPS server it is defence in depth. HIGH is a
  single level covering both. The content-type rule reuses existing successful probe
  observations; the other two probes use harmless `tools/list` and invented
  method requests. Network failures and non-HTTP transports skip rather than
  fail.

  Both security probes judge only what they can actually observe. The `Origin`
  probe first sends a control request *without* the foreign header: a lone HTTP
  403 does not prove Origin validation, because 403 is also how an
  access-controlled server refuses everyone, so the check reports
  `not-applicable` unless the control shows the same request would otherwise be
  accepted. The unknown-method probe reports `not-applicable` on 401/403 for the
  same reason — a request that never reached method dispatch says nothing about
  how the server answers an unknown method, and auth-gated servers are healthy.

## [1.5.0] - 2026-08-05

Correctness release, driven by what real servers exposed. Modern-lifecycle
servers now have their identity read from the spec's location (they had none
before, costing five checks each), one failed `tools/list` no longer cascades
into failures across the whole tools pack, and auth-gated servers whose 401
arrives as a status-less SDK error are auditable instead of unreachable.
Reports gain `server_info`; `outputSchema` root types are judged per spec
revision. 81 rules.

### Fixed

- Modern-lifecycle servers now report their identity. `server/discover`
  carries `serverInfo` in the result's `_meta`
  (`io.modelcontextprotocol/serverInfo`) — 2026-07-28 removed the top-level
  field entirely — but the auditor only read the legacy top-level key, so
  every spec-compliant modern server was audited with no server identity at
  all (`server_info` rules judging absent data, and the new `server_info`
  report field always `null`). The `_meta` location is now read first, with
  the legacy top-level key kept as a deliberate fallback for servers that
  mirror the `initialize` shape, and a malformed value at the spec location
  no longer shadows a usable legacy one. Every fixture simulating a
  `server/discover` response emitted the legacy shape too — the modern-only
  and probe unit tests here, and the modern and auth fixtures in the
  acceptance corpus — which is why nothing caught it; all are now
  spec-accurate.

- Tool-quality rules now skip as `insufficient-data` when a server declares
  the tools capability but `tools/list` produces no usable catalog. The
  capability-consistency rule remains the single failure for that broken
  promise, instead of one collection failure cascading across all 16 tools
  rules. On the current specification, the 15 applicable rules represent 45
  severity-weight points — roughly 30 percentage points in the full score.
  Registry dry-run 2026-08-03: 2/436 sampled servers (about 0.5%) had this
  state.
- Auth-gated Streamable HTTP servers whose 401 surfaces as a status-less SDK
  error (e.g. Airtable, whose body parses as a JSON-RPC error) are now
  classified as `UNAUTHORIZED` via a single status-recovery
  POST, instead of falling through to the legacy SSE transport and reporting
  its `405 Method Not Allowed` as the failure. On any 401/403 the SSE
  fallback is skipped entirely and the expected challenge is logged as an
  info line, not a traceback — the credential-free partial audit runs as it
  should. Genuine SSE fallback is preserved for non-auth HTTP failures.

### Added

- JSON reports now include `server_info` with the server-reported `name` and
  `version` (or `null` when unavailable), allowing baselines to distinguish a
  server release change from an mcpscore engine release change and providing
  the live identity needed for future Server Card consistency checks.
- New HIGH version-scoped rule `tools_output_schema_root_object`: on
  revisions 2025-06-18 through 2025-11-25 the schema restricts `outputSchema`
  to `type: "object"` at the root (any-root schemas became legal in
  2026-07-28) — a non-object root on a legacy negotiation breaks clients
  that compile declared schemas relying on that guarantee. Registry dry-run
  2026-08-03: 143/436 sampled servers declare output schemas, zero violate —
  pure forward protection as 2026-07-28 adoption spreads.

### Changed

- `tools_output_schema_valid` no longer requires an object root: from
  2026-07-28 an output schema "can be any valid JSON Schema 2020-12", so a
  modern server declaring an array-rooted schema was a false positive (input
  schemas keep the object-root requirement — that literal persists in every
  revision). The object-root question for 2025-06-18..2025-11-25 now belongs
  exclusively to the new version-scoped rule, so one condition is never
  penalized twice.

## [1.4.0] - 2026-08-03

Catalog polish release: eight new rules — icon validation across all four
catalog surfaces (tools, resources, resource templates, prompts) with strict
URI/data-URI checking, plus resource-template quality checks (MIME types,
annotations, descriptions, display titles) that bring templates to parity
with the resources catalog. 80 rules total.

### Added

- A LOW resource-template quality rule recommends human-readable display
  titles for MCP 2025-06-18+ catalogs.
- Three resource-template quality rules validate declared MIME types and
  annotations, and recommend descriptions that help clients and models
  understand parameterized resources.
- Four MCP 2025-11-25+ catalog rules validate icon source URIs, optional MIME
  types, and optional size tokens consistently across resources, resource
  templates, prompts, and tools. Diagnostics identify only the catalog item
  and icon index, keeping large embedded `data:` payloads out of audit
  reports.

## [1.3.0] - 2026-08-02

Any-language release: local MCP servers in Go, Java, C#, Rust — any runtime —
can now be audited over stdio via `--stdio`, with secret-safe `--env`
configuration. Plus resource-template collection with three new catalog
rules, a new readiness rule for `supportedVersions`, and a tightened
unsupported-version error check.

### Added

- **`--stdio`: audit local MCP servers written in any language.** The flag
  launches an arbitrary stdio command — a compiled Go binary,
  `java -jar server.jar`, `dotnet run --project …` — and audits it exactly
  like a `.py`/`.js` target. It consumes the rest of the command line (the
  server's own flags included), runs the command directly with no shell, and
  pairs with the new repeatable `--env` for server configuration
  (merged over the SDK's minimal default environment; values are never
  logged or reported). `--env NAME=VALUE` sets a value inline for
  non-sensitive config; the value-less `--env NAME` copies the value from
  mcpscore's own environment, keeping secrets off every command line. Library
  consumers get the same via the new `StdioCommand`
  dataclass accepted by `MCPClient.detect_and_connect`. The positional
  `.py`/`.js`/URL target is unchanged.

- Collect and fully paginate MCP resource templates, preserving partial evidence
  and reporting incomplete listings when pagination fails, loops, or exceeds its
  safety bound.
- Three resource-template rules validate RFC 6570 URI-template syntax, unique
  `uriTemplate` identifiers, and non-blank names without reading resources or
  invoking tools.
- New HIGH readiness rule `readiness_2026_supported_versions`: a
  `server/discover` DiscoverResult must name at least one supported protocol
  version (all strings) — the schema requires `supportedVersions: string[]`
  but has no minItems constraint, and an empty list makes version selection
  impossible.

### Changed

- `readiness_2026_unsupported_version_error` now requires the full
  `UnsupportedProtocolVersionError` shape, not just the -32022 code: the
  error's `data` must carry `supported` (a non-empty list of version strings
  to retry with) and `requested`, as the schema requires. A bare -32022 now
  fails with a dedicated message. Era detection is unaffected: the -32022
  code alone still counts as modern-era evidence.

## [1.2.0] - 2026-07-31

Catalog-quality release: sixteen new rules across tools, resources, and
prompts — each validated against the live registry corpus with dedicated
dry-run sweeps before shipping — plus complete pagination of MCP listings
and a rebalance of the tool-title rule.

### Added

- Three resource-catalog rules validate absolute resource URIs, non-blank
  resource names, and non-negative declared byte sizes.
- Four catalog-validation rules check resource MIME types and annotations, plus
  unique and non-blank argument names within prompts.
- Four MCP 2026 tool-schema rules validate `x-mcp-header` names, uniqueness,
  primitive parameter types, and static reachability without invoking tools.
- Two uniqueness rules verify that resource URIs and prompt names remain unique
  across their complete paginated listings.
- Three catalog-usability rules recommend display titles for resources and
  prompts, and descriptions for statically reachable tool input properties.
- Complete paginated collection for tools, resources, and prompts, with cursor
  loop detection and a page safety bound. Listings that could not be fetched
  completely are reported in a new top-level `incomplete_listings` field, and
  uniqueness rules (including the existing `tools_names_unique`) skip as
  insufficient-data instead of judging a partial catalog.

### Changed

- `tools_title_present_in_all` is downgraded HIGH → LOW and scoped to spec
  revisions that define `title` (2025-06-18 and later): the field is optional
  with a spec-defined display fallback to `name`, a registry sweep showed half
  the ecosystem omits it, and servers on earlier revisions cannot declare it
  at all. Aligns with the new resource and prompt title rules. The check now
  also counts missing and whitespace-only titles — previously only a literal
  empty string failed, so absent titles passed silently.

### Fixed

- **The local lint gate now runs the same hooks, at the same versions, as CI.**
  `make lint` used the venv's ruff (floating `>=0.15.20`, resolving to 0.16.0)
  while CI lints through pre-commit, pinned at 0.14.8 — so the two could not
  agree. The gap was not theoretical: 0.14.8 requires a `# noqa: S310` on a
  `urllib.request.Request(...)` line that 0.16.0 reports as an *unused* noqa
  and `ruff --fix` silently deletes. The local gate went green having removed
  exactly what CI demanded. Both are now pinned to 0.16.0 (`.pre-commit-config.yaml`
  and an exact `ruff==` dev dependency, with a comment tying them together),
  and `make lint` runs `pre-commit run --all-files` before its own working-tree
  pass — the hooks catch what CI enforces, the ruff calls catch untracked files
  the hooks cannot see.

- **The release script now waits for the index resolvers actually use.** It
  polled `pypi.org/pypi/mcpscore/<version>/json`, which turns green before the
  *simple index* has propagated — so 1.1.1 printed its smoke test while `uvx`
  still reported "there is no version of mcpscore==1.1.1" for a release that
  was already published. It now additionally waits until
  `pypi.org/simple/mcpscore/` serves the version's files.

## [1.1.1] - 2026-07-29

Follow-up to the 1.1.0 launch release, driven by a full sweep of the 9,723
auditable endpoints in the official MCP registry.

### Added

- **A registry of retired rule IDs** (`mcpscore/rules/retired.py`), rendered as a
  "Retired rules" table in the [rules reference](https://docs.mcpscore.dev/rules/).
  A `rule_id` is a public contract — it appears in stored reports and in CI
  configuration that waives specific rules — so an ID that stops running now has
  a permanent record of when it went and why, instead of silently vanishing from
  the docs. Retired IDs are never reused; a test enforces both that and the
  registry matching the live rule set.

  The accompanying policy (`AGENTS.md`): a rule is retired only when it was
  *wrong*. A rule that is correct but applies to particular spec revisions keeps
  its ID and gains a `min_spec_version`/`max_spec_version` range instead —
  obsolescence is scoping, not deletion.

### Changed

- **The `listChanged` advisories no longer judge features a server does not
  offer.** `capability_prompts_list_changed` and `capability_resources_list_changed`
  failed servers with no prompts or resources at all — 2,798 and 2,582 servers
  respectively in the registry sweep. They now skip as `not-applicable` when
  the capability is absent, and still apply where the feature exists (a server
  with tools that does not announce tool-list changes is still advised). Median
  effect: +0.9 points, 54% of servers.

### Fixed

- **Auth-gated servers that refuse the legacy handshake now get their partial
  audit.** The partial branch only triggered when the *session* ended in
  401/403; a server with no legacy endpoint fails the handshake on something
  else (405 from the SSE fallback is the common shape), so the probes' 401
  observation — and the RFC 9728 metadata already fetched — were discarded and
  the CLI reported "Error connecting". The 2026-07-29 registry sweep put a
  number on it: **708 of 9,723 servers, 29% of all gated servers**. The engine
  now keeps the probe observations when the modern-only attempt declines and
  decides on that evidence; re-running those 708 produced **703 partial
  audits** (mean auth posture 84.4%), the other 5 being genuinely unreachable.
  The reported status is the gate's (401), not whatever ended the session.

- **The release script's smoke test now refreshes uv's package cache.** It
  printed `uvx mcpscore==<version> …`, which fails with "your requirements are
  unsatisfiable" on any machine that had resolved mcpscore before: uv caches the
  PyPI index, so a version published seconds earlier is invisible to it. The
  hint now passes `--refresh-package mcpscore`. Also notes that `npx
  @mcp-box/mcpscore@<version>` delegates to `uvx` and shares the same cache.

## [1.1.0] - 2026-07-28

First stable release. Ships the day the MCP `2026-07-28` revision went final.

### Added

- **`2026-07-28` is now a recognized protocol version** (`MCPProtocolVersion.v2026_07_28`,
  and `MCPProtocolVersion.Latest` now points at it).

### Changed

- **Pinned to the MCP Python SDK `2.0.0` stable** (from `2.0.0rc1`), published
  2026-07-28 alongside the spec revision it implements. The SDK's own notes
  report no API changes between rc1 and stable — the breaking changes all
  landed earlier in the pre-release cycle, and the two we had already absorbed
  (`OAuthClientProvider(timeout=…)` removal, `httpx2`) are unaffected.

  Verified: the full gate passes, and DeepWiki scores **82/90 on both pins with
  byte-identical per-rule results** (all 32 main rules plus all 12 readiness
  rules compared individually, not just the total). The auth-gated path was
  re-checked too — Linear still returns a 25/25 partial audit with all 8
  auth-posture rules scored.

- **The 2026-07-28 revision went final on 2026-07-28 and the spec registry
  flipped with it**: `2026-07-28` DRAFT → CURRENT, `2025-11-25` CURRENT →
  SUPERSEDED. Two consequences:

  - **Fixes a CRITICAL false positive.** `allowed_versions()` deliberately
    excludes draft revisions, so while `2026-07-28` was a draft, a server
    correctly speaking the new revision failed `protocol_version_allowed`
    (CRITICAL, −5). Our own modern-lifecycle fixture was failing it.
  - `protocol_version_latest` (MEDIUM) now expects `2026-07-28`, so servers
    still negotiating `2025-11-25` are marked as behind — accurate, and the
    point of the rule, but it moves every legacy server's score by 2.

- **All spec facts re-verified against the dated final URLs** on publication
  day: changelog and SEP attributions, the Streamable HTTP request-header
  table (`MCP-Protocol-Version` on every POST; `Mcp-Method` on all requests;
  `Mcp-Name` on `tools/call`/`resources/read`/`prompts/get`), the error-code
  allocation policy (`-32020`/`-32021`/`-32022`) and the deprecated-features
  registry (Roots, Sampling, Logging, DCR, `includeContext`, HTTP+SSE). **No
  fact changed from the release candidate** — the RC-era entry was correct.

- **The capability-presence rules now check declared-vs-served consistency**
  instead of demanding every capability. `capability_tools_present`,
  `capability_prompts_present` and `capability_resources_present` cited "servers
  that support X MUST declare the X capability" while failing servers that
  simply do not offer X — penalizing a tools-only server (the median MCP
  server) 10 CRITICAL points for a legitimate design choice. They now compare
  the declaration against what the listing actually returns:

  | declared | served                 | verdict                                                                      |
  |----------|------------------------|------------------------------------------------------------------------------|
  | yes      | yes (incl. empty)      | ✅ pass                                                                       |
  | no       | no                     | ✅ pass — the capability is only required of servers that support the feature |
  | no       | yes                    | ❌ fail — the real spec MUST                                                  |
  | yes      | listing did not answer | ❌ fail — clients will call it and fail                                       |

  Severity stays CRITICAL, because what remains is a genuine MUST violation.

  **These rules only judge a listing the auditor actually attempted.** `tools`,
  `resources` and `prompts` being `None` is ambiguous — the session path lists a
  feature only when the server declares it, and `audit_modern_only` collects
  tools alone from the stateless probe. A rule whose listing never ran now
  skips as `insufficient-data` (see `AuditData.listings_attempted`) instead of
  reading silence as a failed listing, which had cost a modern server declaring
  resources and prompts 10 CRITICAL points (verified on a fixture: 103/123
  before, 103/113 after). On the modern path the attempt is recorded on the
  server's *answer*, not on a usable one — a server that declares tools and
  then fails `tools/list` fails the rule rather than skipping it, while an
  unobservable probe (network error) still skips. The trade-off is stated in
  the rule docstring: serving a feature without declaring it is only caught
  when the listing ran for another reason.

- **`listChanged` rules downgraded from HIGH to LOW** and relabelled as
  advisory. 2025-11-25 §Capabilities: *"Both `subscribe` and `listChanged` are
  optional — servers can support neither, either, or both."* The signal is
  worth keeping (an agent silently works from a stale list without it) but it
  is an mcpscore recommendation, and the `basis` now says so rather than citing
  a spec section that says the opposite.

  Net effect on live servers: DeepWiki 90/101 → 84/90 (89.1% → 93.3%),
  Context7 88/101 → 86/90 (87.1% → 95.6%), mcp-docs 84/101 → 85/90
  (83.2% → 94.4%). Rule count is unchanged at 52; `max_score` falls because
  optional features no longer carry required-level weight.

### Changed

- **Coverage floor raised to 97%, and Codecov now has an explicit config.**
  `fail_under` in `pyproject.toml` and both Codecov statuses (project and
  patch) are pinned to the same 97%, so the local gate and the PR checks fail
  together. Codecov previously used its "auto" target — the base commit's
  coverage — which failed a PR at 98.71% patch against a 98.84% base while the
  project sat above 99%.

### Removed

- **Retired `capability_resources_subscribe` (HIGH) and
  `capability_logging_present` (MEDIUM).** Both scored the *absence* of a
  capability the spec section they cited calls optional — *"Both `subscribe`
  and `listChanged` are optional: servers can support neither, either, or
  both"* (2025-11-25 Resources §Capabilities) — and the 2026-07-28 revision
  goes further: [SEP-2575][sep-2575] removes `resources/subscribe` in favour of
  `subscriptions/listen`, and [SEP-2577][sep-2577] deprecates Logging.

  `capability_logging_present` also contradicted `readiness_2026_deprecated_features`,
  which fails a server for *declaring* `logging`. With readiness promoted into
  the main score for modern and dual-era servers, **no server could pass both**:
  every server in the acceptance corpus failed one or the other.

  Scores are unaffected for servers that already passed these rules; every other
  server gains up to 5 points as `max_score` drops by the same amount. The
  audit now has **52 rules** (40 main + 12 readiness). Both `rule_id`s are
  retired permanently and will never be reused.

### Fixed

- **Corrected two swapped SEP citations.** `server/discover` is introduced by
  [SEP-2575][sep-2575], not SEP-2567 ("Sessionless MCP via Explicit State
  Handles", which explicitly does not introduce it); the removal of
  protocol-level sessions and `Mcp-Session-Id` is [SEP-2567][sep-2567], not
  SEP-2575. The `readiness_2026_server_discover` and
  `readiness_2026_no_session_id` rules reported each other's SEP in their
  message and `details.sep`.
- **`readiness_2026_no_session_id` no longer overstates the requirement.** The
  spec's backward-compatibility section is SHOULD-level ("ignore it, and do not
  mint or echo session IDs"); the message said "must".

[sep-2567]: https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2567
[sep-2575]: https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2575
[sep-2577]: https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2577

## [1.1.0rc1] - 2026-07-27

### Changed

- **Upgraded to MCP Python SDK `2.0.0rc1`** (from `2.0.0b2`). The engine's live
  invariant is unchanged — DeepWiki still scores 90/101 across the same 34
  rules — and the full suite passes on the new pin.
- **Dropped the `timeout=` argument to `OAuthClientProvider`**, which
  `2.0.0rc1` removed from its signature (it also gained `client_metadata_url`
  and `validate_resource_url`). No behaviour change: the browser step was
  already bounded by our own `callback_handler`, which waits on
  `wait_for_callback(flow_timeout_s)` and raises `OAuthFlowError` with our
  message. The SDK argument had been redundant.

- **The CLI welcome line is now `Welcome to mcpscore!`** (lowercase wordmark).
  The brand guidelines spell the name as one lowercase word everywhere, and
  spell this string out verbatim; the CLI was the last place saying "MCPScore".
  The PyPI and npm summaries now both use the guidelines' per-surface copy —
  they had drifted into three different descriptions of the same tool.

### Fixed

- **The auth-gated connection messages no longer claim mcpscore cannot audit
  gated servers.** Both read "MCPScore can only audit publicly accessible
  servers", which stopped being true in 1.1.0b2 when credential-free partial
  audits landed — and it is the text a consumer surfaces when it reports the
  connection failure. They now state the observation only (`The MCP server
  requires authentication (HTTP 401).`); the actionable hint belongs to the
  caller, which knows whether it can carry credentials at all.

## [1.1.0b6] - 2026-07-25

### Added

- **`mcpscore --version`.** It prints `mcpscore <version>` and exits 0 without
  requiring a target, so identifying an installed build no longer means running
  an audit or reading `--json` output. The greeting banner moved after argument
  parsing, so `--version` and `--help` are no longer preceded by it — the
  version line is the only thing written, and scripts can parse it.

### Fixed

- **`auth_challenge_references_metadata` now accepts an unquoted
  `resource_metadata` value.** RFC 7235 §2.1 defines an auth-param value as
  `token / quoted-string`, and a URL contains `:` and `/` — delimiters that are
  not valid `token` characters — so strictly the value must be quoted.
  Deployed servers send it bare anyway (verified against Stripe's MCP endpoint,
  2026-07-25) and clients read it without trouble, so failing the rule reported
  a discovery failure no real client experiences. The parser now reads both
  forms, ending a bare value at the next comma or whitespace. Two related
  corrections in the same parser: parameter names are matched
  case-insensitively (RFC 7235 §2.1), and a name is matched only at a parameter
  boundary, so `xresource_metadata=` is no longer mistaken for
  `resource_metadata=`.

## [1.1.0b5] - 2026-07-25

### Fixed

- **An unreachable authorization server no longer voids the protected-resource
  findings.** The RFC 8414 discovery walk leaves the audited server's origin
  for the authorization server's, and a transport failure there (DNS, refused
  connection, timeout, TLS) propagated out of the auth-metadata probe and
  discarded the RFC 9728 metadata already collected. Six auth rules
  (`auth_protected_resource_metadata`, `auth_authorization_servers_https`,
  `auth_metadata_https`, `auth_scopes_advertised`,
  `auth_server_metadata_present`, `auth_server_metadata_pkce`) then skipped as
  insufficient-data, shrinking `max_score` — so a server advertising a *bogus*
  authorization server scored more leniently than one advertising a working
  one, and `auth_server_metadata_present` skipped itself out of the very score
  it exists to enforce. The walk now records the failure in
  `auth_server_metadata_error` and leaves `auth_server_metadata_present` false,
  keeping the protected-resource findings intact. This covers unusable issuer
  URLs too (an invalid IPv4 literal, a bare IPv6 host): `authorization_servers`
  is server-controlled and only scheme-checked, and those raise `InvalidURL`,
  which does not derive from `HTTPError` — so advertising a malformed issuer
  was a way for a server to skip those six rules out of its own `max_score`.
- A transport error on one RFC 9728 well-known location no longer aborts the
  discovery of the next. When *every* location fails to connect the probe still
  reports `ERROR` (unverified) rather than `UNSUPPORTED` — an unreachable host
  is not evidence that a server publishes no metadata, so the dependent rules
  skip instead of failing it. Locations that could not be contacted are listed
  in the probe's `unreachable_locations`, and the `ERROR` outcome now keeps the
  context it collected (`urls_tried`) instead of reporting the exception alone.
- `auth_server_metadata_error` is now recorded only when *no* authorization-server
  location could be contacted. An issuer answering one location with a 404 is
  reachable and simply publishes nothing there; it previously kept an earlier
  candidate's transport error, misreporting it as unreachable.

## [1.1.0b4] - 2026-07-25

### Added

- **`--oauth`: interactive browser OAuth flow.** mcpscore discovers the
  server's authorization server (RFC 9728 → RFC 8414), registers a client
  dynamically (RFC 7591), opens the browser for the authorization-code +
  PKCE grant, catches the redirect on a loopback listener, and audits with
  the obtained token — which is held in memory only, never written to disk,
  never logged. For authorization servers without dynamic client
  registration (e.g. GitHub's), `--oauth --client-id <id>` uses a
  pre-registered client instead; the failure message suggests this when
  registration is unavailable. `--callback-port` pins the loopback redirect
  port for authorization servers that (against RFC 8252) require the exact
  pre-registered redirect URI.

- **Stability contract published** (`docs/stability.mdx`): what is stable
  from 1.1.0 on (`rule_id` never renamed/reused, report schema versioned via
  `schema_version`, CLI flags and exit codes, credentials never in
  logs/reports) and what evolves by design (the score is ruleset-dependent;
  messages/details/severities may improve in any release).

- **Readiness promotion for modern-lifecycle servers.** A server that
  negotiates the 2026-07-28 lifecycle (era `modern` or `dual-era`) now has
  its readiness points counted in the main score; the readiness block stays
  populated as the breakdown and gains a `counted_in_main` flag. Legacy-only
  servers are unchanged (readiness stays informative), and partial audits
  are never promoted. This is the score migration the methodology doc
  promised for spec-final; every `rule_id` is unchanged.

- **Every rule now cites its primary source.** All 34 rules that predated the
  citation policy carry a `basis` in their result `details` — the MCP
  2025-11-25 spec section (or, where the spec is silent, the best-practice
  basis, labeled as such) verified against the published spec text. The
  readiness rules keep their `sep` citations and the auth rules their RFC
  sections, so every one of the 55 checks now names what it enforces.
  Enforced by a registry test so future rules cannot ship uncited.

## [1.1.0b3] - 2026-07-22

**Pre-release: deeper auth-posture rules on the SDK v2 line.** Published as a
PyPI pre-release only (`uvx --prerelease=allow mcpscore==1.1.0b3 …`); plain
`pip install mcpscore` keeps resolving the stable 0.x line.

### Added

**Deeper auth-posture rules** — the auth-discovery probe now follows the chain
from the RFC 9728 protected-resource metadata to the first authorization
server's RFC 8414 metadata, enabling five new credential-free rules that score
a gated server's authorization surface:

- `auth_server_metadata_pkce` (Security, HIGH): the authorization server
  advertises PKCE with S256 (`code_challenge_methods_supported`), as required
  by the OAuth security BCP (RFC 9700) and the MCP authorization spec.
- `auth_server_metadata_present` (Security, HIGH): the authorization server's
  RFC 8414 metadata is reachable and advertises the authorization and token
  endpoints (OpenID `/.well-known/openid-configuration` is accepted as a
  fallback location).
- `auth_challenge_references_metadata` (Security, MEDIUM): the 401
  `WWW-Authenticate` header carries a `resource_metadata` parameter that points
  at the protected-resource metadata (RFC 9728 §5.1).
- `auth_metadata_https` (Security, MEDIUM): the protected-resource metadata URL
  and its `resource` identifier use HTTPS.
- `auth_scopes_advertised` (Security, LOW): the metadata advertises
  `scopes_supported` so clients can request least privilege.

Like the existing auth-posture rules, all five run credential-free (including
in a partial audit of a gated server) and skip rather than fail when the
document they need is unreachable, avoiding double-counting one defect.

### Fixed

- **Anonymous probes no longer carry any caller-supplied headers.** The
  unauthenticated-behavior probe and the auth-metadata discovery fetches now
  run on a separate HTTP client with none of the `--header` values (previously
  only `Authorization` was stripped): a non-Authorization credential such as an
  API key or cookie could defeat the unauthenticated observation, and RFC 8414
  discovery can leave the server's origin for the authorization server's — no
  caller credential belongs on those requests.
- A malformed `--header` value (e.g. a missing colon) is no longer echoed in
  the error message, which is logged — the value may be a mistyped secret. The
  error now identifies the bad argument by position (`--header #2: …`).
- The "custom header(s)" log line no longer says "for authentication" —
  `--header` is also valid for non-auth headers.
- The report's `authenticated` flag is now set only when an Authorization
  credential was sent (`--token` or an explicit `Authorization` header) —
  previously any custom header marked the audit authenticated.
- The auth-posture rules' `details["basis"]` now carries a per-rule,
  section-level citation (e.g. `RFC 9728 §5.1`) instead of one broad string
  shared across rules, matching the readiness rules' per-rule SEP citations.
- The CLI now releases client resources on every exit path: the modern-only
  and partial-audit early returns and the connection-failure exit previously
  bypassed the cleanup that closes the client's exit stack.
- Auth-posture messages no longer hard-code "401": the WWW-Authenticate and
  challenge-metadata rules report the observed HTTP status (401 or 403), and
  `auth_www_authenticate`'s display name is now "Auth - WWW-Authenticate
  Challenge" (rule_id unchanged).
- A partial audit now distinguishes missing credentials from rejected ones:
  when an Authorization credential was sent (`--token` or an explicit
  non-blank `Authorization` header — the same predicate as the report's
  `authenticated` flag) and the server still answered 401/403, the log and `partial_reason`
  say the credentials were rejected and suggest verifying them, instead of
  advising to pass a token. Non-auth custom headers (e.g. tracing) get the
  missing-credential guidance.
- The unauthenticated auth-posture probe no longer crashes against a server
  that returns a 401 with an RFC 6750 OAuth error body (a JSON object whose
  `error` field is a string like `"invalid_token"`, not a JSON-RPC error
  object). Such a body is now correctly treated as having no JSON-RPC error,
  so the auth-posture rules score normally instead of the probe erroring out.

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

[Unreleased]: https://github.com/mcp-box/mcpscore/compare/v1.5.0...HEAD
[1.5.0]: https://github.com/mcp-box/mcpscore/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/mcp-box/mcpscore/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/mcp-box/mcpscore/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/mcp-box/mcpscore/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/mcp-box/mcpscore/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/mcp-box/mcpscore/compare/v1.1.0rc1...v1.1.0
[1.1.0rc1]: https://github.com/mcp-box/mcpscore/compare/v1.1.0b6...v1.1.0rc1
[1.1.0b6]: https://github.com/mcp-box/mcpscore/compare/v1.1.0b5...v1.1.0b6
[1.1.0b5]: https://github.com/mcp-box/mcpscore/compare/v1.1.0b4...v1.1.0b5
[1.1.0b4]: https://github.com/mcp-box/mcpscore/compare/v1.1.0b3...v1.1.0b4
[1.1.0b3]: https://github.com/mcp-box/mcpscore/compare/v1.1.0b2...v1.1.0b3
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
