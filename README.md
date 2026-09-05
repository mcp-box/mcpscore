# mcpscore

[![CI](https://github.com/mcp-box/mcpscore/actions/workflows/ci.yml/badge.svg)](https://github.com/mcp-box/mcpscore/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/mcp-box/mcpscore/graph/badge.svg)](https://codecov.io/gh/mcp-box/mcpscore)
[![PyPI](https://img.shields.io/pypi/v/mcpscore.svg)](https://pypi.org/project/mcpscore/)
[![Python](https://img.shields.io/pypi/pyversions/mcpscore.svg)](https://pypi.org/project/mcpscore/)
[![License](https://img.shields.io/github/license/mcp-box/mcpscore.svg)](https://github.com/mcp-box/mcpscore/blob/main/LICENSE)

**Lighthouse for MCP.** Audit any MCP (Model Context Protocol) server and get a scored, actionable report in seconds.

MCP servers that break the spec fail in the worst place: silently, inside someone
else's agent. A missing tool description, a stale protocol version, or an
unencrypted endpoint never crashes your server. It makes agents pick the wrong
tool, drop you from their registry, or leak traffic. mcpscore finds that before
your users do. Deterministic, no API key, no sign-up.

```bash
pip install mcpscore
mcpscore https://mcp.deepwiki.com/mcp
```

```text
Welcome to mcpscore!
Successfully connected to MCP server via Streamable HTTP: https://mcp.deepwiki.com/mcp
Transport: streamable-http
Starting the audit...
✅ Protocol version '2025-11-25' is one of the allowed versions
❌ Not using the latest protocol version: negotiated '2025-11-25', latest is '2026-07-28', and no stateless-lifecycle support was observed
✅ Server name is present: 'DeepWiki'
❌ Server title is not present in server info
✅ Declares the tools capability and serves 3 via tools/list
✅ Server uses HTTPS with valid TLS (TLSv1.3)
...
Audit finished. Final score: 78/91
Spec: 2025-11-25 negotiated (latest: 2026-07-28) · era: legacy
Readiness for MCP 2026-07-28: 3/13 (informative — not part of the main score; 4 of 21 checks assessed)
```

Every ❌ is one thing to fix, and every result cites the spec section or best
practice it enforces.
Full docs: [docs.mcpscore.dev](https://docs.mcpscore.dev).

## Audit any server, in any language

```bash
# A local Python or Node server — the transport is detected automatically
mcpscore path/to/server.py
mcpscore path/to/server.js

# Any other language: --stdio runs a command and consumes the rest of the line,
# so put every mcpscore option before it
mcpscore --stdio ./my-go-server
mcpscore --stdio java -jar server.jar

# Pass config to the server with --env; for secrets use the value-less form,
# which copies from your environment and keeps the value out of the report
API_KEY=... mcpscore --env API_KEY --stdio ./my-go-server

# A remote server (Streamable HTTP or SSE, detected automatically)
mcpscore https://your-server.example/mcp

# Behind OAuth or an API key: bring a token, or let --oauth open the browser
mcpscore https://your-server.example/mcp --token "$TOKEN"
mcpscore https://your-server.example/mcp --oauth
```

No install at all: `uvx mcpscore <target>` or `npx @mcp-box/mcpscore <target>`.
Guides: [authenticated servers](https://docs.mcpscore.dev/authenticated-servers),
[CLI reference](https://docs.mcpscore.dev/cli).

## Use it in CI

```bash
# Machine-readable report on stdout; logs go to stderr
mcpscore https://your-server.example/mcp --json > report.json

# Fail the build when the score drops below 80%
mcpscore https://your-server.example/mcp --fail-under 80

# After the audit, actually call your own server's tools and check they behave
mcpscore path/to/server.py --smoke
```

Rules that don't apply to your server, or matter more to you, go in a
`mcpscore.toml` next to your code: `off` turns a rule off, a severity name
re-ranks it, and `[gate] fail_on = "high"` fails the build on any failed rule
counted in the main score at or above it. It changes the score in your CI only, never the badge.
Details: [configure rules](https://docs.mcpscore.dev/configure-rules).

| Exit code | Meaning                                                      |
|-----------|--------------------------------------------------------------|
| `0`       | Audit completed and every gate passed                        |
| `1`       | Audit never ran: usage error or a failed `--oauth` flow      |
| `2`       | Could not connect to the server                              |
| `3`       | `--fail-under` or `--fail-under-readiness` threshold not met |
| `4`       | A `--smoke` check failed (`3` wins when both fail)           |

The [GitHub Action](https://docs.mcpscore.dev/github-action) wraps this into
one step that gates the pull request and posts the report as a comment.
[Smoke mode](https://docs.mcpscore.dev/smoke-mode) explains what `--smoke`
calls and why it never changes the score.

## What the score measures

Each rule has a severity and a weight. Passing rules add their weight, and the
score is reported as `earned/maximum`. Rules that cannot apply to your server
are skipped and excluded from the maximum, never failed.

| Severity | Weight | Example                                      |
|----------|--------|----------------------------------------------|
| CRITICAL | 5      | Protocol version, server name, TLS           |
| HIGH     | 3      | Server version, valid tool schemas           |
| MEDIUM   | 2      | Titles, descriptions, error hygiene          |
| LOW      | 1      | Capability extras, transport recommendations |

105 rules run today, in four categories:

- **Protocol** (17 rules): protocol version, server name, title and version,
  advertised capabilities, transport. SSE-only servers get migration advice.
- **Primitives** (50 rules): tools, prompts, resources, and resource templates.
  Names, titles, descriptions, JSON Schema validity, URIs, MIME types,
  annotations, and pagination behavior. These decide whether an agent picks
  the right tool and calls it correctly.
- **Security & Auth** (11 rules): TLS version and certificate, error responses
  that leak data, and for auth-gated servers the OAuth posture: the
  `WWW-Authenticate` challenge, RFC 9728 resource metadata, the RFC 8414
  authorization-server chain, and PKCE enforcement.
- **Readiness** (21 rules): how ready the server is for the 2026-07-28 spec
  revision, on its own axis. Servers already on the new stateless lifecycle
  get these points counted in the main score. Legacy servers see them as
  guidance.

Six separate **Packaging** rules score a published npm or PyPI listing with
`--package npm:name` or `--package pypi:name`. The package is read from the
registry and never downloaded or run, and its score has its own denominator.

How it all fits together: [scoring methodology](https://docs.mcpscore.dev/methodology).
Every rule with its weight and the spec revisions it applies to: [rules reference](https://docs.mcpscore.dev/rules).

## JSON report

`--json` writes one JSON document to stdout. `rule_id` values are stable across
releases and are the key to build tooling on. Names and messages can be reworded.

```json
{
  "schema_version": 1,
  "mcpscore_version": "1.11.0",
  "target": "https://mcp.deepwiki.com/mcp",
  "transport": "streamable-http",
  "score": 78,
  "max_score": 91,
  "partial": false,
  "spec": { "negotiated_version": "2025-11-25", "latest_version": "2026-07-28", "era": "legacy" },
  "results": [
    {
      "rule_id": "protocol_version_allowed",
      "severity": "CRITICAL",
      "severity_value": 5,
      "passed": true,
      "message": "✅ Protocol version '2025-11-25' is one of the allowed versions",
      "details": {
        "basis": "MCP 2025-11-25 Lifecycle §Version Negotiation (server MUST respond with a version it supports)"
      }
    }
  ]
}
```

What is stable and what moves between releases:
[stability contract](https://docs.mcpscore.dev/stability).

## Score badge

Every server audited on [mcpscore.dev](https://mcpscore.dev) gets a badge URL
keyed by the server URL, and a report link keyed the same way. Embed it once
and it shows the latest score forever.

```markdown
[![mcpscore score](https://mcpscore.dev/api/v1/servers/badge.svg?url=https%3A%2F%2Fyour-server.example%2Fmcp)](https://mcpscore.dev/s?url=https%3A%2F%2Fyour-server.example%2Fmcp)
```

The report page on mcpscore.dev has this snippet prefilled for your server.
Details: [score badge](https://docs.mcpscore.dev/badge).

## When it fails

**`Error connecting to the MCP server: https://...`** (exit `2`)

- Cause: the URL answered, but not as an MCP endpoint. The log above it shows
  the legacy handshake failing and the modern-only probe finding nothing.
- Fix: point at the MCP endpoint itself, usually ending in `/mcp`.

**`Server script not found: ./server.py`** (exit `2`)

- Cause: the path does not exist relative to where you ran the command.
- Fix: check the path. For non-Python, non-Node servers use `--stdio <command>`.

**A local server starts and then the audit hangs or exits `2`**

- Cause: the server's runtime is not on `PATH`, or it needs an environment
  variable it did not get.
- Fix: run the command yourself first. Pass config with `--env NAME=VALUE`,
  secrets with `--env NAME`.

**`PARTIAL score: 24/27 from 10 of 78 checks`**

- Cause: the server answered 401 and you passed no credential, so only the
  auth, TLS, and transport surface was scored.
- Fix: pass `--token`, `--header`, or `--oauth`. See
  [authenticated servers](https://docs.mcpscore.dev/authenticated-servers).

**A rule flags a protocol version mcpscore does not recognize**

- Cause: your server is newer than the installed mcpscore.
- Fix: upgrade, and if it persists,
  [open an issue](https://github.com/mcp-box/mcpscore/issues) with the version.

## Requirements

- Python 3.11 or newer.
- For local servers, the server's own runtime on `PATH`: Node.js for `.js`
  targets, Python for `.py` targets, and whatever `--stdio` names for the rest.

## Use as a library

The package is fully typed (`py.typed`). `MCPClient` connects and collects,
`MCPAuditor` runs the rules and builds the same report the CLI prints.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the development setup and how to add
a rule. [MISSION.md](MISSION.md) says why the project exists.
[SECURITY.md](SECURITY.md) is for security reports. [CHANGELOG.md](CHANGELOG.md)
lists every release. Bugs and ideas go to
[GitHub issues](https://github.com/mcp-box/mcpscore/issues).

## License

MIT. See [LICENSE](LICENSE).
