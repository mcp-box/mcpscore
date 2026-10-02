# mcpscore

[![CI](https://github.com/mcp-box/mcpscore/actions/workflows/ci.yml/badge.svg)](https://github.com/mcp-box/mcpscore/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/mcp-box/mcpscore/graph/badge.svg)](https://codecov.io/gh/mcp-box/mcpscore)
[![PyPI](https://img.shields.io/pypi/v/mcpscore.svg)](https://pypi.org/project/mcpscore/)
[![Python](https://img.shields.io/pypi/pyversions/mcpscore.svg)](https://pypi.org/project/mcpscore/)
[![License](https://img.shields.io/github/license/mcp-box/mcpscore.svg)](https://github.com/mcp-box/mcpscore/blob/main/LICENSE)

**Lighthouse for MCP.** Point mcpscore at an MCP server and get a score plus
a list of what to fix, each finding cited to its source: the MCP spec,
an RFC, the MCP Registry schema, or a stated best practice.

A missing tool title, a stale protocol version, or an endpoint that accepts
any `Origin` never crashes your server. It makes agents pick the wrong tool,
or lets a malicious web page talk to your server. mcpscore finds those before
your users do. It is deterministic and needs no API key and no sign-up.

Documentation: [docs.mcpscore.dev](https://docs.mcpscore.dev)

## Install

```bash
pip install mcpscore
```

With uv, `uvx mcpscore` runs it without installing. Node users can run
`npx @mcp-box/mcpscore` with uv or pipx on `PATH`; the npm package launches
this Python engine ([npm setup](https://github.com/mcp-box/mcpscore/blob/main/npm/README.md)).

## Audit your first server

```bash
mcpscore https://mcp.deepwiki.com/mcp
```

```text
Welcome to mcpscore!
Successfully connected to MCP server via Streamable HTTP: https://mcp.deepwiki.com/mcp
Transport: streamable-http
Starting the audit...
✅ Protocol version "2025-11-25" is one of the allowed versions.
❌ Server title is not present in server info. This is an optional quality recommendation. First affected field: server "/serverInfo/title".
  Fix: Add a human-readable serverInfo.title so clients can display a recognizable server name.
✅ Server uses HTTPS with valid TLS (TLSv1.3).
❌ Streamable HTTP does not reject an invalid foreign Origin with HTTP 403, risking DNS rebinding. Observed HTTP status: 200.
  Fix: Validate supplied Origin headers against the origins allowed for this endpoint. Return HTTP 403 for invalid origins; do not allow every origin to satisfy browser requests.
...
Audit finished. Final score: 87/103
Spec: 2025-11-25 negotiated (latest: 2026-07-28) · era: legacy
Readiness for MCP 2026-07-28: 3/13 (informative — not part of the main score; 4 of 20 checks assessed)
```

That's it. The server has a score.

Each ✅ or ❌ is one rule: one check, like `security_origin_validation`, that
passed or failed. Every ❌ carries a `Fix:` line. `87/103` means the server
earned 87 of the 103 points its rules can award. Rules that cannot apply to
this server are skipped and left out of the 103, so a server is never
penalized for a feature it does not have.

## Audit a server on your machine

A local server is audited the same way as a URL: put the script where the URL
was.

```bash
mcpscore path/to/server.py
```

```text
Transport: stdio
...
Audit finished. Final score: 131/155
Spec: 2025-11-25 negotiated (latest: 2026-07-28) · era: dual-era
```

Python and Node scripts are detected by extension. For any other language,
or a Python server in its own environment, name the command after `--stdio`:

```bash
mcpscore --stdio ./my-go-server
mcpscore --stdio uv run server.py
```

`--stdio` consumes the rest of the line, so put every other option before it.
More: [audit a local server](https://docs.mcpscore.dev/local-servers).

## Audit a server behind auth

```bash
mcpscore https://your-server.example/mcp --token "$TOKEN"
```

Without a credential, an auth-gated server still gets a partial score for its
auth, TLS, and transport surface. `--oauth` opens the browser instead of
taking a token, and `--header` sends an API-key header.
More: [authenticated servers](https://docs.mcpscore.dev/authenticated-servers).

## Fail the build when the score drops

```bash
mcpscore https://your-server.example/mcp --fail-under 90
```

When the score is below the threshold, the last line says so and the exit
code is `3`:

```text
Audit finished. Final score: 87/103
...
Gate failed — --fail-under 90: score 87/103 (84%) is below the required 90%
```

A refactor that drops a tool description now fails the pull request instead
of reaching someone's agent. On GitHub, the Action runs the same gate and
posts the report as a pull request comment:

```yaml
- uses: mcp-box/mcpscore-action@v1
  with:
    target: https://your-server.example/mcp
    min-score: 80
```

`--json` writes the full report to stdout and `--sarif FILE` writes failed
rules for GitHub code scanning.
More: [GitHub Action](https://docs.mcpscore.dev/github-action),
[other CI systems](https://docs.mcpscore.dev/ci-other-platforms).

## Check that your tools actually work

`--smoke` runs the audit, then calls your server's tools and checks how they
answer:

```bash
mcpscore --smoke path/to/server.py
```

```text
Smoke checks (tools/call): 0 passed, 1 failed, 2 skipped — only readOnlyHint: true tools called (see --call-all). Never counted in the score.
  skip smoke_structured_content [add]: not called under the safety default (readOnlyHint is not true); pass --call-all to include it
  ...
  FAIL smoke_unknown_tool: reported a tool execution error (isError) for a nonexistent tool — the spec's unknown-tool example is a protocol error, and an isError result claims the tool exists and ran
Gate failed — --smoke: 1 smoke check(s) failed
```

A failed smoke check exits `4` and never changes the score. By default only
tools annotated `readOnlyHint: true` are called; `--call-all` includes the
rest, so use it only on a server you own.
More: [smoke mode](https://docs.mcpscore.dev/smoke-mode).

## Turn off or re-rank rules

Put an `mcpscore.toml` next to your code:

```toml
[rules]
server_websiteurl_present = "off"          # does not run
tools_title_present_in_all = "critical"    # counts as CRITICAL

[gate]
fail_on = "high"   # exit 3 on any failed rule at HIGH or above
```

The CLI finds it by walking up from the current directory, and also reads
`[tool.mcpscore]` in `pyproject.toml`. It changes the score in your
runs only; the website and the badge always use the defaults.
More: [configure rules](https://docs.mcpscore.dev/configure-rules).

## Show the score in your README

Audit the server once on [mcpscore.dev](https://mcpscore.dev) and embed its
badge. It always shows the latest score.

```markdown
[![mcpscore score](https://mcpscore.dev/api/v1/servers/badge.svg?url=https%3A%2F%2Fyour-server.example%2Fmcp)](https://mcpscore.dev/s?url=https%3A%2F%2Fyour-server.example%2Fmcp)
```

More: [score badge](https://docs.mcpscore.dev/badge).

## Score a published package

```bash
mcpscore --package pypi:mcpscore
```

```text
📦 Auditing package pypi:mcpscore
Resolved version: 1.20.0
✅ Package "mcpscore" is published on pypi.
✅ Source repository declared: "https://github.com/mcp-box/mcpscore".
...
Audit finished. Final score: 16/16
Packaging audit of pypi:mcpscore — metadata only, the package was not downloaded or run.
```

This scores the npm or PyPI listing from registry metadata, on its own scale.
More: [package audits](https://docs.mcpscore.dev/package-audits).

## Exit codes

| Exit code | Meaning                                                            |
|-----------|--------------------------------------------------------------------|
| `0`       | The audit completed and every gate passed                          |
| `1`       | The audit never ran: a usage error or a failed `--oauth` flow      |
| `2`       | mcpscore could not connect to the server                           |
| `3`       | `--fail-under`, `--fail-under-readiness`, or `[gate]` was not met  |
| `4`       | A `--smoke` check failed (`3` wins when both fail)                 |

## What the score measures

99 server rules in four categories:

- **Protocol**: protocol version, server identity, capabilities, transport.
- **Primitives**: tools, prompts, resources, and resource templates. Names,
  titles, descriptions, schemas, annotations, and pagination decide whether
  an agent picks the right tool and calls it correctly.
- **Security & Auth**: TLS, `Origin` validation, error responses that leak
  data, and for auth-gated servers the OAuth challenge and metadata chain.
- **Readiness**: how ready the server is for the 2026-07-28 spec revision.
  It counts in the main score for servers already on the new stateless
  lifecycle and is guidance for the rest.

Each rule has a severity: CRITICAL is worth 5 points, HIGH 3, MEDIUM 2,
LOW 1. Six more rules score packages under `--package`.
More: [scoring methodology](https://docs.mcpscore.dev/methodology),
[every rule](https://docs.mcpscore.dev/rules),
[what is stable between releases](https://docs.mcpscore.dev/stability).

## When it fails

**`Error connecting to the MCP server: https://...`** (exit `2`)

- Cause: the URL answered, but not as an MCP endpoint.
- Fix: point at the MCP endpoint itself, usually ending in `/mcp`.

**`'server.py' is a script, not an executable command`** (exit `2`)

- Cause: `--stdio` runs a program, and a bare script is looked up on `PATH`.
- Fix: name the interpreter: `--stdio uv run server.py`.

**`Audit finished. PARTIAL score: ... — not comparable to a full audit.`**

- Cause: the server answered 401 and you passed no credential.
- Fix: pass `--token`, `--header`, or `--oauth`.

More: [troubleshooting](https://docs.mcpscore.dev/troubleshooting).

## Requirements

- Python 3.11 or newer.
- For local servers, the server's own runtime on `PATH`: Python for `.py`,
  Node.js for `.js`, and whatever `--stdio` names for the rest.

## Use as a library

The package is fully typed (`py.typed`). `MCPClient` connects and collects,
and `MCPAuditor` runs the rules and builds the same report the CLI prints.
The `--json` report shape is versioned by `schema_version`, and `rule_id`
values are stable across releases.

## Contributing

[CONTRIBUTING.md](https://github.com/mcp-box/mcpscore/blob/main/CONTRIBUTING.md)
covers the development setup and how to add a rule.
[MISSION.md](https://github.com/mcp-box/mcpscore/blob/main/MISSION.md) says
why the project exists, and
[SECURITY.md](https://github.com/mcp-box/mcpscore/blob/main/SECURITY.md) is
for security reports. Every release is in the
[CHANGELOG](https://github.com/mcp-box/mcpscore/blob/main/CHANGELOG.md).
Bugs and ideas go to [GitHub issues](https://github.com/mcp-box/mcpscore/issues).

## License

MIT. See [LICENSE](https://github.com/mcp-box/mcpscore/blob/main/LICENSE).
