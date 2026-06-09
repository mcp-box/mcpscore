# Security Policy

## Supported Versions

Only the latest release of mcpscore receives security fixes.

| Version | Supported |
|---------|-----------|
| latest  | ✅         |
| older   | ❌         |

## Reporting a Vulnerability

Please **do not open a public issue** for security vulnerabilities.

Instead, report them privately via
[GitHub Security Advisories](https://github.com/mcp-box/mcpscore/security/advisories/new).

We aim to acknowledge reports within 48 hours and will keep you informed of
the fix's progress. Credit is given in the release notes unless you prefer
to remain anonymous.

## Scope notes

mcpscore connects to MCP servers you point it at. It never executes tool
calls against audited servers — it only reads metadata (initialize result,
tool/resource/prompt listings). Treat audit targets as untrusted: run audits
of unknown servers from an environment you are comfortable having open a
network connection from.
