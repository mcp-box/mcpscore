"""Command-line interface for MCPScore."""

from __future__ import annotations

import argparse
import asyncio
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
import json
import logging
import os
import sys
from typing import TYPE_CHECKING, NoReturn

from mcpscore import MCPAuditor, MCPClient
from mcpscore.enums import ConnectionErrorReason
from mcpscore.mcp_auditor import has_authorization_credential

if TYPE_CHECKING:
    from mcpscore import MCPTransportType

logger = logging.getLogger(__name__)

REPORT_SCHEMA_VERSION = 1
"""Version of the JSON report schema emitted by --json.

Bumped on backwards-incompatible changes to the report structure so that
machine consumers (CI integrations, acceptance suites) can detect them.
"""


class _CLIArgumentParser(argparse.ArgumentParser):
    """Argument parser that exits with code 1 on usage errors.

    The default argparse exit code for usage errors is 2, which mcpscore
    reserves for connection failures (documented CLI contract).
    """

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        logger.error("Usage error: %s", message)
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the mcpscore CLI.

    Returns:
        Configured ArgumentParser with the audit target and output options.

    """
    parser = _CLIArgumentParser(
        prog="mcpscore",
        description="Audit an MCP server and get a comprehensive report on its quality.",
    )
    parser.add_argument(
        "target",
        help="Path to a local MCP server (.py, .js) or URL of a remote server (Streamable HTTP / SSE)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable JSON report to stdout (logs go to stderr)",
    )
    parser.add_argument(
        "--header",
        action="append",
        metavar="'Name: Value'",
        help=(
            "Extra HTTP header sent to the server, e.g. --header 'Authorization: Bearer <token>' "
            "to audit an auth-gated server. Repeatable. Header values are never logged or reported."
        ),
    )
    parser.add_argument(
        "--token",
        metavar="TOKEN",
        help=(
            "Convenience for --header 'Authorization: Bearer <TOKEN>'. "
            "Defaults to the MCPSCORE_TOKEN environment variable (keeps tokens out of shell history)."
        ),
    )
    parser.add_argument(
        "--oauth",
        action="store_true",
        help=(
            "Obtain a token interactively: opens your browser for the server's OAuth flow "
            "(authorization code + PKCE). The token is held in memory only — never written "
            "to disk, never logged. Requires the authorization server to support dynamic "
            "client registration unless --client-id is given."
        ),
    )
    parser.add_argument(
        "--client-id",
        metavar="ID",
        help=(
            "Pre-registered OAuth client ID for --oauth, for authorization servers without "
            "dynamic client registration (e.g. GitHub's). The registered app must allow a "
            "loopback redirect URI (http://127.0.0.1:<port>/callback)."
        ),
    )
    parser.add_argument(
        "--callback-port",
        metavar="PORT",
        type=int,
        help=(
            "Fixed loopback port for the --oauth redirect URI. RFC 8252 says authorization "
            "servers must accept any port on loopback redirects, but if yours requires the "
            "exact pre-registered URI, pin the port you registered (pairs with --client-id)."
        ),
    )
    return parser


def parse_header(raw: str) -> tuple[str, str]:
    """Parse a ``Name: Value`` header string into a (name, value) pair.

    Args:
        raw: A header in ``Name: Value`` form.

    Returns:
        The (name, value) tuple, both stripped.

    Raises:
        ValueError: If there is no colon separating name and value. The
            malformed input is deliberately not echoed — header values may
            carry secrets and the error text is logged.

    """
    name, sep, value = raw.partition(":")
    if not sep or not name.strip():
        raise ValueError("invalid header (expected 'Name: Value'; the value is not shown — headers may carry secrets)")
    return name.strip(), value.strip()


def collect_headers(args: argparse.Namespace) -> dict[str, str]:
    """Build the request-header dict from --header, --token, and MCPSCORE_TOKEN.

    Precedence: explicit --header entries first, then a bearer from --token or
    the MCPSCORE_TOKEN env var (an explicit Authorization header is not
    overwritten).

    Args:
        args: Parsed CLI arguments.

    Returns:
        A header dict (possibly empty).

    Raises:
        ValueError: If a --header value is malformed.

    """
    headers: dict[str, str] = {}
    for position, raw in enumerate(args.header or [], start=1):
        try:
            name, value = parse_header(raw)
        except ValueError as e:
            raise ValueError(f"--header #{position}: {e}") from None
        headers[name] = value
    token = args.token or os.environ.get("MCPSCORE_TOKEN")
    if token and not any(name.lower() == "authorization" for name in headers):
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _mcpscore_version() -> str:
    """Return the installed mcpscore package version, or "unknown"."""
    try:
        return version("mcpscore")
    except PackageNotFoundError:  # pragma: no cover - only without package metadata
        return "unknown"


def log_audit_outcome(auditor: MCPAuditor) -> None:
    """Log the human-readable audit outcome: score, spec/era line, readiness line.

    The main score and the readiness score are deliberately separate lines —
    readiness for the next spec revision is informative for legacy servers
    and counted in the main score for modern-lifecycle full audits — the
    line says which mode applied (readiness promotion).
    """
    report = auditor.get_audit_report()
    spec = report["spec"]
    readiness = report["readiness"]

    logger.info("")
    if report["partial"]:
        logger.info("⚠️  Partial audit (%s).", report["partial_reason"])
        logger.info("Only the auth, TLS, and transport surface was scored — not comparable to a full audit.")
    logger.info("Audit finished. Final score: %s/%s", report["score"], report["max_score"])
    logger.info(
        "Spec: %s negotiated (latest: %s) · era: %s",
        spec["negotiated_version"] or "unknown",
        spec["latest_version"],
        spec["era"] or "unknown",
    )
    if readiness["max_score"] > 0:
        logger.info(
            "Readiness for MCP %s: %s/%s (%s)",
            spec["readiness_target"],
            readiness["score"],
            readiness["max_score"],
            "counted in the main score — modern-lifecycle server"
            if readiness.get("counted_in_main")
            else "informative — not part of the main score",
        )
    else:
        logger.info(
            "Readiness for MCP %s: not assessed (no probe observations for this transport)",
            spec["readiness_target"],
        )


def build_report(target: str, transport: MCPTransportType | None, auditor: MCPAuditor) -> dict:
    """Build the machine-readable audit report emitted by --json.

    Args:
        target: The server path or URL that was audited
        transport: The transport the connection was established over
        auditor: The auditor instance after a completed audit run

    Returns:
        Dictionary with report metadata (schema version, mcpscore version,
        timestamp, target, transport) and the audit results
        (score, max_score, summary, per-rule results).

    """
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "mcpscore_version": _mcpscore_version(),
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "target": target,
        "transport": str(transport) if transport is not None else None,
        **auditor.get_audit_report(),
    }


async def _apply_oauth(args: argparse.Namespace, headers: dict[str, str]) -> None:
    """Run the --oauth browser flow and place the token into the header dict.

    Exits with code 1 on flag conflicts or a failed flow; a no-op when
    --oauth was not requested.
    """
    if (args.client_id or args.callback_port) and not args.oauth:
        logger.error("Usage error: --client-id / --callback-port only make sense together with --oauth")
        sys.exit(1)
    if not args.oauth:
        return
    if any(name.lower() == "authorization" for name in headers):
        logger.error(
            "Usage error: --oauth conflicts with an existing Authorization credential "
            "(--token, an Authorization --header, or the MCPSCORE_TOKEN environment variable) — pick one"
        )
        sys.exit(1)
    if not args.target.startswith(("http://", "https://")):
        logger.error("Usage error: --oauth requires an HTTP(S) server URL")
        sys.exit(1)
    from mcpscore.oauth import OAuthFlowError, obtain_token_interactively

    try:
        access_token = await obtain_token_interactively(
            args.target, client_id=args.client_id, callback_port=args.callback_port
        )
    except OAuthFlowError as e:
        logger.error("OAuth: %s", e)  # noqa: TRY400 — user-facing outcome, not a traceback
        sys.exit(1)
    headers["Authorization"] = f"Bearer {access_token}"
    logger.info("OAuth flow completed — token held in memory only for this audit.")


async def async_main() -> None:
    """Execute the main entry point for the MCPScore CLI application.

    Orchestrates the audit process by:
    1. Parsing command line arguments for the server path or URL
    2. Creating MCP client and auditor instances
    3. Auto-detecting transport and connecting to the MCP server
    4. Running the audit process and displaying results
    5. Optionally emitting a JSON report to stdout (--json)
    6. Cleaning up resources

    Supports local servers (.py, .js) via STDIO and remote servers via
    Streamable HTTP or SSE (auto-detected). When the legacy connection fails
    against an HTTP(S) target, the server is checked for modern-only
    (2026-07-28 stateless lifecycle) support and audited via probes if so.

    Exits with code 1 on usage errors, or code 2 if connection fails and the
    server shows no modern-lifecycle support either.
    """
    logger.info("Welcome to MCPScore!")

    args = build_parser().parse_args()

    try:
        headers = collect_headers(args)
    except ValueError as e:
        logger.error("Usage error: %s", e)  # noqa: TRY400 — usage error, not an exception to trace
        sys.exit(1)

    await _apply_oauth(args, headers)

    if headers:
        logger.info("Using %d custom header(s).", len(headers))

    client: MCPClient = MCPClient(headers=headers or None)
    auditor: MCPAuditor = MCPAuditor(headers=headers or None)

    # Everything below runs inside one try/finally: failed detection attempts
    # can leave resources on the client's exit stack, so every path out —
    # early returns, sys.exit(2), audit errors — must reach cleanup().
    try:
        success, transport = await client.detect_and_connect(args.target)

        if not success:
            if args.target.startswith(("http://", "https://")):
                logger.info("Legacy connection failed — checking for a modern-only (stateless lifecycle) MCP server...")
                if await auditor.audit_modern_only(args.target):
                    logger.info(
                        "Modern-only MCP server detected: audited via stateless probes (no legacy session available)."
                    )
                    log_audit_outcome(auditor)
                    if args.json:
                        report = build_report(args.target, auditor.audit_data.transport_type, auditor)
                        sys.stdout.write(json.dumps(report, indent=2, default=str) + "\n")
                    return

                failure = client.last_connection_error
                if failure is not None and failure.reason in (
                    ConnectionErrorReason.UNAUTHORIZED,
                    ConnectionErrorReason.FORBIDDEN,
                ):
                    status = failure.status_code or (
                        401 if failure.reason is ConnectionErrorReason.UNAUTHORIZED else 403
                    )
                    # Key off the same predicate as the report's authenticated
                    # flag: only an Authorization credential counts — a 401
                    # with only tracing/custom headers is a missing credential,
                    # not a rejected one.
                    if has_authorization_credential(headers):
                        logger.info(
                            "Server rejected the provided credentials — "
                            "running a partial audit of the observable surface."
                        )
                        logger.info("(Check that the --token/--header credentials are valid for this server.)")
                        partial_reason = (
                            f"Server rejected the provided credentials (HTTP {status}); scored the unauthenticated "
                            "surface only — check that the token or headers are valid for this server."
                        )
                    else:
                        logger.info(
                            "Server requires authentication — running a partial audit of the observable surface."
                        )
                        logger.info("(Pass a token with --token or --header to audit behind the gate.)")
                        partial_reason = (
                            f"Server requires authentication (HTTP {status}); scored the unauthenticated surface "
                            "only — pass a token to audit behind the gate."
                        )
                    await auditor.audit_partial(args.target, reason=partial_reason)
                    log_audit_outcome(auditor)
                    if args.json:
                        report = build_report(args.target, auditor.audit_data.transport_type, auditor)
                        sys.stdout.write(json.dumps(report, indent=2, default=str) + "\n")
                    return
            logger.error("Error connecting to the MCP server: %s", args.target)
            sys.exit(2)

        logger.info("Connected to the MCP server: %s", args.target)
        logger.info("Transport: %s", transport)

        logger.info("Starting the audit...")
        await auditor.audit(client)
        log_audit_outcome(auditor)

        if args.json:
            report = build_report(args.target, transport, auditor)
            sys.stdout.write(json.dumps(report, indent=2, default=str) + "\n")
    finally:
        await client.cleanup()


def main() -> None:
    """Entry point for the mcpscore CLI command.

    This function is called when running `mcpscore` from the command line.
    It sets up logging (to stderr, keeping stdout clean for --json output)
    and runs the async main function.
    """
    logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stderr)
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
