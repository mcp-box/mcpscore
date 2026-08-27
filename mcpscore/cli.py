"""Command-line interface for mcpscore."""

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

from mcpscore import MCPAuditor, MCPClient, StdioCommand
from mcpscore.enums import ConnectionErrorReason
from mcpscore.mcp_auditor import has_authorization_credential
from mcpscore.packages import InvalidCoordinateError, PackageCoordinate
from mcpscore.probes import observed_auth_status

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
        nargs="?",
        help=(
            "Path to a local MCP server (.py, .js) or URL of a remote server (Streamable HTTP / SSE). "
            "For servers in other languages, use --stdio instead."
        ),
    )
    parser.add_argument(
        "--stdio",
        nargs=argparse.REMAINDER,
        metavar="COMMAND",
        help=(
            "Launch a local MCP server as an arbitrary stdio command — any language: "
            "--stdio ./server, --stdio java -jar server.jar, --stdio dotnet run --project ./srv. "
            "Consumes the REST of the command line (the server's own flags included), so put "
            "every mcpscore option before it. Replaces the positional target. The command runs "
            "directly (no shell). Never pass secrets as arguments — the command line appears as "
            "the report's target (and in the process list); use the value-less --env NAME form."
        ),
    )
    parser.add_argument(
        "--package",
        metavar="COORDINATE",
        help=(
            "Score a published package instead of a running server: --package npm:@scope/name, "
            "--package npm:name@1.2.3, --package pypi:name==1.2.3. Reads the registry's metadata "
            "only — the package is never downloaded and never executed, so no install hook runs. "
            "Judges how the server is PUBLISHED (resolves, versioned, licensed, source-linked), "
            "not whether it speaks MCP; for that, run the server with --stdio. The two scores "
            "come from disjoint rule sets and are not comparable."
        ),
    )
    parser.add_argument(
        "--env",
        action="append",
        metavar="NAME=VALUE",
        help=(
            "Extra environment variable for the --stdio server process. Repeatable. "
            "--env NAME=VALUE sets it inline (non-sensitive config only: the value lands in "
            "shell history and the process list). --env NAME copies the value from mcpscore's "
            "own environment — use this for secrets: API_KEY=… mcpscore --env API_KEY --stdio … "
            "Merged over a minimal default environment; values are never logged or reported."
        ),
    )
    # An "action=version" argument exits during parsing, before argparse
    # enforces the required `target` — so `mcpscore --version` works on its
    # own, which is the whole point of asking a tool what version it is.
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_mcpscore_version()}",
        help="Show the installed mcpscore version and exit",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a machine-readable JSON report to stdout (logs go to stderr)",
    )
    parser.add_argument(
        "--fail-under",
        metavar="PCT",
        type=int,
        help=(
            "Exit with code 3 when the main score percentage (0-100, rounded) is below PCT — "
            "a CI gate: 'your server scored badly' (3) stays distinct from 'the audit never "
            "ran' (1) or 'could not connect' (2). A partial audit always fails this gate: its "
            "percentage covers only the observable surface and cannot demonstrate the "
            "threshold — pass a credential to audit behind the gate."
        ),
    )
    parser.add_argument(
        "--fail-under-readiness",
        metavar="PCT",
        type=int,
        help=(
            "Exit with code 3 when the readiness percentage for the latest spec revision is "
            "below PCT. Skipped when readiness was not assessed at all (nothing to gate on), "
            "matching the GitHub Action's min-readiness input."
        ),
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


def parse_env_vars(pairs: list[str]) -> dict[str, str]:
    """Parse repeated --env arguments (``NAME=VALUE`` or value-less ``NAME``).

    ``NAME=VALUE`` sets the value inline — fine for non-sensitive
    configuration. A bare ``NAME`` copies the value from mcpscore's own
    inherited environment (``API_KEY=… mcpscore --env API_KEY --stdio …``) —
    the right form for secrets, because the value never appears on any
    command line, in shell history, or in a process listing.

    Args:
        pairs: Raw --env values as given on the command line.

    Returns:
        Mapping of variable names to values (later duplicates win).

    Raises:
        ValueError: If an entry has an empty name, or names a variable that
            is not set in the environment. Error messages identify the entry
            by position only and never echo it: a malformed entry may be an
            accidentally pasted secret (same policy as ``parse_header``).

    """
    env: dict[str, str] = {}
    for position, raw in enumerate(pairs, start=1):
        name, sep, value = raw.partition("=")
        if not name:
            raise ValueError(
                f"--env #{position}: expected NAME=VALUE or NAME (the entry is not shown — it may carry a secret)"
            )
        if not sep:
            inherited = os.environ.get(name)
            if inherited is None:
                raise ValueError(
                    f"--env #{position}: names a variable that is not set in the environment "
                    "(the entry is not shown — it may be a mistyped name or a pasted secret)"
                )
            env[name] = inherited
        else:
            env[name] = value
    return env


def resolve_target(args: argparse.Namespace) -> str | StdioCommand | PackageCoordinate:
    """Resolve the audit target from the positional target, --stdio and --package.

    Exactly one of the three must be given; --env only makes sense with
    --stdio (a URL, bare script target or package coordinate spawns no
    configurable process — and --package spawns no process at all).

    Returns:
        The URL / script path string, a StdioCommand for --stdio, or a
        PackageCoordinate for --package.

    Raises:
        ValueError: On any invalid combination (message is user-facing).

    """
    if args.package is not None:
        if args.target is not None or args.stdio is not None:
            raise ValueError("give either a target, --stdio, or --package — not more than one")
        if args.env:
            raise ValueError("--env only applies to --stdio servers; --package never runs the package")
        try:
            return PackageCoordinate.parse(args.package)
        except InvalidCoordinateError as e:
            raise ValueError(str(e)) from None
    if args.stdio is not None:
        if args.target is not None:
            raise ValueError("give either a target or --stdio, not both")
        if not args.stdio:
            raise ValueError("--stdio needs a command to run, e.g. --stdio java -jar server.jar")
        return StdioCommand(
            command=args.stdio[0],
            args=tuple(args.stdio[1:]),
            env=parse_env_vars(args.env) if args.env else None,
        )
    if args.env:
        raise ValueError("--env only applies to --stdio servers")
    if args.target is None:
        raise ValueError("a target is required: a URL, a .py/.js path, --stdio <command>, or --package <coordinate>")
    return args.target


def _mcpscore_version() -> str:
    """Return the installed mcpscore package version, or "unknown"."""
    try:
        return version("mcpscore")
    except PackageNotFoundError:  # pragma: no cover - only without package metadata
        return "unknown"


async def run_package_audit(args: argparse.Namespace, coordinate: PackageCoordinate) -> int:
    """Score a package coordinate and report it. Returns the process exit code.

    Its own entry point rather than a branch inside the server flow: there is no
    client to connect, no transport to detect and no session to clean up — the
    whole run is one HTTPS GET against a package registry.

    Exit codes match the server flow's meaning: 0 audited, 2 could not look the
    package up (the analogue of "could not connect").
    """
    auditor = MCPAuditor()
    await auditor.audit_package(coordinate)
    report = auditor.get_audit_report()
    package = report["package"]

    logger.info("")
    if package["outcome"] == "error":
        logger.error("Could not read %s metadata: %s", package["registry"], package["error"])
        return 2

    logger.info("Audit finished. Final score: %s/%s", report["score"], report["max_score"])
    logger.info(
        "Packaging audit of %s — metadata only, the package was not downloaded or run.",
        coordinate.display,
    )
    logger.info("This scores how the server is published, not whether it speaks MCP; use --stdio for that.")

    if args.json:
        full = build_report(coordinate.display, None, auditor)
        sys.stdout.write(json.dumps(full, indent=2, default=str) + "\n")
    # A package audit has no readiness axis (max 0), so only --fail-under can gate it —
    # against the packaging percentage, the only score this audit has.
    return fail_under_exit_code(args, report)


def score_percentage(score: float, max_score: float) -> int:
    """Score as an integer percentage; 0 when there is nothing to score.

    The same arithmetic the GitHub Action's gate has always used, so a
    threshold means the same thing in both places.
    """
    if max_score <= 0:
        return 0
    return round(score / max_score * 100)


def fail_under_exit_code(args: argparse.Namespace, report: dict) -> int:
    """Return 3 when the report fails a --fail-under gate, else 0.

    Gate semantics (each breach is logged before returning):

    - ``--fail-under`` compares the main score percentage. A **partial audit
      always fails it**: its percentage covers only the observable surface
      (an auth-gated server with a clean auth posture normalizes to 100% on
      a handful of checks), so it cannot demonstrate the threshold — passing
      silently would wave through a server that was barely inspected.
    - ``--fail-under-readiness`` compares the readiness percentage, and is
      skipped when readiness was not assessed at all (``max_score == 0``) —
      the GitHub Action's ``min-readiness`` semantics.
    """
    failures: list[str] = []

    if args.fail_under is not None:
        if report["partial"]:
            failures.append(
                f"--fail-under {args.fail_under}: this was a partial audit — its score covers only the "
                "observable surface and cannot demonstrate the threshold; pass a credential to audit "
                "behind the gate (or drop --fail-under for partial audits)"
            )
        else:
            pct = score_percentage(report["score"], report["max_score"])
            if pct < args.fail_under:
                failures.append(
                    f"--fail-under {args.fail_under}: score {report['score']}/{report['max_score']} "
                    f"({pct}%) is below the required {args.fail_under}%"
                )

    if args.fail_under_readiness is not None:
        readiness = report.get("readiness") or {}
        readiness_max = readiness.get("max_score", 0)
        if readiness_max > 0:
            pct = score_percentage(readiness.get("score", 0), readiness_max)
            if pct < args.fail_under_readiness:
                failures.append(
                    f"--fail-under-readiness {args.fail_under_readiness}: readiness "
                    f"{readiness.get('score', 0)}/{readiness_max} ({pct}%) is below the required "
                    f"{args.fail_under_readiness}%"
                )

    for failure in failures:
        logger.error("Gate failed — %s", failure)
    return 3 if failures else 0


def finish_server_audit(
    args: argparse.Namespace,
    auditor: MCPAuditor,
    target_display: str,
    transport: MCPTransportType | None,
) -> None:
    """Finish a server audit: log the outcome, emit --json, apply the gate.

    The shared tail of every completed server audit (full, partial, and
    modern-only). Exits with code 3 when a --fail-under gate fails;
    returns normally otherwise so ungated behavior is unchanged.
    """
    log_audit_outcome(auditor)
    if args.json:
        report = build_report(target_display, transport, auditor)
        sys.stdout.write(json.dumps(report, indent=2, default=str) + "\n")
    if code := fail_under_exit_code(args, auditor.get_audit_report()):
        sys.exit(code)


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
        # Main axis only, both sides. `results` holds main-axis results while
        # `skipped_rules` holds every skip including readiness ones, so
        # len(results) + len(skipped_rules) counts readiness skips in the
        # denominator without counting the readiness checks that ran in the
        # numerator — a ratio belonging to neither axis. The summary already
        # separates them, and the score being qualified here is the main-axis
        # score; readiness reports its own totals on its own line below.
        scored = report["summary"]["total"]
        considered = scored + report["summary"]["skipped"]
        logger.info("⚠️  Partial audit (%s).", report["partial_reason"])
        logger.info("Only the auth, TLS, and transport surface was scored — not comparable to a full audit.")
        # The qualifier goes on the SAME line as the number. A partial audit of
        # a well-configured auth-gated server scores 25/25, and the caveat above
        # does not survive the screenshot — the number is what gets pasted into
        # a chat or a slide (external feedback, 2026-08-18). Saying how many
        # checks actually ran is what makes "25/25" interpretable.
        logger.info(
            "Audit finished. PARTIAL score: %s/%s from %s of %s checks — not comparable to a full audit.",
            report["score"],
            report["max_score"],
            scored,
            considered,
        )
    else:
        logger.info("Audit finished. Final score: %s/%s", report["score"], report["max_score"])
    logger.info(
        "Spec: %s negotiated (latest: %s) · era: %s",
        spec["negotiated_version"] or "unknown",
        spec["latest_version"],
        spec["era"] or "unknown",
    )
    if readiness["max_score"] > 0:
        assessed = len(readiness.get("results", []))
        skipped = readiness.get("skipped", 0)
        coverage = f"; {assessed} of {assessed + skipped} checks assessed" if skipped else ""
        logger.info(
            "Readiness for MCP %s: %s/%s (%s%s)",
            spec["readiness_target"],
            readiness["score"],
            readiness["max_score"],
            "counted in the main score — modern-lifecycle server"
            if readiness.get("counted_in_main")
            else "informative — not part of the main score",
            coverage,
        )
    else:
        logger.info(
            "Readiness for MCP %s: not assessed (no usable probe observations)",
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


async def _apply_oauth(args: argparse.Namespace, headers: dict[str, str], target: str | StdioCommand) -> None:
    """Run the --oauth browser flow and place the token into the header dict.

    Exits with code 1 on flag conflicts or a failed flow; a no-op when
    --oauth was not requested.
    """
    if (args.client_id is not None or args.callback_port is not None) and not args.oauth:
        logger.error("Usage error: --client-id / --callback-port only make sense together with --oauth")
        sys.exit(1)
    if not args.oauth:
        return
    if args.callback_port is not None and not 1 <= args.callback_port <= 65535:
        logger.error("Usage error: --callback-port must be between 1 and 65535")
        sys.exit(1)
    if has_authorization_credential(headers):
        logger.error(
            "Usage error: --oauth conflicts with an existing Authorization credential "
            "(--token, an Authorization --header, or the MCPSCORE_TOKEN environment variable) — pick one"
        )
        sys.exit(1)
    if not isinstance(target, str) or not target.startswith(("http://", "https://")):
        logger.error("Usage error: --oauth requires an HTTP(S) server URL")
        sys.exit(1)
    from mcpscore.oauth import OAuthFlowError, obtain_token_interactively

    try:
        access_token = await obtain_token_interactively(
            target, client_id=args.client_id, callback_port=args.callback_port
        )
    except OAuthFlowError as e:
        logger.error("OAuth: %s", e)  # noqa: TRY400 — user-facing outcome, not a traceback
        sys.exit(1)
    # Replace any case-variant of the header (e.g. a blank 'authorization:')
    # so the wire never carries duplicate Authorization headers.
    for key in [name for name in headers if name.lower() == "authorization"]:
        del headers[key]
    headers["Authorization"] = f"Bearer {access_token}"
    logger.info("OAuth flow completed — token held in memory only for this audit.")


async def async_main() -> None:
    """Execute the main entry point for the mcpscore CLI application.

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
    # Parse before greeting: --version and --help exit during parsing, and
    # neither should be preceded by a banner.
    args = build_parser().parse_args()

    # Resolve the target before greeting: an invalid target/--stdio combination
    # is a usage error, and (like argparse's own) it should not be preceded by
    # a banner.
    try:
        target = resolve_target(args)
    except ValueError as e:
        logger.error("Usage error: %s", e)  # noqa: TRY400 — usage error, not an exception to trace
        sys.exit(1)

    logger.info("Welcome to mcpscore!")

    # A package audit shares no machinery with a server audit past this point:
    # no headers, no OAuth, no client, no transport detection, no cleanup.
    if isinstance(target, PackageCoordinate):
        sys.exit(await run_package_audit(args, target))

    try:
        headers = collect_headers(args)
    except ValueError as e:
        logger.error("Usage error: %s", e)  # noqa: TRY400 — usage error, not an exception to trace
        sys.exit(1)

    # What the report and log lines call the target: the URL/path itself, or
    # the joined command line for a --stdio server.
    target_display = target if isinstance(target, str) else target.display

    await _apply_oauth(args, headers, target)

    if headers:
        logger.info("Using %d custom header(s).", len(headers))

    client: MCPClient = MCPClient(headers=headers or None)
    auditor: MCPAuditor = MCPAuditor(headers=headers or None)

    # Everything below runs inside one try/finally: failed detection attempts
    # can leave resources on the client's exit stack, so every path out —
    # early returns, sys.exit(2), audit errors — must reach cleanup().
    try:
        success, transport = await client.detect_and_connect(target)

        if not success:
            if isinstance(target, str) and target.startswith(("http://", "https://")):
                logger.info("Legacy connection failed — checking for a modern-only (stateless lifecycle) MCP server...")
                if await auditor.audit_modern_only(target):
                    logger.info(
                        "Modern-only MCP server detected: audited via stateless probes (no legacy session available)."
                    )
                    finish_server_audit(args, auditor, target_display, auditor.audit_data.transport_type)
                    return

                failure = client.last_connection_error
                session_gated = failure is not None and failure.reason in (
                    ConnectionErrorReason.UNAUTHORIZED,
                    ConnectionErrorReason.FORBIDDEN,
                )
                # A gated server does not always *fail* with 401: when it serves
                # no legacy endpoint the handshake dies on something else (405
                # on the SSE fallback is the common shape) and only the probes
                # see the challenge. Trust that observation too, or ~29% of
                # gated servers report as unreachable while we hold their
                # WWW-Authenticate and RFC 9728 metadata.
                probed_status = observed_auth_status(auditor.last_probes)
                if session_gated or probed_status is not None:
                    # Report the status of the *gate*, not of whatever ended the
                    # session: a server whose SSE fallback answers 405 is still
                    # gated at 401, and saying "requires authentication (HTTP
                    # 405)" would send the reader hunting the wrong problem.
                    if session_gated:
                        assert failure is not None  # noqa: S101 — session_gated implies it
                        status = failure.status_code or (
                            403 if failure.reason is ConnectionErrorReason.FORBIDDEN else 401
                        )
                    else:
                        status = probed_status or 401
                    # Key off the same predicate as the report's authenticated
                    # flag: only an Authorization credential counts — a 401
                    # with only tracing/custom headers is a missing credential,
                    # not a rejected one.
                    #
                    # "Rejected" additionally requires that the *session* was
                    # the thing refused. The probe that reports a gate runs
                    # `anonymous=True` — it strips the Authorization header —
                    # so its 401 says the endpoint is gated and nothing at all
                    # about the caller's token. When the session died of
                    # something else (405 on the SSE fallback), the credential
                    # was never exercised, and telling the user it was rejected
                    # sends them to re-issue a token that is probably fine.
                    credentials_rejected = session_gated and has_authorization_credential(headers)
                    if credentials_rejected:
                        logger.info(
                            "Server rejected the provided credentials — "
                            "running a partial audit of the observable surface."
                        )
                        logger.info("(Check that the --token/--header credentials are valid for this server.)")
                        partial_reason = (
                            f"Server rejected the provided credentials (HTTP {status}); scored the unauthenticated "
                            "surface only — check that the token or headers are valid for this server."
                        )
                    elif not session_gated and has_authorization_credential(headers):
                        # Gated per an anonymous probe, but the session failed
                        # separately — say so, and do not blame the credential.
                        session_status = failure.status_code if failure is not None else None
                        detail = f" (HTTP {session_status})" if session_status else ""
                        logger.info(
                            "Server requires authentication, and the session could not be established%s — "
                            "running a partial audit of the observable surface.",
                            detail,
                        )
                        logger.info(
                            "(Your credentials were not exercised: the connection failed before they were used.)"
                        )
                        partial_reason = (
                            f"Server requires authentication (HTTP {status}); the session could not be "
                            f"established{detail}, so the supplied credentials were never exercised — scored the "
                            "unauthenticated surface only."
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
                    await auditor.audit_partial(target, reason=partial_reason)
                    finish_server_audit(args, auditor, target_display, auditor.audit_data.transport_type)
                    return
            logger.error("Error connecting to the MCP server: %s", target_display)
            sys.exit(2)

        logger.info("Connected to the MCP server: %s", target_display)
        logger.info("Transport: %s", transport)

        logger.info("Starting the audit...")
        await auditor.audit(client)
        # A gate failure exits inside the try and still reaches cleanup() via
        # finally; the happy path returns normally (no SystemExit(0)).
        finish_server_audit(args, auditor, target_display, transport)
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
