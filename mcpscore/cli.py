"""Command-line interface for MCPScore."""

from __future__ import annotations

import argparse
import asyncio
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
import json
import logging
import sys
from typing import TYPE_CHECKING, NoReturn

from mcpscore import MCPAuditor, MCPClient

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
    return parser


def _mcpscore_version() -> str:
    """Return the installed mcpscore package version, or "unknown"."""
    try:
        return version("mcpscore")
    except PackageNotFoundError:  # pragma: no cover - only without package metadata
        return "unknown"


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
    Streamable HTTP or SSE (auto-detected).

    Exits with code 1 on usage errors, or code 2 if connection fails.
    """
    logger.info("Welcome to MCPScore!")

    args = build_parser().parse_args()

    client: MCPClient = MCPClient()
    auditor: MCPAuditor = MCPAuditor()

    success, transport = await client.detect_and_connect(args.target)

    if not success:
        logger.error("Error connecting to the MCP server: %s", args.target)
        sys.exit(2)

    logger.info("Connected to the MCP server: %s", args.target)
    logger.info("Transport: %s", transport)

    try:
        logger.info("Starting the audit...")
        final_score, max_score = await auditor.audit(client)
        logger.info("Audit finished. Final score: %s/%s", final_score, max_score)

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
