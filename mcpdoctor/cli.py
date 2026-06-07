"""Command-line interface for MCPDoctor."""

import asyncio
import logging
import sys

from mcpdoctor import MCPClient, MCPDoctor

logger = logging.getLogger(__name__)


async def async_main() -> None:
    """Execute the main entry point for the MCPDoctor CLI application.

    Orchestrates the audit process by:
    1. Parsing command line arguments for the server path or URL
    2. Creating MCP client and doctor instances
    3. Auto-detecting transport and connecting to the MCP server
    4. Running the audit process and displaying results
    5. Cleaning up resources

    Supports local servers (.py, .js) via STDIO and remote servers via
    Streamable HTTP or SSE (auto-detected).

    Exits with code 1 if no server path is provided, or code 2 if connection fails.
    """
    logger.info("Welcome to MCPDoctor!")

    if len(sys.argv) < 2:
        logger.error("Usage: mcpdoctor <server_path_or_url>")
        sys.exit(1)

    target: str = sys.argv[1]
    client: MCPClient = MCPClient()
    doctor: MCPDoctor = MCPDoctor()

    success, transport = await client.detect_and_connect(target)

    if success:
        logger.info("Connected to the MCP server: %s", target)
        logger.info("Transport: %s", transport)
    else:
        logger.error("Error connecting to the MCP server: %s", target)
        sys.exit(2)

    logger.info("Starting the audit...")
    final_score, max_score = await doctor.audit(client)
    logger.info("Audit finished. Final score: %s/%s", final_score, max_score)

    await client.cleanup()


def main() -> None:
    """Entry point for the mcpdoctor CLI command.

    This function is called when running `mcpdoctor` from the command line.
    It sets up logging and runs the async main function.
    """
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
