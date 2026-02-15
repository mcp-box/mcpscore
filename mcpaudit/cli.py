"""Command-line interface for MCPAudit."""

import asyncio
import logging
import sys

from mcpaudit import MCPAuditor, MCPClient, MCPTransportType

logger = logging.getLogger(__name__)


async def async_main() -> None:
    """Execute the main entry point for the MCPAudit CLI application.

    Orchestrates the audit process by:
    1. Parsing command line arguments for the server script path
    2. Creating MCP client and auditor instances
    3. Connecting to the MCP server via stdio transport
    4. Running the audit process and displaying results
    5. Cleaning up resources

    Exits with code 1 if no server path is provided, or code 2 if connection fails.
    """
    logger.info("Welcome to MCPAudit!")

    if len(sys.argv) < 2:
        logger.error("Usage: mcpaudit <path_to_server_script>")
        sys.exit(1)

    mcp_transport: MCPTransportType = MCPTransportType.STDIO
    mcp_path: str = sys.argv[1]
    client: MCPClient = MCPClient()
    auditor: MCPAuditor = MCPAuditor()

    success: bool = await client.connect_to_server(mcp_transport, mcp_path)

    if success:
        logger.info("Connected to the MCP server: %s", mcp_path)
        logger.info("Transport: %s", mcp_transport)
    else:
        logger.error("Error connecting to the MCP server: %s", mcp_path)
        sys.exit(2)

    logger.info("Starting the audit...")
    final_score, max_score = await auditor.audit(client)
    logger.info("Audit finished. Final score: %s/%s", final_score, max_score)

    await client.cleanup()


def main() -> None:
    """Entry point for the mcpaudit CLI command.

    This function is called when running `mcpaudit` from the command line.
    It sets up logging and runs the async main function.
    """
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
