"""Backwards compatibility wrapper for MCPAudit CLI.

This file is kept for backwards compatibility with the old usage:
    python main.py <path_to_server_script>

New usage (after pip install):
    mcpaudit <path_to_server_script>
"""

from mcpaudit.cli import main

if __name__ == "__main__":
    main()
