"""Console entrypoint."""

from __future__ import annotations

import asyncio
import logging
import sys

from cisco_mcp_server.server import CiscoMCPServer


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)],
    )
    try:
        asyncio.run(CiscoMCPServer().run())
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
