#!/usr/bin/env python3
import asyncio
import logging
import sys
from cisco_mcp.server import CiscoMCPServer

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)

if __name__ == "__main__":
    server = CiscoMCPServer()
    try:
        asyncio.run(server.run())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.critical(f"Fatal error: {e}")
        sys.exit(1)
