"""Runtime settings loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_OPS_DIR = Path("~/.local/share/cisco-mcp-next").expanduser()
DEFAULT_INVENTORY_PATH = Path("~/.config/cisco-mcp/inventory.yml").expanduser()
DEFAULT_DATA_DIR = DEFAULT_OPS_DIR / "artifacts"


@dataclass(frozen=True)
class Settings:
    inventory_path: Path
    data_dir: Path
    default_timeout_seconds: int = 60

    @classmethod
    def from_env(cls) -> Settings:
        inventory = Path(os.getenv("CISCO_MCP_INVENTORY", str(DEFAULT_INVENTORY_PATH))).expanduser()
        data_dir = Path(os.getenv("CISCO_MCP_DATA_DIR", str(DEFAULT_DATA_DIR))).expanduser()
        timeout = int(os.getenv("CISCO_MCP_COMMAND_TIMEOUT", "60"))
        return cls(inventory_path=inventory, data_dir=data_dir, default_timeout_seconds=timeout)
