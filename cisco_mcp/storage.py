import os
import json
import logging
import getpass
from datetime import datetime
from typing import List, Dict, Any
from cisco_mcp.config import MCP_USER, DATA_DIR

logger = logging.getLogger(__name__)

# User Data setup
USER_DATA_DIR = DATA_DIR

class StorageManager:
    def __init__(self):
        self.command_history_file = os.path.join(USER_DATA_DIR, "command_history.json")
        self.topology_file = os.path.join(USER_DATA_DIR, "last_topology.json")
        os.makedirs(USER_DATA_DIR, mode=0o700, exist_ok=True)
        os.chmod(USER_DATA_DIR, 0o700)
        self.command_history = self.load_command_history()

    def load_command_history(self) -> List[Dict]:
        """Load command history"""
        try:
            if os.path.exists(self.command_history_file):
                with open(self.command_history_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading command history: {e}")
        return []

    def save_command_history(self):
        """Save command history"""
        try:
            # Keep only last 100 commands
            if len(self.command_history) > 100:
                self.command_history = self.command_history[-100:]
            with open(os.open(self.command_history_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w', encoding='utf-8') as f:
                json.dump(self.command_history, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving command history: {e}")

    def add_to_history(self, host, command, success, output=None, error=None):
        """Add command to history"""
        history_entry = {
            "timestamp": datetime.now().isoformat(),
            "user": MCP_USER,
            "host": host,
            "command": command,
            "success": success,
            "output_length": len(output) if output else 0,
            "error": error
        }
        self.command_history.append(history_entry)
        self.save_command_history()

    def get_history(self, limit: int = 20) -> List[Dict]:
        return self.command_history[-limit:] if self.command_history else []

    def save_topology(self, topology_data: Dict[str, Any]):
        try:
            with open(os.open(self.topology_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as f:
                json.dump(topology_data, f)
        except Exception as e:
            logger.error(f"Failed to save topology: {e}")

    def load_topology(self) -> Dict[str, Any]:
        if not os.path.exists(self.topology_file):
            return {}
        try:
            with open(self.topology_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading topology: {e}")
            return {}
