import os
import re
import logging
import ipaddress
from pathlib import Path
from typing import List, Set

# Configure logging
logger = logging.getLogger(__name__)

# Get the base directory (where the cisco_mcp package is located)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Constants - use environment variables with fallback to relative paths
WHITELIST_FILE = os.getenv("CISCO_MCP_HOSTS_FILE", os.path.join(BASE_DIR, "hosts"))
COMMAND_WHITELIST_FILE = os.getenv("CISCO_MCP_CMD_WHITELIST", os.path.join(BASE_DIR, "command_whitelist.txt"))
COMMAND_BLACKLIST_FILE = os.getenv("CISCO_MCP_CMD_BLACKLIST", os.path.join(BASE_DIR, "command_blacklist.txt"))

# User and Server info
MCP_USER = os.getenv("CISCO_MCP_USER", "mcpuser")
MCP_REMOTE_HOST = os.getenv("CISCO_MCP_REMOTE_HOST", "")
DATA_DIR = os.path.expanduser(os.getenv("CISCO_MCP_DATA_DIR", "~/.local/share/cisco-mcp"))
MCP_USER_GROUP = os.getenv("CISCO_MCP_GROUP", "mcpusers")

# Dynamic System Info (for remote file copies)
import getpass
SYSTEM_USER = getpass.getuser()

class ConfigManager:
    def __init__(self):
        self.whitelist = self.load_whitelist()
        self.command_whitelist = self.load_command_whitelist()
        self.command_blacklist = self.load_command_blacklist()

    def is_user_authorized(self) -> bool:
        """Verify if current system user is allowed to run as MCP_USER."""
        import grp
        import getpass
        try:
            current_user = getpass.getuser()
            # User must be member of MCP_USER_GROUP
            group_info = grp.getgrnam(MCP_USER_GROUP)
            return current_user in group_info.gr_mem or current_user == "root"
        except KeyError:
            logger.error(f"Group '{MCP_USER_GROUP}' not found on system.")
            return False
        except Exception as e:
            logger.error(f"Auth check error: {e}")
            return False

    def _load_command_patterns(self, file_path: str) -> List[str]:
        """Load command patterns from a file (one regex per line)."""
        patterns = []
        try:
            if os.path.exists(file_path):
                with open(file_path, "r") as f:
                    for line in f:
                        pattern = line.strip()
                        if pattern and not pattern.startswith("#"):
                            patterns.append(pattern)
        except Exception as e:
            logger.error(f"Error loading command patterns from {file_path}: {e}")
        return patterns

    def load_command_whitelist(self) -> List[str]:
        """Load allowed command patterns from the whitelist file."""
        return self._load_command_patterns(COMMAND_WHITELIST_FILE)

    def load_command_blacklist(self) -> List[str]:
        """Load blocked command patterns from the blacklist file."""
        return self._load_command_patterns(COMMAND_BLACKLIST_FILE)

    def load_whitelist(self) -> Set[str]:
        """Load allowed hosts from hosts file, ignoring lines starting with [ or #"""
        whitelist = set()
        try:
            if os.path.exists(WHITELIST_FILE):
                with open(WHITELIST_FILE, "r") as f:
                    for line in f:
                        host = line.strip()
                        if not host or host.startswith("#") or host.startswith("["):
                            continue
                        # Skip Ansible group references (usually contain underscores and aren't valid IPs)
                        if "_" in host and not re.match(r"^[0-9\.]+$", host):
                            continue
                        whitelist.add(host)
        except Exception as e:
            logger.error(f"Error loading whitelist: {e}")
        return whitelist

    def is_host_allowed(self, host: str) -> bool:
        """Check if host is in the whitelist (exact match)"""
        # Reload whitelist every time for dynamic updates (optional: cache for perf)
        self.whitelist = self.load_whitelist()
        return host in self.whitelist

    def is_discovery_host_allowed(self, host: str) -> bool:
        """Neighbors require an exact allowlist entry or explicit numeric CIDR scope."""
        if self.is_host_allowed(host):
            return True
        try:
            address = ipaddress.ip_address(host)
            scopes = [ipaddress.ip_network(x.strip(), strict=True)
                      for x in os.getenv("CISCO_MCP_DISCOVERY_CIDRS", "").split(",") if x.strip()]
            return any(address in scope for scope in scopes)
        except ValueError:
            return False

    def validate_read_only_command(self, command: str) -> dict:
        """
        Validate that command is read-only and safe to execute.
        The logic prioritizes security by checking the blacklist first.
        """
        if not isinstance(command, str) or not command.strip() or any(
                ord(ch) < 32 or ch in ";|&`$<>\\" for ch in command):
            return {"valid": False, "error": "Command separators and control characters are blocked.",
                    "category": "blocked_operation"}
        command_clean = command.strip().lower()

        # PRIORITY 1: Check against the blacklist first.
        for pattern in self.command_blacklist:
            if re.match(pattern, command_clean):
                return {
                    "valid": False,
                    "error": f"Command '{command}' is on the blacklist and is not allowed.",
                    "category": "blocked_operation",
                    "suggestion": "This command is explicitly blocked by the administrator."
                }

        # PRIORITY 2: Check against whitelists.
        for pattern in self.command_whitelist:
            if re.match(pattern, command_clean):
                return {
                    "valid": True,
                    "category": "read_only",
                    "command_type": "general_info"
                }

        # PRIORITY 3: Default Deny if not on any whitelist.
        return {
            "valid": False,
            "error": f"Command '{command}' is not in the allowed read-only command list.",
            "category": "unknown_command",
            "suggestion": "Use 'show' commands or other explicitly allowed commands."
        }
