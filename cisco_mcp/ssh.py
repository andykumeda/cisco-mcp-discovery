import asyncio
import os
import logging
import subprocess
import shutil
import re
import ipaddress
import traceback
from typing import Dict, Any, List, Optional
from cisco_mcp.config import ConfigManager
from cisco_mcp.storage import StorageManager

# Try importing Genie
GENIE_AVAILABLE = False
try:
    from genie.libs.parser.utils import get_parser
    try:
         # Attempt to import Device from unicon/pyats if needed,
         # but for "Zero Install" we might need to rely on the 'pyATS_MCP' logic
         # of dynamic testbed creation if we want full Unicon support.
         # For now, we will use the 'pyATS_MCP' strategy of ad-hoc parsing where possible
         # or use a mock device object if get_parser requires it.
         from pyats.topology import Device
    except ImportError:
         Device = None
    GENIE_AVAILABLE = True
except ImportError:
    pass

logger = logging.getLogger(__name__)

from cisco_mcp.config import ConfigManager, MCP_USER, MCP_REMOTE_HOST, BASE_DIR

# Constants - using standardized config
MCP_KEY_PATH = os.path.expanduser(os.getenv("CISCO_MCP_KEY_PATH", "~/.ssh/cisco_mcp_id_ed25519"))
AUTH_USER = MCP_USER
AUTH_KEY_PATH = MCP_KEY_PATH


class CiscoSSHManager:
    def __init__(self):
        self.config = ConfigManager()
        self.storage = StorageManager()

    def validate_ip_or_hostname(self, host):
        """Validate if input is a valid IP address or hostname"""
        try:
            ipaddress.ip_address(host)
            return True, "ip"
        except ValueError:
            # Check for valid hostname (RFC 1123)
            if isinstance(host, str) and len(host) <= 253 and all(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                for part in host.split(".")):
                return True, "hostname"
            return False, "invalid"

    async def execute_ssh_command_direct(
        self,
        host: str,
        command: str,
        port: int = 22,
        enforce_whitelist: bool = True,
        use_genie: bool = False
    ) -> Dict[str, Any]:
        """
        Execute a command directly on a host via SSH.
        If use_genie is True, attempts to parse the output into JSON.
        """
        warnings: List[str] = []

        if os.getenv("CISCO_MCP_ENABLE_SSH") != "1":
            return {"success": False, "status": "ssh_disabled", "error": "Live SSH is disabled; enable explicitly for an authorized lab.", "output": "", "return_code": -1}
        allowed = (self.config.is_host_allowed(host) if enforce_whitelist
                   else self.config.is_discovery_host_allowed(host))
        if not allowed:
            return {"success": False, "status": "host_outside_scope", "error": "Host is outside the explicit permitted scope.", "output": "", "return_code": -1}

        # 2. Validate Host Format
        is_valid, _ = self.validate_ip_or_hostname(host)
        if not is_valid:
             return {
                "success": False,
                "error": f"Invalid host format: {host}",
                "output": "",
                "return_code": -1
             }

        # 3. Validate Command Security
        validation_result = self.config.validate_read_only_command(command)
        if not validation_result["valid"]:
             return {
                "success": False,
                "error": f"SECURITY VIOLATION: {validation_result['error']}",
                "output": "",
                "return_code": -1,
                "security_category": validation_result.get("category"),
             }

        # 4. Execute via SSH (Raw)
        # We stick to raw SSH for simplicity and "zero client install" robustness
        # (avoiding complex Unicon state machines for simple one-off commands unless necessary)
        # Note: In a full refactor, we could switch this execution to use Unicon if installed.
        cmd_result = await self._run_raw_ssh(host, command, port, AUTH_USER, AUTH_KEY_PATH)

        result_payload = cmd_result
        if warnings:
            result_payload.setdefault("warnings", []).extend(warnings)

        # 5. Genie Parsing (The New Feature)
        if use_genie and cmd_result["success"] and GENIE_AVAILABLE:
            try:
                parsed = self._parse_with_genie(command, cmd_result["output"], host)
                if parsed:
                    result_payload["parsed_output"] = parsed
                    result_payload["is_parsed"] = True
                else:
                    result_payload["is_parsed"] = False
                    result_payload["warnings"] = result_payload.get("warnings", []) + ["Genie parser not found or parsing failed; returned raw output."]
            except Exception as e:
                logger.error(f"Genie parsing failed: {e}")
                result_payload["is_parsed"] = False
                result_payload["warnings"] = result_payload.get("warnings", []) + [f"Genie parsing error: {str(e)}"]

        # 6. Save History
        self.storage.add_to_history(
            host=host,
            command=command,
            success=cmd_result["success"],
            output=cmd_result["output"],
            error=cmd_result.get("error")
        )

        return result_payload

    async def _run_raw_ssh(self, host, command, port, username, key_path):
        """Helper to run non-interactive SSH subprocess"""
        try:
            logger.info(f"Executing '{command}' on {host} as {username} via SSH...")
            ssh_cmd = [
                'ssh',
                '-i', key_path,
                '-o', 'ConnectTimeout=15',
                '-o', 'StrictHostKeyChecking=yes',
                '-o', 'LogLevel=ERROR',
                '-o', 'BatchMode=yes',
                '-p', str(port),
                f"{username}@{host}",
                command
            ]

            loop = asyncio.get_running_loop()
            process = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    ssh_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
            )

            if process.returncode != 0:
                error_msg = process.stderr.strip()
                return {
                    "success": False,
                    "output": process.stdout,
                    "error": f"Command failed with return code {process.returncode}: {error_msg}",
                    "return_code": process.returncode,
                    "host": host,
                    "command": command
                }

            return {
                "success": True,
                "output": process.stdout,
                "error": None,
                "return_code": process.returncode,
                "host": host,
                "command": command
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Command execution timeout (60s)",
                "output": "",
                "return_code": -1,
                "host": host
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"SSH execution error: {str(e)}",
                "output": "",
                "return_code": -1,
                "host": host
            }

    def _parse_with_genie(self, command: str, output: str, hostname: str) -> Optional[Dict]:
        """
        Attempt to parse output using Genie.
        We simulate a Device object because Genie parsers often require one with an 'os' attribute.
        """
        # Heuristic to guess OS if not known - default to iosxe for common commands,
        # or we could try to detect from output. For now, try iosxe then nxos.

        # We need a mock device object that Genie accepts
        class MockDevice:
            def __init__(self, os_type):
                self.os = os_type
                self.name = hostname
                self.custom = {} # Parser often looks for this

        # Try parsing as IOS-XE first
        try:
            device = MockDevice("iosxe")
            parser = get_parser(command, device)
            if parser:
                return parser.parse(text=output, received_command=command)
        except Exception:
            pass

        # Try parsing as NX-OS
        try:
             device = MockDevice("nxos")
             parser = get_parser(command, device)
             if parser:
                 return parser.parse(text=output, received_command=command)
        except Exception:
            pass

        return None
