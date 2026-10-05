from mcp.server import Server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
)
import json
import logging
import traceback
from typing import Any, List, Dict
from cisco_mcp.ssh import CiscoSSHManager
from cisco_mcp.discovery import DiscoveryEngine
from cisco_mcp.visualization import VisualizationEngine
from cisco_mcp.config import ConfigManager, MCP_USER, MCP_USER_GROUP

logger = logging.getLogger(__name__)

class CiscoMCPServer:
    def __init__(self):
        self.config = ConfigManager()
        # Security Check: Ensure user is authorized to run as MCP_USER
        if not self.config.is_user_authorized():
             import getpass
             curr = getpass.getuser()
             logger.error(f"FATAL: User '{curr}' is not authorized. Must be in group '{MCP_USER_GROUP}'.")
             raise PermissionError(f"User '{curr}' is not in required group '{MCP_USER_GROUP}'")

        self.ssh = CiscoSSHManager()
        self.discovery = DiscoveryEngine(self.ssh)
        self.viz = VisualizationEngine()
        self.app = Server("cisco-mcp-server")

        # Register handlers
        self.app.list_resources()(self.list_resources)
        self.app.read_resource()(self.read_resource)
        self.app.list_tools()(self.list_tools)
        self.app.call_tool()(self.call_tool)

    async def list_resources(self) -> List[Resource]:
        return [
            Resource(
                uri="cisco://command-history",
                name="Command History",
                description="Recent command execution history",
                mimeType="application/json"
            ),
            Resource(
                uri="cisco://topology.drawio",
                name="Last Topology Diagram",
                description="The most recently generated Draw.io XML topology diagram",
                mimeType="application/xml"
            )
        ]

    async def read_resource(self, uri):
        from mcp.server.lowlevel.helper_types import ReadResourceContents
        import os
        from cisco_mcp.visualization import USER_DATA_DIR
        uri = str(uri)
        if uri == "cisco://command-history":
            return [ReadResourceContents(content=json.dumps(self.ssh.storage.get_history(50), indent=2), mime_type="application/json")]
        if uri == "cisco://topology.drawio":
            path = os.path.join(USER_DATA_DIR, "topology.drawio")
            if os.path.exists(path):
                with open(path, encoding="utf-8") as handle:
                    return [ReadResourceContents(content=handle.read(), mime_type="application/xml")]
            return [ReadResourceContents(content="No diagram generated yet. Run 'get_topology_diagram' first.", mime_type="text/plain")]
        raise ValueError(f"Unknown resource: {uri}")

    async def list_tools(self) -> List[Tool]:
        return [
            Tool(
                name="run_command",
                description="Execute a command on a Cisco device. Optionally parse output into structured JSON using Genie.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "IP or Hostname of the device"},
                        "command": {"type": "string", "description": "Command to execute (e.g., 'show version')"},
                        "parse": {"type": "boolean", "default": False, "description": "Whether to return structured JSON data"}
                    },
                    "required": ["host", "command"]
                }
            ),
            Tool(
                name="discover_network",
                description="Discover network topology starting from a seed host using CDP, LLDP, and ARP tables.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "host": {"type": "string", "description": "Seed host IP/Hostname"},
                        "depth": {"type": "integer", "default": 3, "minimum": 0, "maximum": 10, "description": "Recursion depth (number of hops)"}
                    },
                    "required": ["host"]
                }
            ),
             Tool(
                name="get_topology_diagram",
                description="Generate and provide a download link/method for the network topology diagram.",
                inputSchema={"type": "object", "properties": {}}
            )
        ]

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> List[Any]:
        try:
            if name == "run_command":
                use_genie = arguments.get("parse", False)
                res = await self.ssh.execute_ssh_command_direct(arguments["host"], arguments["command"], use_genie=use_genie)
                if use_genie:
                    if res.get("is_parsed"):
                         return [TextContent(type="text", text=json.dumps(res["parsed_output"], indent=2))]
                    else:
                         return [TextContent(type="text", text=f"Parsing Failed (Returning Raw):\n{res.get('output')}")]
                else:
                    return [TextContent(type="text", text=res.get("output", "") or res.get("error", "Unknown Error"))]

            elif name == "discover_network":
                topo = await self.discovery.discover_devices(arguments["host"], arguments.get("depth", 3))
                self.ssh.storage.save_topology({"topology": topo, "start_host": arguments["host"]})
                return [TextContent(type="text", text=f"Discovery Complete. Found {len(topo['nodes'])} nodes and {len(topo['links'])} links.\nWarnings: {json.dumps(topo['warnings'])}\nUse 'get_topology_diagram' to view.")]

            elif name == "get_topology_diagram":
                data = self.ssh.storage.load_topology()
                if not data:
                    return [TextContent(type="text", text="No topology found. Run 'discover_network' first.")]

                path, xml = self.viz.export_topology_to_drawio(data.get("topology"), data.get("start_host"))


                return [TextContent(type="text", text=f"Diagram generated locally: {path}\nRead MCP resource cisco://topology.drawio or open the file in a trusted local Draw.io editor.")]

            else:
                raise ValueError(f"Unknown tool: {name}")

        except Exception as e:
            logger.error(f"Tool error: {e}")
            return [TextContent(type="text", text=f"Error: {str(e)}")]

    async def run(self):
        from mcp.server.stdio import stdio_server
        async with stdio_server() as (read_stream, write_stream):
            await self.app.run(read_stream, write_stream, self.app.create_initialization_options())
