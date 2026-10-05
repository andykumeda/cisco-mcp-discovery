"""Optional MCP SDK integration checks; skip cleanly in the zero-dependency demo."""
import asyncio
import tempfile
import unittest
from unittest.mock import patch
from cisco_mcp.demo import DemoSSH
try:
    from cisco_mcp.server import CiscoMCPServer
    from mcp import types
    AVAILABLE = True
except ImportError:
    AVAILABLE = False

@unittest.skipUnless(AVAILABLE, 'Install requirements.txt to exercise MCP SDK handlers')
class ServerTests(unittest.TestCase):
    def test_sdk_resource_handler_and_tools(self):
        with tempfile.TemporaryDirectory() as folder, patch('cisco_mcp.storage.USER_DATA_DIR', folder), patch('cisco_mcp.visualization.USER_DATA_DIR', folder), patch('cisco_mcp.config.ConfigManager.is_user_authorized', return_value=True):
            server = CiscoMCPServer()
            request = types.ReadResourceRequest(method='resources/read', params=types.ReadResourceRequestParams(uri='cisco://command-history'))
            result = asyncio.run(server.app.request_handlers[types.ReadResourceRequest](request))
            self.assertEqual(result.root.contents[0].text, '[]')
            self.assertEqual({t.name for t in asyncio.run(server.list_tools())}, {'run_command', 'discover_network', 'get_topology_diagram'})
            server.discovery.ssh = DemoSSH()
            result = asyncio.run(server.call_tool('discover_network', {'host':'192.0.2.10','depth':2}))
            self.assertIn('3 nodes and 2 links', result[0].text)
            result = asyncio.run(server.call_tool('get_topology_diagram', {}))
            self.assertIn('Diagram generated locally', result[0].text)
            request = types.ReadResourceRequest(method='resources/read', params=types.ReadResourceRequestParams(uri='cisco://topology.drawio'))
            result = asyncio.run(server.app.request_handlers[types.ReadResourceRequest](request))
            self.assertIn('<mxfile', result.root.contents[0].text)

    def test_os_group_authorization_is_required(self):
        with patch('cisco_mcp.config.ConfigManager.is_user_authorized', return_value=False):
            with self.assertRaises(PermissionError): CiscoMCPServer()
