from __future__ import annotations
import asyncio
from mcp import types
from cisco_mcp_server.server import CiscoMCPServer
from cisco_mcp_server.settings import Settings


def test_mcp_sdk_resource_dispatch_uses_temporary_fictional_inventory(tmp_path):
    inventory = tmp_path / 'inventory.ini'
    inventory.write_text('[lab]\nlab-core ansible_host=192.0.2.10\n')
    server = CiscoMCPServer(Settings(inventory_path=inventory, data_dir=tmp_path / 'artifacts'))
    request = types.ReadResourceRequest(method='resources/read', params=types.ReadResourceRequestParams(uri='cisco://investigation-standards'))
    result = asyncio.run(server.app.request_handlers[types.ReadResourceRequest](request))
    assert result.root.contents[0].text
    tools = asyncio.run(server.list_tools())
    assert {'run_discovery', 'investigate_network_question', 'audit_connected_devices'} <= {tool.name for tool in tools}
