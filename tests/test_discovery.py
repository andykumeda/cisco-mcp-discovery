import asyncio
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch, AsyncMock
import xml.etree.ElementTree as ET

from cisco_mcp.config import ConfigManager
from cisco_mcp.demo import DemoSSH, SEED, run_demo
from cisco_mcp.discovery import DiscoveryEngine
from cisco_mcp.ssh import CiscoSSHManager
from cisco_mcp import visualization

class DiscoveryTests(unittest.TestCase):
    def test_bidirectional_link_dedup_and_lldp(self):
        ssh = DemoSSH()
        topo = asyncio.run(DiscoveryEngine(ssh).discover_devices(SEED, 2))
        self.assertEqual(len(topo['nodes']), 3)
        self.assertEqual(len(topo['links']), 2)
        self.assertTrue(any(l['source_int'] == 'Gi1/0/2' for l in topo['links']))
        self.assertEqual({h for h, _ in ssh.calls}, {'192.0.2.10', '192.0.2.20', '192.0.2.30'})

    def test_scope_and_depth_stop_queries(self):
        ssh = DemoSSH()
        ssh.config.is_discovery_host_allowed = lambda h: h == SEED
        topo = asyncio.run(DiscoveryEngine(ssh).discover_devices(SEED, 2))
        self.assertEqual({h for h, _ in ssh.calls}, {SEED})
        self.assertEqual(len(topo['warnings']), 2)
        ssh = DemoSSH()
        asyncio.run(DiscoveryEngine(ssh).discover_devices(SEED, 0))
        self.assertEqual({h for h, _ in ssh.calls}, {SEED})
        with self.assertRaises(ValueError):
            asyncio.run(DiscoveryEngine(ssh).discover_devices(SEED, -1))

    def test_limit_and_denied_seed(self):
        ssh = DemoSSH()
        topo = asyncio.run(DiscoveryEngine(ssh).discover_devices(SEED, 2, max_devices=1))
        self.assertEqual(len(topo['nodes']), 1)
        self.assertTrue(topo['warnings'])
        ssh = DemoSSH()
        topo = asyncio.run(DiscoveryEngine(ssh).discover_devices('192.0.2.99', 2))
        self.assertEqual(ssh.calls, [])
        self.assertEqual(topo['nodes'], [])

    def test_arp_resolution_is_per_neighbor(self):
        class ARPSSH(DemoSSH):
            async def execute_ssh_command_direct(self, host, command, **kwargs):
                if host == SEED and command == 'show cdp neighbors detail':
                    return {'success': True, 'output': '\n-------------------------\n'.join(
                        f'Device ID: lab-{name}\nRemote Interface MAC: {mac}\nInterface: Gi1/0/{i}, Port ID (outgoing port): Gi1/0/48'
                        for i, name, mac in [(1,'access','0011.2233.4455'),(2,'edge','0011.2233.4466')])}
                if host == SEED and command == 'show ip arp':
                    return {'success': True, 'output': 'Internet 192.0.2.20 1 0011.2233.4455 ARPA Gi1\nInternet 192.0.2.30 1 0011.2233.4466 ARPA Gi2'}
                return await super().execute_ssh_command_direct(host, command, **kwargs)
        topo = asyncio.run(DiscoveryEngine(ARPSSH()).discover_devices(SEED, 0))
        self.assertEqual({l['target_ip'] for l in topo['links']}, {'192.0.2.20','192.0.2.30'})

    def test_diagram_geometry_and_html_escape(self):
        with tempfile.TemporaryDirectory() as folder:
            topo = asyncio.run(run_demo(folder))
            xml = ET.parse(Path(folder)/'topology.drawio')
            self.assertTrue(all(g.get('as') == 'geometry' for g in xml.findall('.//mxGeometry')))
            self.assertIsNotNone(xml.find('.//mxCell[@id="table_summary"]'))
            topo['nodes'][0]['label'] = '<img src=x onerror=alert(1)>'
            topo['nodes'][0]['hostname'] = topo['nodes'][0]['label']
            with patch.object(visualization, 'USER_DATA_DIR', folder):
                _, text = visualization.VisualizationEngine().export_topology_to_drawio(topo, SEED)
            table = ET.fromstring(text).find('.//mxCell[@id="table_summary"]').get('value')
            self.assertNotIn('<img', table)
            self.assertIn('&lt;img', table)

    def test_command_policy_and_cidr(self):
        config = ConfigManager()
        self.assertTrue(config.validate_read_only_command('show version')['valid'])
        for cmd in ['show version\nreload','show version; reload','show running-config','show version | redirect x','show version$(id)']:
            self.assertFalse(config.validate_read_only_command(cmd)['valid'])
        with patch.object(config, 'is_host_allowed', return_value=False), patch.dict(os.environ, {'CISCO_MCP_DISCOVERY_CIDRS':'192.0.2.0/24'}):
            self.assertTrue(config.is_discovery_host_allowed('192.0.2.20'))
            self.assertFalse(config.is_discovery_host_allowed('198.51.100.20'))
            self.assertFalse(config.is_discovery_host_allowed('unresolved.example.invalid'))
        with patch.dict(os.environ, {'CISCO_MCP_DISCOVERY_CIDRS':'bad/24'}):
            self.assertFalse(config.is_discovery_host_allowed('192.0.2.20'))

    def test_ssh_opt_in_and_scope(self):
        with tempfile.TemporaryDirectory() as folder, patch('cisco_mcp.storage.USER_DATA_DIR', folder):
            manager = CiscoSSHManager()
            manager._run_raw_ssh = AsyncMock()
            with patch.dict(os.environ, {'CISCO_MCP_ENABLE_SSH':'0'}):
                result = asyncio.run(manager.execute_ssh_command_direct(SEED,'show version'))
                self.assertEqual(result['status'], 'ssh_disabled')
            with patch.dict(os.environ, {'CISCO_MCP_ENABLE_SSH':'1'}), patch.object(manager.config,'is_discovery_host_allowed',return_value=False):
                result = asyncio.run(manager.execute_ssh_command_direct(SEED,'show version',enforce_whitelist=False))
                self.assertEqual(result['status'], 'host_outside_scope')
            manager._run_raw_ssh.assert_not_awaited()
            self.assertTrue(manager.validate_ip_or_hostname('lab-core.example.invalid')[0])
            self.assertFalse(manager.validate_ip_or_hostname('-oProxyCommand=bad')[0])

if __name__ == '__main__': unittest.main()

class SSHArgumentsTests(unittest.TestCase):
    def test_strict_host_keys_and_argument_vector(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as folder, patch('cisco_mcp.storage.USER_DATA_DIR', folder):
            manager = CiscoSSHManager()
            with patch('cisco_mcp.ssh.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout='ok', stderr='')) as run:
                result = asyncio.run(manager._run_raw_ssh(SEED, 'show version', 22, 'lab-user', '/tmp/fictional-key'))
                self.assertTrue(result['success'])
                arguments = run.call_args.args[0]
                self.assertIn('StrictHostKeyChecking=yes', arguments)
                self.assertNotIn('UserKnownHostsFile=/dev/null', arguments)
                self.assertNotIn('shell', run.call_args.kwargs)
                self.assertEqual(arguments[-1], 'show version')
