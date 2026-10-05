"""Offline discovery demonstration using fictional command responses only."""
import argparse
import asyncio
from html import escape
import json
from pathlib import Path
from types import SimpleNamespace
from cisco_mcp.discovery import DiscoveryEngine
from cisco_mcp import visualization

SEED = '192.0.2.10'
HOSTS = {SEED: 'lab-core', '192.0.2.20': 'lab-access', '192.0.2.30': 'lab-edge'}

class DemoSSH:
    """The SSH command interface backed entirely by fictional responses."""
    def __init__(self):
        self.calls = []
        self.config = SimpleNamespace(is_host_allowed=lambda h: h == SEED,
                                      is_discovery_host_allowed=lambda h: h in HOSTS)

    async def execute_ssh_command_direct(self, host, command, **kwargs):
        self.calls.append((host, command))
        if host not in HOSTS:
            return {'success': False, 'output': '', 'error': 'No fictional response'}
        text = ''
        if command == 'show version':
            text = f'Cisco IOS XE Software\ncisco C9300-24T processor\n{HOSTS[host]} uptime is 1 day'
        elif command == 'show cdp neighbors detail':
            neighbor = ('lab-access', '192.0.2.20', 'Gi1/0/1', 'Gi1/0/48') if host == SEED else ('lab-core', SEED, 'Gi1/0/48', 'Gi1/0/1') if host == '192.0.2.20' else None
            if neighbor:
                name, ip, local, remote = neighbor
                text = f'Device ID: {name}.example.invalid\nIP address: {ip}\nPlatform: cisco C9300-24T, Capabilities: Switch\nInterface: {local}, Port ID (outgoing port): {remote}\n'
        elif command == 'show lldp neighbors detail' and host == SEED:
            text = 'Local Intf: Gi1/0/2\nSystem Name: lab-edge.example.invalid\nManagement Address: 192.0.2.30\nSystem Description: C9300-24T\nPort id: Gi1/0/48\n'
        elif command == 'show ip arp':
            text = 'Internet 192.0.2.30 1 0011.2233.4455 ARPA Gi1/0/2'
        return {'success': True, 'output': text, 'return_code': 0}

async def run_demo(output_dir):
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    ssh = DemoSSH()
    topology = await DiscoveryEngine(ssh).discover_devices(SEED, 2)
    (output_dir / 'topology.json').write_text(json.dumps(topology, indent=2) + '\n')
    previous = visualization.USER_DATA_DIR
    try:
        visualization.USER_DATA_DIR = str(output_dir)
        visualization.VisualizationEngine().export_topology_to_drawio(topology, SEED)
    finally:
        visualization.USER_DATA_DIR = previous
    cards = ''.join(f'<div class="node"><strong>{escape(n["id"])}</strong><br>{escape(", ".join(n.get("ip_addresses", [])))}</div>' for n in topology['nodes'])
    rows = ''.join('<tr>' + ''.join(f'<td>{escape(str(link.get(k) or "—"))}</td>' for k in ('source', 'source_int', 'target', 'target_int')) + '</tr>' for link in topology['links'])
    html = f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>MCP discovery — fictional example</title>
<style>body{{font:18px system-ui;background:#f4f7fb;color:#192b40;max-width:1000px;margin:60px auto;padding:0 24px}}h1{{font-size:36px}}.nodes{{display:flex;gap:20px;margin:32px 0}}.node{{background:white;border:2px solid #517ca8;border-radius:12px;padding:24px;flex:1}}table{{border-collapse:collapse;background:white;width:100%}}td,th{{text-align:left;padding:14px;border-bottom:1px solid #dde3eb}}.tag{{color:#5c6878}}a{{color:#165f9e}}</style>
<p class="tag">OFFLINE EXAMPLE · FICTIONAL DEVICES</p><h1>From a seed host to a topology</h1><p>Seed {SEED} → CDP / LLDP evidence → device and link deduplication → diagram for engineer review.</p><div class="nodes">{cards}</div><table><tr><th>Device</th><th>Interface</th><th>Neighbor</th><th>Interface</th></tr>{rows}</table><p>{len(topology['nodes'])} devices · {len(topology['links'])} links · {len(ssh.calls)} simulated queries · no network access</p><p><a href="topology.json">Collected evidence</a> · <a href="topology.drawio" download>Editable Draw.io diagram</a></p><p class="tag">Missing information is not proof that a device or link does not exist. This example does not validate a real network or the optional Genie parsers.</p></html>'''
    (output_dir / 'index.html').write_text(html)
    return topology

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', default='demo-output')
    args = parser.parse_args()
    topology = asyncio.run(run_demo(args.output_dir))
    print(f"Offline demo: {len(topology['nodes'])} nodes, {len(topology['links'])} links. Open {Path(args.output_dir).resolve() / 'index.html'}")
