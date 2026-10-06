from __future__ import annotations

from cisco_mcp_server.discovery import DISCOVERY_COMMANDS, DiscoveryEngine
from cisco_mcp_server.inventory import load_inventory
from cisco_mcp_server.inventory_update import InventoryUpdater
from cisco_mcp_server.models import BatchResult, CommandResult, DeviceTarget
from cisco_mcp_server.storage import TrustedTargetStore


class FakeDeviceClient:
    def __init__(self, inventory):
        self.inventory = inventory
        self.calls: list[str] = []
        self.outputs = {
            "192.0.2.10": {
                "show version": "Cisco IOS XE Software, Version 17.09\nedge-1 uptime is 1 week\n",
                "show cdp neighbors detail": """
-------------------------
Device ID: dist-1.example.test
Entry address(es):
  IP address: 192.0.2.20
Platform: cisco C9300, Capabilities: Switch
Interface: GigabitEthernet1/0/1, Port ID (outgoing port): GigabitEthernet1/0/24
""",
                "show lldp neighbors detail": "",
                "show ip interface brief": """
Interface              IP-Address      OK? Method Status                Protocol
GigabitEthernet1/0/1   192.0.2.10      YES NVRAM  up                    up
""",
                "show interfaces": "",
                "show ip route": "",
                "show interfaces status": """
Port         Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1      to-dist            connected    trunk      a-full  a-1000 10/100/1000BaseTX
Gi1/0/10     user-host          connected    10         a-full  a-1000 10/100/1000BaseTX
""",
                "show mac address-table": """
Vlan    Mac Address       Type        Ports
 10     0011.2233.4455    DYNAMIC     Gi1/0/10
""",
                "show ip arp": """
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  192.0.2.55              0   0011.2233.4455  ARPA   Vlan10
""",
                "show interfaces trunk": "",
                "show spanning-tree detail": "",
            },
            "192.0.2.20": {
                "show version": "Cisco IOS XE Software, Version 17.09\ndist-1 uptime is 2 weeks\n",
                "show cdp neighbors detail": """
-------------------------
Device ID: access-1.example.test
Entry address(es):
  IP address: 192.0.2.30
Platform: cisco C9300, Capabilities: Switch
Interface: GigabitEthernet1/0/2, Port ID (outgoing port): GigabitEthernet1/0/48
""",
                "show lldp neighbors detail": "",
                "show ip interface brief": "",
                "show interfaces": "",
                "show ip route": "",
                "show interfaces status": "",
                "show mac address-table": "",
                "show ip arp": "",
                "show interfaces trunk": "",
                "show spanning-tree detail": "",
            },
            "192.0.2.30": {
                "show version": (
                    "Cisco IOS XE Software, Version 17.09\n"
                    "access-1 uptime is 3 weeks\n"
                ),
                "show cdp neighbors detail": "",
                "show lldp neighbors detail": "",
                "show ip interface brief": "",
                "show interfaces": "",
                "show ip route": "",
                "show interfaces status": "",
                "show mac address-table": "",
                "show ip arp": "",
                "show interfaces trunk": "",
                "show spanning-tree detail": "",
            },
        }

    def run_commands_for_target(
        self, target: DeviceTarget, commands, *, mode="exec", timeout_seconds=60
    ):
        self.calls.append(target.address)
        host_outputs = self.outputs.get(target.address, {})
        results = tuple(
            CommandResult(command=command, output=host_outputs.get(command, ""))
            for command in commands
        )
        return BatchResult(host=target.name, address=target.address, mode=mode, results=results)


def test_discovery_adds_neighbors_recursively_and_updates_inventory(tmp_path):
    inventory_path = tmp_path / "inventory.ini"
    inventory_path.write_text(
        "[iosxe]\nedge-1 ansible_host=192.0.2.10 ansible_user=netops\n",
        encoding="utf-8",
    )
    inventory = load_inventory(inventory_path)
    trusted = TrustedTargetStore(tmp_path)
    fake_client = FakeDeviceClient(inventory)
    engine = DiscoveryEngine(
        device_client=fake_client,
        trusted_targets=trusted,
        inventory_updater=InventoryUpdater(inventory_path),
    )

    topology = engine.run(seed_hosts=["edge-1"], depth=1, full_discovery=True, max_devices=10)

    node_ids = {node["id"] for node in topology["nodes"]}
    assert {"192.0.2.10", "192.0.2.20", "192.0.2.30"} <= node_ids
    assert topology["links"][0]["protocol"] == "cdp"
    assert trusted.resolve("192.0.2.20", inventory).credential_source == "edge-1"
    assert fake_client.calls == ["192.0.2.10", "192.0.2.20", "192.0.2.30"]
    assert "added from seed 192.0.2.10 (edge-1)" in inventory_path.read_text(
        encoding="utf-8"
    )
    assert topology["metadata"]["commands"] == DISCOVERY_COMMANDS
    assert topology["metadata"]["full_discovery"] is True
    assert topology["tables"]["network_devices"]
    assert any(
        row["interface"] == "Gi1/0/10" and row["learned_ips"] == ["192.0.2.55"]
        for row in topology["tables"]["connected_interfaces"]
    )
    assert any(
        row["mac"] == "0011.2233.4455" and row["ips"] == ["192.0.2.55"]
        for row in topology["tables"]["learned_endpoints"]
    )


def test_discovery_respects_depth_when_full_discovery_is_disabled(tmp_path):
    inventory_path = tmp_path / "inventory.ini"
    inventory_path.write_text(
        "[iosxe]\nedge-1 ansible_host=192.0.2.10 ansible_user=netops\n",
        encoding="utf-8",
    )
    inventory = load_inventory(inventory_path)
    trusted = TrustedTargetStore(tmp_path)
    fake_client = FakeDeviceClient(inventory)
    engine = DiscoveryEngine(
        device_client=fake_client,
        trusted_targets=trusted,
        inventory_updater=InventoryUpdater(inventory_path),
    )

    topology = engine.run(seed_hosts=["edge-1"], depth=1, full_discovery=False, max_devices=10)

    node_ids = {node["id"] for node in topology["nodes"]}
    assert "192.0.2.20" in node_ids
    assert "192.0.2.30" in node_ids
    assert fake_client.calls == ["192.0.2.10", "192.0.2.20"]
    assert topology["metadata"]["depth"] == 1
    assert topology["metadata"]["full_discovery"] is False


def test_duplicate_queued_neighbors_do_not_consume_device_budget(tmp_path):
    path = tmp_path / 'inventory.ini'
    path.write_text('[iosxe]\nedge-1 ansible_host=192.0.2.10 ansible_user=fixture-user\n')
    client = FakeDeviceClient(load_inventory(path))
    client.outputs['192.0.2.20']['show cdp neighbors detail'] = ''
    client.outputs['192.0.2.10']['show lldp neighbors detail'] = '''
Local Intf: Gi1/0/1
System Name: dist-1.example.test
Management Address: 192.0.2.20
Port id: Gi1/0/24

Local Intf: Gi1/0/2
System Name: access-1.example.test
Management Address: 192.0.2.30
Port id: Gi1/0/48
'''
    engine = DiscoveryEngine(device_client=client, trusted_targets=TrustedTargetStore(tmp_path))
    topology = engine.run(seed_hosts=['edge-1', '192.0.2.10'], max_devices=3)
    assert client.calls == ['192.0.2.10', '192.0.2.20', '192.0.2.30']
    assert len(set(client.calls)) == 3
