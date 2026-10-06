from __future__ import annotations

from cisco_mcp_server.connected_devices import (
    CONNECTED_DEVICE_AUDIT_COMMANDS,
    build_connected_device_audit,
    normalize_interface,
    normalize_mac,
    parse_interfaces_status,
    parse_ip_arp,
    parse_mac_address_table,
)
from cisco_mcp_server.models import BatchResult, CommandResult


def test_connected_device_audit_does_not_treat_cdp_as_exhaustive():
    outputs = {
        "show cdp neighbors detail": """
-------------------------
Device ID: AFM-146-9300-EN.hca.co.ventura.ca.us
Entry address(es):
  IP address: 192.0.2.1091
Platform: cisco C9300, Capabilities: Switch
Interface: TenGigabitEthernet1/0/37, Port ID (outgoing port): GigabitEthernet0/0
""",
        "show lldp neighbors detail": "% LLDP is not enabled",
        "show interfaces status": """
Port         Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1      silent-host        connected    128        a-full  a-1000 10/100/1000BaseTX
Te1/0/37     cdp-neighbor       connected    trunk      a-full  a-10G  SFP-10GBase-SR
Gi1/0/48                        notconnect   1          auto    auto   10/100/1000BaseTX
""",
        "show mac address-table": """
          Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 128    0011.2233.4455    DYNAMIC     Gi1/0/1
 128    04bd.9712.1910    DYNAMIC     Te1/0/37
""",
        "show ip arp": """
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  203.0.113.2          0   0011.2233.4455  ARPA   Vlan128
Internet  192.0.2.1091         0   04bd.9712.1910  ARPA   Vlan128
""",
        "show interfaces trunk": """
Port        Mode             Encapsulation  Status        Native vlan
Te1/0/37    on               802.1q         trunking      1
""",
        "show spanning-tree detail": """
 Port 37 (TenGigabitEthernet1/0/37) of VLAN0128 is designated forwarding
""",
    }
    batch = BatchResult(
        host="edge-1",
        address="192.0.2.10",
        mode="exec",
        results=tuple(
            CommandResult(command=command, output=outputs.get(command, ""))
            for command in CONNECTED_DEVICE_AUDIT_COMMANDS
        ),
    )

    audit = build_connected_device_audit(batch)

    assert audit["summary"]["cdp_neighbor_count"] == 1
    assert audit["summary"]["lldp_neighbor_count"] == 0
    assert audit["summary"]["connected_interface_count"] == 2
    assert audit["summary"]["interfaces_learning_macs_count"] == 2
    assert audit["summary"]["non_advertising_connected_interfaces"] == [
        {
            "interface": "Gi1/0/1",
            "name": "silent-host",
            "vlan": "128",
            "trunk": False,
            "learned_mac_count": 1,
            "learned_ips": [
                {
                    "mac": "0011.2233.4455",
                    "ip": "203.0.113.2",
                    "arp_interface": "Vlan128",
                }
            ],
        }
    ]
    assert "without CDP/LLDP identity" in audit["summary"]["assessment"]
    assert "Do not answer 'only connected device'" in audit["summary"]["required_answer_discipline"]
    assert audit["command_status"][1]["status"] == "disabled"


def test_parse_interfaces_status_handles_names_and_trunks():
    output = """
Port         Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1      user port          connected    10         a-full  a-1000 10/100/1000BaseTX
Te1/0/37     uplink             connected    trunk      a-full  a-10G  SFP-10GBase-SR
Gi1/0/48                        notconnect   1          auto    auto   10/100/1000BaseTX
"""

    interfaces = parse_interfaces_status(output)

    assert [item["interface"] for item in interfaces] == ["Gi1/0/1", "Te1/0/37", "Gi1/0/48"]
    assert interfaces[0]["name"] == "user port"
    assert interfaces[1]["vlan"] == "trunk"
    assert interfaces[2]["connected"] is False


def test_mac_and_arp_parsing_normalizes_keys():
    mac_entries = parse_mac_address_table(
        """
Vlan    Mac Address       Type        Ports
 128    0011.2233.4455    DYNAMIC     Gi1/0/1
* 129   04BD.9712.1910    dynamic     Te1/0/37
 All    0100.0ccc.cccc    STATIC      CPU
"""
    )
    arp_entries = parse_ip_arp(
        """
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  203.0.113.2          0   00:11:22:33:44:55  ARPA   Vlan128
"""
    )

    assert [entry["mac"] for entry in mac_entries] == ["0011.2233.4455", "04bd.9712.1910"]
    assert [entry["interface"] for entry in mac_entries] == ["Gi1/0/1", "Te1/0/37"]
    assert arp_entries[0]["mac"] == "0011.2233.4455"
    assert normalize_mac("00-11-22-33-44-55") == "0011.2233.4455"
    assert normalize_interface("TenGigabitEthernet1/0/37") == normalize_interface("Te1/0/37")
