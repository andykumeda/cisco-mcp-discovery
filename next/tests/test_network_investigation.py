from __future__ import annotations

from cisco_mcp_server.models import BatchResult, CommandResult
from cisco_mcp_server.network_investigation import (
    build_investigation_commands,
    build_investigation_result,
    select_investigation_profiles,
)


def test_question_profiles_select_relevant_senior_evidence():
    profiles = select_investigation_profiles(
        "Confirm the default route and whether traffic to 192.0.2.55 is reachable"
    )

    assert "routing_forwarding" in profiles

    commands = build_investigation_commands(
        "Confirm the default route and whether traffic to 192.0.2.55 is reachable",
        profiles,
    )

    assert "show ip route 0.0.0.0" in commands
    assert "show ip cef 192.0.2.55" in commands
    assert "show ip protocols" in commands


def test_interface_question_adds_interface_specific_commands():
    profiles = select_investigation_profiles("Why is Gi1/0/37 dropping packets?")
    commands = build_investigation_commands("Why is Gi1/0/37 dropping packets?", profiles)

    assert "interface_health" in profiles
    assert "show interfaces Gi1/0/37" in commands
    assert "show running-config interface Gi1/0/37" in commands
    assert "show mac address-table interface Gi1/0/37" in commands


def test_investigation_result_includes_answer_contract_and_connected_audit():
    batch = BatchResult(
        host="edge-1",
        address="192.0.2.10",
        mode="exec",
        results=(
            CommandResult(command="show version", output="Cisco IOS XE Software, Version 17.9\n"),
            CommandResult(
                command="show ip interface brief",
                output="Interface IP-Address OK? Method Status Protocol\n",
            ),
            CommandResult(command="show cdp neighbors detail", output=""),
            CommandResult(command="show lldp neighbors detail", output="LLDP is not enabled\n"),
            CommandResult(
                command="show interfaces status",
                output=(
                    "Port Name Status Vlan Duplex Speed Type\n"
                    "Gi1/0/1 host connected 10 a-full a-1000 10/100/1000BaseTX\n"
                ),
            ),
            CommandResult(
                command="show mac address-table",
                output="Vlan Mac Address Type Ports\n10 0011.2233.4455 DYNAMIC Gi1/0/1\n",
            ),
            CommandResult(
                command="show ip arp",
                output=(
                    "Protocol Address Age (min) Hardware Addr Type Interface\n"
                    "Internet 192.0.2.55 0 0011.2233.4455 ARPA Vlan10\n"
                ),
            ),
            CommandResult(command="show interfaces trunk", output=""),
            CommandResult(command="show spanning-tree detail", output=""),
            CommandResult(command="show vlan brief", output=""),
            CommandResult(command="show spanning-tree summary", output=""),
            CommandResult(command="show etherchannel summary", output=""),
        ),
    )

    result = build_investigation_result(
        question="What devices are connected?",
        batch=batch,
        profiles=["connected_devices", "switching_layer2"],
        include_raw_outputs=False,
        max_output_chars_per_command=100,
    )

    assert result["answer_contract"]["minimum_standard"] == "senior_network_engineer"
    assert result["evidence"]["connected_device_audit"]["summary"]["connected_interface_count"] == 1
    assert result["confidence"] in {"moderate", "high"}
    assert any("Separate CDP/LLDP" in item for item in result["answer_contract"]["requirements"])
