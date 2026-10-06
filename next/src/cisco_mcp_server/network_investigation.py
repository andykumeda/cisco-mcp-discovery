"""Question-driven network investigation plans.

The MCP server cannot make every possible network conclusion by itself, but it
can prevent shallow answers by collecting the right evidence set and returning
the reasoning boundaries an engineer must honor.
"""

from __future__ import annotations

import re
from typing import Any

from cisco_mcp_server.connected_devices import (
    CONNECTED_DEVICE_AUDIT_COMMANDS,
    build_connected_device_audit,
)
from cisco_mcp_server.device import DeviceClient
from cisco_mcp_server.models import BatchResult, CommandResult

BASELINE_COMMANDS = [
    "show version",
    "show ip interface brief",
]

MAX_INVESTIGATION_COMMANDS = 48
DEFAULT_OUTPUT_CHARS_PER_COMMAND = 12000

INTERFACE_RE = re.compile(
    r"\b(?:"
    r"(?:Gi|GigabitEthernet|Te|TenGigabitEthernet|Twe|TwentyFiveGigE|"
    r"Fo|FortyGigabitEthernet|Hu|HundredGigE|Eth|Ethernet|Fa|FastEthernet)"
    r"\d+(?:/\d+){1,3}|"
    r"(?:Po|Port-channel)\d+|Vlan\d+"
    r")\b",
    re.IGNORECASE,
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")


INVESTIGATION_PROFILES: dict[str, dict[str, Any]] = {
    "connected_devices": {
        "description": "Physical and learned-device evidence for connected endpoint questions.",
        "keywords": (
            "connected",
            "attached",
            "plugged",
            "neighbor",
            "neighbour",
            "endpoint",
            "device on",
            "only device",
            "what is on",
        ),
        "commands": CONNECTED_DEVICE_AUDIT_COMMANDS,
        "answer_requirements": (
            "Separate CDP/LLDP advertised neighbors from physical connected ports.",
            "Use MAC learning and ARP to identify silent endpoints where possible.",
            "Call out trunks, multiple MACs, and STP forwarding as possible downstream devices.",
        ),
    },
    "routing_forwarding": {
        "description": "Routing table, forwarding, next-hop, and path-selection evidence.",
        "keywords": (
            "route",
            "routing",
            "default gateway",
            "default route",
            "next-hop",
            "nexthop",
            "path",
            "forward",
            "reachable",
            "reachability",
            "gateway",
            "traffic to",
        ),
        "commands": (
            "show ip route",
            "show ip protocols",
            "show ip cef",
            "show ip arp",
            "show running-config | include ^ip route|^ipv6 route",
        ),
        "answer_requirements": (
            "Distinguish configured routes, learned routes, and selected forwarding entries.",
            "State next hop, outgoing interface, administrative distance, and metric when visible.",
            (
                "Identify missing evidence if reachability depends on an untested next hop "
                "or return path."
            ),
        ),
    },
    "interface_health": {
        "description": "Interface state, errors, counters, transceiver, and recent link events.",
        "keywords": (
            "interface",
            "port",
            "link",
            "down",
            "up",
            "error",
            "errors",
            "drops",
            "crc",
            "duplex",
            "speed",
            "flap",
            "flapping",
            "transceiver",
        ),
        "commands": (
            "show interfaces status",
            "show interfaces",
            "show interfaces counters errors",
            "show logging | include LINEPROTO|LINK|UPDOWN|ERR|error|duplex|speed",
        ),
        "answer_requirements": (
            "Separate administrative state, operational state, protocol state, and physical media.",
            "Use counters and logs before blaming cabling, optics, duplex, or the remote side.",
            "Mention whether counters are current or require a clear-and-recheck interval.",
        ),
    },
    "switching_layer2": {
        "description": "VLAN, trunk, MAC table, spanning-tree, and EtherChannel evidence.",
        "keywords": (
            "vlan",
            "trunk",
            "stp",
            "spanning-tree",
            "spanning tree",
            "mac",
            "layer 2",
            "l2",
            "etherchannel",
            "port-channel",
            "loop",
        ),
        "commands": (
            "show vlan brief",
            "show interfaces trunk",
            "show spanning-tree summary",
            "show spanning-tree detail",
            "show mac address-table",
            "show etherchannel summary",
        ),
        "answer_requirements": (
            "Verify VLAN existence, trunk allowance, STP state, and MAC learning together.",
            "Do not infer a loop or downstream switch from a single signal without corroboration.",
            (
                "Identify where the evidence is local-only and where the remote switch must "
                "be checked."
            ),
        ),
    },
    "routing_protocols": {
        "description": "Dynamic routing protocol state and adjacency evidence.",
        "keywords": (
            "ospf",
            "bgp",
            "eigrp",
            "isis",
            "neighbor adjacency",
            "routing protocol",
            "peer",
            "adjacency",
        ),
        "commands": (
            "show ip protocols",
            "show ip ospf neighbor",
            "show ip bgp summary",
            "show ip eigrp neighbors",
            "show ipv6 protocols",
        ),
        "answer_requirements": (
            "Separate protocol process configuration from actual neighbor state.",
            "Report adjacency state, timers, received prefixes, and obvious filtering symptoms.",
            (
                "Call out protocol-specific gaps instead of declaring the protocol healthy "
                "from one command."
            ),
        ),
    },
    "security_policy": {
        "description": "ACL, NAT, and interface policy evidence.",
        "keywords": (
            "acl",
            "access-list",
            "blocked",
            "permit",
            "deny",
            "nat",
            "policy",
            "firewall",
            "security",
        ),
        "commands": (
            "show access-lists",
            "show ip interface",
            "show running-config | section access-list",
            "show ip nat translations",
            "show ip nat statistics",
        ),
        "answer_requirements": (
            "Tie ACL or NAT behavior to the interface direction and matching counters.",
            "Separate configured policy from observed hits or translations.",
            (
                "Do not claim traffic is allowed or denied without matching source, "
                "destination, and protocol."
            ),
        ),
    },
    "system_state": {
        "description": "Device version, uptime, inventory, environment, CPU, memory, and logs.",
        "keywords": (
            "version",
            "ios",
            "ios-xe",
            "nx-os",
            "uptime",
            "reload",
            "crash",
            "cpu",
            "memory",
            "hardware",
            "inventory",
            "temperature",
            "power",
            "environment",
            "logs",
        ),
        "commands": (
            "show version",
            "show inventory",
            "show processes cpu sorted",
            "show memory statistics",
            "show environment all",
            "show logging | last 100",
        ),
        "answer_requirements": (
            "State uptime, software, platform, and any visible resource or environmental alarms.",
            "Separate a current symptom from historical log evidence.",
            "Call out when logs have wrapped or timestamps are unavailable.",
        ),
    },
}


def investigate_network_question(
    device_client: DeviceClient,
    *,
    host: str,
    question: str,
    timeout_seconds: int = 60,
    include_raw_outputs: bool = True,
    max_output_chars_per_command: int = DEFAULT_OUTPUT_CHARS_PER_COMMAND,
) -> dict[str, Any]:
    profiles = select_investigation_profiles(question)
    commands = build_investigation_commands(question, profiles)
    batch = device_client.run_batch(host, commands, mode="exec", timeout_seconds=timeout_seconds)
    return build_investigation_result(
        question=question,
        batch=batch,
        profiles=profiles,
        include_raw_outputs=include_raw_outputs,
        max_output_chars_per_command=max_output_chars_per_command,
    )


def select_investigation_profiles(question: str) -> list[str]:
    normalized = re.sub(r"\s+", " ", question.strip().lower())
    selected: list[str] = []
    for name, profile in INVESTIGATION_PROFILES.items():
        if any(keyword in normalized for keyword in profile["keywords"]):
            selected.append(name)

    if "connected_devices" in selected and "switching_layer2" not in selected:
        selected.append("switching_layer2")
    if not selected:
        selected = ["system_state", "routing_forwarding", "interface_health"]
    return selected


def build_investigation_commands(question: str, profiles: list[str]) -> list[str]:
    commands: list[str] = []
    _extend_unique(commands, BASELINE_COMMANDS)
    for profile_name in profiles:
        profile = INVESTIGATION_PROFILES[profile_name]
        _extend_unique(commands, profile["commands"])
    _extend_unique(commands, _dynamic_route_commands(question))
    _extend_unique(commands, _dynamic_interface_commands(question))
    return commands[:MAX_INVESTIGATION_COMMANDS]


def build_investigation_result(
    *,
    question: str,
    batch: BatchResult,
    profiles: list[str],
    include_raw_outputs: bool,
    max_output_chars_per_command: int,
) -> dict[str, Any]:
    command_status = [_command_status(result) for result in batch.results]
    result_by_command = {result.command: result for result in batch.results}
    profile_details = [
        {
            "name": name,
            "description": INVESTIGATION_PROFILES[name]["description"],
            "answer_requirements": list(INVESTIGATION_PROFILES[name]["answer_requirements"]),
        }
        for name in profiles
    ]

    output_excerpts = [
        {
            "command": result.command,
            "output": _clip(result.output, max_output_chars_per_command),
            "truncated": len(result.output) > max_output_chars_per_command,
        }
        for result in batch.results
        if include_raw_outputs
    ]

    connected_audit = None
    if "connected_devices" in profiles:
        connected_audit = build_connected_device_audit(
            _subset_batch(batch, result_by_command, CONNECTED_DEVICE_AUDIT_COMMANDS),
            include_raw_outputs=False,
        )

    return {
        "question": question,
        "host": batch.host,
        "address": batch.address,
        "profiles": profile_details,
        "commands": [result.command for result in batch.results],
        "command_status": command_status,
        "evidence": {
            "output_excerpts": output_excerpts,
            "connected_device_audit": connected_audit,
        },
        "answer_contract": _answer_contract(profiles),
        "gaps": _gaps(command_status),
        "confidence": _confidence(command_status),
    }


def _dynamic_route_commands(question: str) -> list[str]:
    normalized = question.lower()
    commands: list[str] = []
    if "default" in normalized and ("route" in normalized or "gateway" in normalized):
        commands.extend(["show ip route 0.0.0.0", "show ip cef 0.0.0.0"])
    for ip_address in _extract_ipv4_targets(question):
        commands.append(f"show ip route {ip_address}")
        commands.append(f"show ip cef {ip_address.split('/')[0]}")
    return commands


def _dynamic_interface_commands(question: str) -> list[str]:
    commands: list[str] = []
    for interface in _extract_interfaces(question):
        commands.extend(
            [
                f"show interfaces {interface}",
                f"show running-config interface {interface}",
                f"show mac address-table interface {interface}",
                f"show spanning-tree interface {interface} detail",
            ]
        )
    return commands


def _extract_ipv4_targets(question: str) -> list[str]:
    targets: list[str] = []
    for match in IPV4_RE.finditer(question):
        target = match.group(0)
        octets = target.split("/")[0].split(".")
        if all(0 <= int(octet) <= 255 for octet in octets) and target not in targets:
            targets.append(target)
    return targets


def _extract_interfaces(question: str) -> list[str]:
    interfaces: list[str] = []
    for match in INTERFACE_RE.finditer(question):
        interface = match.group(0)
        if interface not in interfaces:
            interfaces.append(interface)
    return interfaces


def _subset_batch(
    batch: BatchResult,
    result_by_command: dict[str, CommandResult],
    commands: list[str],
) -> BatchResult:
    results: list[CommandResult] = []
    for command in commands:
        results.append(
            result_by_command.get(
                command,
                CommandResult(
                    command=command,
                    output="",
                    success=False,
                    error="Command was not collected during investigation.",
                ),
            )
        )
    return BatchResult(
        host=batch.host,
        address=batch.address,
        mode=batch.mode,
        results=tuple(results),
    )


def _command_status(result: CommandResult) -> dict[str, Any]:
    output = result.output or ""
    lowered = output.lower()
    status = "ok"
    if not result.success:
        status = "failed"
    elif any(pattern in output for pattern in ("% Invalid input", "% Ambiguous command")):
        status = "unsupported"
    elif "not enabled" in lowered or "not running" in lowered:
        status = "disabled"
    elif not output.strip():
        status = "empty"
    return {
        "command": result.command,
        "status": status,
        "success": result.success and status not in {"failed", "unsupported"},
        "error": result.error,
        "output_lines": len(output.splitlines()),
    }


def _answer_contract(profiles: list[str]) -> dict[str, Any]:
    requirements: list[str] = [
        "Lead with the answer only after citing the evidence that supports it.",
        "Separate observed facts from inference.",
        "State confidence and limitations.",
        "Do not overclaim exclusivity, causality, or health from one command.",
    ]
    for profile in profiles:
        _extend_unique(requirements, INVESTIGATION_PROFILES[profile]["answer_requirements"])
    return {
        "minimum_standard": "senior_network_engineer",
        "requirements": requirements,
    }


def _gaps(command_status: list[dict[str, Any]]) -> list[str]:
    gaps = [
        f"{item['command']} returned status {item['status']}."
        for item in command_status
        if item["status"] in {"failed", "unsupported", "empty"}
    ]
    if not gaps:
        gaps.append(
            "No command collection gaps detected; interpretation may still require context."
        )
    return gaps


def _confidence(command_status: list[dict[str, Any]]) -> str:
    failed_or_unsupported = [
        item for item in command_status if item["status"] in {"failed", "unsupported"}
    ]
    empty = [item for item in command_status if item["status"] == "empty"]
    if len(failed_or_unsupported) >= 3:
        return "low"
    if failed_or_unsupported or len(empty) >= 3:
        return "moderate"
    return "high"


def _clip(text: str, max_chars: int) -> str:
    if max_chars < 1:
        return ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... <truncated>"


def _extend_unique(items: list[str], additions: Any) -> None:
    for item in additions:
        if item not in items:
            items.append(item)
