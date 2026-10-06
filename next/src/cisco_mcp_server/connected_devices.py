"""Senior-level connected-device audit helpers.

CDP and LLDP identify neighbors that advertise themselves, not every device
attached to a switch. This module intentionally combines protocol neighbors
with physical port state, MAC learning, ARP, trunk, and spanning-tree evidence
before making any statement about connected devices.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from cisco_mcp_server.device import DeviceClient
from cisco_mcp_server.models import BatchResult, CommandResult
from cisco_mcp_server.parsers import parse_neighbors

CONNECTED_DEVICE_AUDIT_COMMANDS = [
    "show cdp neighbors detail",
    "show lldp neighbors detail",
    "show interfaces status",
    "show mac address-table",
    "show ip arp",
    "show interfaces trunk",
    "show spanning-tree detail",
]

COMMAND_UNSUPPORTED_PATTERNS = (
    "% Invalid input",
    "% Ambiguous command",
    "% Incomplete command",
    "% Unrecognized command",
)
COMMAND_DISABLED_PATTERNS = (
    "CDP is not enabled",
    "CDP is not running",
    "LLDP is not enabled",
    "LLDP is not running",
)

MAC_RE = re.compile(
    r"(?i)(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}|"
    r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|"
    r"(?:[0-9a-f]{2}-){5}[0-9a-f]{2}"
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class ConnectedDeviceAuditor:
    def __init__(self, device_client: DeviceClient) -> None:
        self.device_client = device_client

    def audit(
        self,
        host: str,
        *,
        timeout_seconds: int = 60,
        include_raw_outputs: bool = False,
    ) -> dict[str, Any]:
        batch = self.device_client.run_batch(
            host,
            CONNECTED_DEVICE_AUDIT_COMMANDS,
            mode="exec",
            timeout_seconds=timeout_seconds,
        )
        return build_connected_device_audit(batch, include_raw_outputs=include_raw_outputs)


def build_connected_device_audit(
    batch: BatchResult,
    *,
    include_raw_outputs: bool = False,
) -> dict[str, Any]:
    output_by_command = {result.command: result.output for result in batch.results}
    command_status = [_command_status(result) for result in batch.results]

    cdp_neighbors = parse_neighbors(output_by_command.get("show cdp neighbors detail", ""), "")
    lldp_neighbors = parse_neighbors("", output_by_command.get("show lldp neighbors detail", ""))
    protocol_neighbors = cdp_neighbors + lldp_neighbors
    connected_interfaces = parse_interfaces_status(
        output_by_command.get("show interfaces status", "")
    )
    mac_entries = parse_mac_address_table(output_by_command.get("show mac address-table", ""))
    arp_entries = parse_ip_arp(output_by_command.get("show ip arp", ""))
    trunk_interfaces = parse_trunk_interfaces(output_by_command.get("show interfaces trunk", ""))
    stp_forwarding_interfaces = parse_stp_forwarding_interfaces(
        output_by_command.get("show spanning-tree detail", "")
    )

    neighbors_by_interface = _group_by_interface(protocol_neighbors, "source_interface")
    macs_by_interface = _group_by_interface(mac_entries, "interface")
    arp_by_mac = _group_by_mac(arp_entries)
    trunk_by_interface = {
        item["normalized_interface"]: item
        for item in trunk_interfaces
        if item.get("normalized_interface")
    }

    enriched_interfaces = []
    for interface in connected_interfaces:
        normalized = interface.get("normalized_interface")
        learned_macs = macs_by_interface.get(normalized or "", [])
        neighbor_records = neighbors_by_interface.get(normalized or "", [])
        learned_ips = _ips_for_macs(learned_macs, arp_by_mac)
        enriched_interfaces.append(
            {
                **interface,
                "cdp_lldp_neighbors": neighbor_records,
                "learned_mac_count": len(learned_macs),
                "learned_macs": learned_macs,
                "learned_ips": learned_ips,
                "trunk": normalized in trunk_by_interface
                or str(interface.get("vlan") or "").lower() == "trunk",
                "stp_forwarding": normalized in stp_forwarding_interfaces,
            }
        )

    interface_norms = {item.get("normalized_interface") for item in connected_interfaces}
    interface_norms.discard(None)
    mac_only_interfaces = [
        {
            "interface": interface,
            "learned_mac_count": len(entries),
            "learned_macs": entries,
            "learned_ips": _ips_for_macs(entries, arp_by_mac),
        }
        for interface, entries in sorted(macs_by_interface.items())
        if interface not in interface_norms
    ]
    non_advertising_interfaces = [
        item
        for item in enriched_interfaces
        if item.get("status") == "connected" and not item.get("cdp_lldp_neighbors")
    ]
    multiple_mac_interfaces = [
        item for item in enriched_interfaces if int(item.get("learned_mac_count", 0)) > 1
    ]

    evidence = {
        "cdp_neighbors": cdp_neighbors,
        "lldp_neighbors": lldp_neighbors,
        "connected_interfaces": enriched_interfaces,
        "mac_only_interfaces": mac_only_interfaces,
        "trunk_interfaces": trunk_interfaces,
        "stp_forwarding_interfaces": sorted(stp_forwarding_interfaces),
    }
    if include_raw_outputs:
        evidence["raw_outputs"] = output_by_command

    summary = _build_summary(
        command_status=command_status,
        cdp_neighbors=cdp_neighbors,
        lldp_neighbors=lldp_neighbors,
        connected_interfaces=enriched_interfaces,
        mac_entries=mac_entries,
        mac_only_interfaces=mac_only_interfaces,
        non_advertising_interfaces=non_advertising_interfaces,
        multiple_mac_interfaces=multiple_mac_interfaces,
    )

    return {
        "host": batch.host,
        "address": batch.address,
        "scope": (
            "Local-switch connected-device audit. CDP/LLDP is treated as neighbor "
            "identity evidence only, not as proof of exclusive connectivity."
        ),
        "commands": CONNECTED_DEVICE_AUDIT_COMMANDS,
        "command_status": command_status,
        "summary": summary,
        "evidence": evidence,
        "limitations": _limitations(command_status),
    }


def parse_interfaces_status(output: str) -> list[dict[str, Any]]:
    status_words = {
        "connected",
        "notconnect",
        "disabled",
        "err-disabled",
        "inactive",
        "monitoring",
        "suspended",
        "faulty",
        "sfpabsent",
        "xcvrabsent",
    }
    interfaces: list[dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith(("port ", "----", "name ", "interface ")):
            continue
        tokens = line.split()
        if len(tokens) < 2:
            continue

        status_index = None
        for index, token in enumerate(tokens[1:], start=1):
            status = token.lower()
            if status in status_words or status.startswith("err-disabled"):
                status_index = index
                break
        if status_index is None:
            continue

        interface = tokens[0]
        status = tokens[status_index].lower()
        vlan = tokens[status_index + 1] if len(tokens) > status_index + 1 else None
        duplex = tokens[status_index + 2] if len(tokens) > status_index + 2 else None
        speed = tokens[status_index + 3] if len(tokens) > status_index + 3 else None
        media_type = " ".join(tokens[status_index + 4 :]) or None
        interfaces.append(
            {
                "interface": interface,
                "normalized_interface": normalize_interface(interface),
                "name": " ".join(tokens[1:status_index]) or None,
                "status": status,
                "connected": status == "connected",
                "vlan": vlan,
                "duplex": duplex,
                "speed": speed,
                "type": media_type,
            }
        )
    return interfaces


def parse_mac_address_table(output: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("-") or "mac address" in line.lower():
            continue
        mac_match = MAC_RE.search(line)
        if not mac_match:
            continue
        tokens = line.split()
        mac_token = mac_match.group(0)
        try:
            mac_index = next(
                index
                for index, token in enumerate(tokens)
                if normalize_mac(token) == normalize_mac(mac_token)
            )
        except StopIteration:
            continue

        interface = tokens[-1]
        if interface.upper() in {"CPU", "ROUTER", "DROP"}:
            continue
        vlan = _token_before_mac(tokens, mac_index)
        entry_type = tokens[mac_index + 1] if len(tokens) > mac_index + 1 else None
        entries.append(
            {
                "vlan": vlan,
                "mac": normalize_mac(mac_token),
                "type": entry_type,
                "interface": interface,
                "normalized_interface": normalize_interface(interface),
                "raw": line,
            }
        )
    return entries


def parse_ip_arp(output: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("protocol"):
            continue
        mac_match = MAC_RE.search(line)
        ip_match = IPV4_RE.search(line)
        if not mac_match or not ip_match:
            continue
        tokens = line.split()
        interface = tokens[-1] if tokens else None
        entries.append(
            {
                "ip": ip_match.group(0),
                "mac": normalize_mac(mac_match.group(0)),
                "interface": interface,
                "normalized_interface": normalize_interface(interface) if interface else None,
                "raw": line,
            }
        )
    return entries


def parse_trunk_interfaces(output: str) -> list[dict[str, Any]]:
    interfaces: list[dict[str, Any]] = []
    in_trunk_table = False
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        lower = line.lower()
        if lower.startswith("port") and "mode" in lower and "encapsulation" in lower:
            in_trunk_table = True
            continue
        if not in_trunk_table or lower.startswith(("----", "port ")):
            continue
        tokens = line.split()
        if len(tokens) >= 2 and tokens[0][0].isalpha():
            interfaces.append(
                {
                    "interface": tokens[0],
                    "normalized_interface": normalize_interface(tokens[0]),
                    "mode": tokens[1] if len(tokens) > 1 else None,
                    "status": tokens[3] if len(tokens) > 3 else None,
                    "native_vlan": tokens[4] if len(tokens) > 4 else None,
                    "raw": line,
                }
            )
    return interfaces


def parse_stp_forwarding_interfaces(output: str) -> set[str]:
    interfaces: set[str] = set()
    for match in re.finditer(
        r"(?im)^Port\s+\S+\s+\(([^)]+)\).*?\bis\s+\S+\s+forwarding\b",
        output,
    ):
        interfaces.add(normalize_interface(match.group(1)))
    return interfaces


def normalize_interface(interface: str) -> str:
    value = re.sub(r"\s+", "", str(interface).strip().lower())
    value = value.replace("-", "")
    prefixes = [
        ("hundredgigabitethernet", "hu"),
        ("hundredgige", "hu"),
        ("fortygigabitethernet", "fo"),
        ("tengigabitethernet", "te"),
        ("twentyfivegigabitethernet", "twe"),
        ("gigabitethernet", "gi"),
        ("fastethernet", "fa"),
        ("ethernet", "eth"),
        ("portchannel", "po"),
        ("vlan", "vlan"),
    ]
    for full, short in prefixes:
        if value.startswith(full):
            return short + value[len(full) :]
    return value


def normalize_mac(mac: str) -> str:
    chars = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(chars) != 12:
        return mac.lower()
    return ".".join(chars[index : index + 4] for index in range(0, 12, 4))


def _command_status(result: CommandResult) -> dict[str, Any]:
    output = result.output or ""
    status = "ok"
    if not result.success:
        status = "failed"
    elif any(pattern in output for pattern in COMMAND_UNSUPPORTED_PATTERNS):
        status = "unsupported"
    elif any(pattern.lower() in output.lower() for pattern in COMMAND_DISABLED_PATTERNS):
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


def _group_by_interface(items: list[dict[str, Any]], key: str) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        interface = item.get(key)
        if interface:
            grouped[normalize_interface(str(interface))].append(item)
    return dict(grouped)


def _group_by_mac(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        mac = item.get("mac")
        if mac:
            grouped[str(mac)].append(item)
    return dict(grouped)


def _ips_for_macs(
    mac_entries: list[dict[str, Any]],
    arp_by_mac: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    ips: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for entry in mac_entries:
        mac = str(entry.get("mac"))
        for arp in arp_by_mac.get(mac, []):
            key = (mac, str(arp.get("ip")))
            if key in seen:
                continue
            seen.add(key)
            ips.append({"mac": mac, "ip": arp.get("ip"), "arp_interface": arp.get("interface")})
    return ips


def _token_before_mac(tokens: list[str], mac_index: int) -> str | None:
    for token in reversed(tokens[:mac_index]):
        if token == "*":
            continue
        return token
    return None


def _build_summary(
    *,
    command_status: list[dict[str, Any]],
    cdp_neighbors: list[dict[str, Any]],
    lldp_neighbors: list[dict[str, Any]],
    connected_interfaces: list[dict[str, Any]],
    mac_entries: list[dict[str, Any]],
    mac_only_interfaces: list[dict[str, Any]],
    non_advertising_interfaces: list[dict[str, Any]],
    multiple_mac_interfaces: list[dict[str, Any]],
) -> dict[str, Any]:
    statuses = {item["command"]: item["status"] for item in command_status}
    connected_count = sum(1 for item in connected_interfaces if item.get("connected"))
    cdp_lldp_neighbor_count = len(cdp_neighbors) + len(lldp_neighbors)
    mac_interface_count = len(
        {
            item.get("normalized_interface")
            for item in mac_entries
            if item.get("normalized_interface")
        }
    )

    if statuses.get("show interfaces status") in {"ok", "disabled", "empty"}:
        interface_confidence = "available"
    else:
        interface_confidence = "missing"
    if statuses.get("show mac address-table") in {"ok", "empty"}:
        mac_confidence = "available"
    else:
        mac_confidence = "missing"

    confidence = "high"
    if interface_confidence == "missing" and mac_confidence == "missing":
        confidence = "low"
    elif interface_confidence == "missing" or mac_confidence == "missing":
        confidence = "moderate"

    assessment = _assessment_text(
        cdp_lldp_neighbor_count=cdp_lldp_neighbor_count,
        connected_count=connected_count,
        mac_interface_count=mac_interface_count,
        non_advertising_interfaces=non_advertising_interfaces,
        mac_only_interfaces=mac_only_interfaces,
        confidence=confidence,
    )

    return {
        "assessment": assessment,
        "confidence": confidence,
        "cdp_neighbor_count": len(cdp_neighbors),
        "lldp_neighbor_count": len(lldp_neighbors),
        "cdp_lldp_neighbor_count": cdp_lldp_neighbor_count,
        "connected_interface_count": connected_count,
        "interfaces_learning_macs_count": mac_interface_count,
        "non_advertising_connected_interfaces": [
            _interface_summary(item) for item in non_advertising_interfaces
        ],
        "interfaces_with_multiple_macs": [
            _interface_summary(item) for item in multiple_mac_interfaces
        ],
        "mac_only_interfaces": mac_only_interfaces,
        "required_answer_discipline": (
            "Do not answer 'only connected device' from CDP/LLDP alone. State what "
            "was proven by neighbor protocols, physical link state, MAC learning, "
            "and ARP separately."
        ),
    }


def _assessment_text(
    *,
    cdp_lldp_neighbor_count: int,
    connected_count: int,
    mac_interface_count: int,
    non_advertising_interfaces: list[dict[str, Any]],
    mac_only_interfaces: list[dict[str, Any]],
    confidence: str,
) -> str:
    if connected_count == 0 and mac_interface_count == 0:
        return (
            "No connected access/trunk ports or learned MAC interfaces were parsed. "
            "This does not prove no devices exist if interface or MAC commands were "
            "unsupported, empty, or filtered."
        )

    extra_evidence_count = len(non_advertising_interfaces) + len(mac_only_interfaces)
    if extra_evidence_count:
        return (
            f"CDP/LLDP shows {cdp_lldp_neighbor_count} advertising neighbor(s), but "
            f"the switch has {connected_count} connected interface(s) and "
            f"{mac_interface_count} interface(s) with learned MAC evidence. "
            f"{extra_evidence_count} interface(s) have connectivity evidence without "
            "CDP/LLDP identity. Treat those as possible hosts, silent devices, or "
            "downstream network devices until traced."
        )

    return (
        f"Current evidence supports {connected_count} connected interface(s), "
        f"{cdp_lldp_neighbor_count} CDP/LLDP-advertising neighbor(s), and "
        f"{mac_interface_count} MAC-learning interface(s). Confidence is {confidence}, "
        "subject to the listed limitations."
    )


def _interface_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "interface": item.get("interface"),
        "name": item.get("name"),
        "vlan": item.get("vlan"),
        "trunk": item.get("trunk"),
        "learned_mac_count": item.get("learned_mac_count"),
        "learned_ips": item.get("learned_ips", []),
    }


def _limitations(command_status: list[dict[str, Any]]) -> list[str]:
    limitations = [
        "CDP/LLDP only identifies devices that advertise those protocols.",
        (
            "MAC learning requires traffic; a quiet endpoint can be physically connected "
            "without a current MAC entry."
        ),
        (
            "ARP only maps IPs visible to local L3 interfaces and may not identify all "
            "L2-only endpoints."
        ),
        (
            "Multiple MACs on one port can indicate a downstream switch, phone, AP, "
            "hypervisor, or trunk."
        ),
        (
            "A complete physical answer may still require cabling records, optics state, "
            "port descriptions, and remote-side verification."
        ),
    ]
    unavailable = [
        item["command"]
        for item in command_status
        if item["status"] in {"failed", "unsupported"}
    ]
    if unavailable:
        limitations.append(
            "Some evidence was unavailable: " + ", ".join(unavailable) + "."
        )
    return limitations
