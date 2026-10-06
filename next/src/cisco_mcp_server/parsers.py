"""Small Cisco IOS/IOS-XE parsing helpers for discovery fixtures and fallbacks."""

from __future__ import annotations

import re
from typing import Any


def parse_version(output: str) -> dict[str, str]:
    data: dict[str, str] = {}
    hostname_match = re.search(r"(?m)^(\S+)\s+uptime\s+is\s+", output)
    if hostname_match:
        data["hostname"] = hostname_match.group(1)

    version_match = re.search(r"Version\s+([A-Za-z0-9().:_-]+)", output)
    if version_match:
        data["software_version"] = version_match.group(1)

    platform_match = re.search(r"[Cc]isco\s+([A-Za-z0-9_-]+)\s+\(", output)
    if platform_match:
        data["platform"] = platform_match.group(1)
    return data


def parse_ip_interface_brief(output: str) -> list[dict[str, str]]:
    interfaces: list[dict[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("interface"):
            continue
        match = re.match(
            r"^(?P<name>\S+)\s+(?P<ip>\S+)\s+\S+\s+\S+\s+(?P<status>.+?)\s+(?P<protocol>\S+)$",
            line,
        )
        if match:
            interfaces.append(match.groupdict())
    return interfaces


def parse_neighbors(cdp_output: str = "", lldp_output: str = "") -> list[dict[str, Any]]:
    neighbors: list[dict[str, Any]] = []
    neighbors.extend(_parse_cdp_neighbors(cdp_output))
    neighbors.extend(_parse_lldp_neighbors(lldp_output))
    return neighbors


def _parse_cdp_neighbors(output: str) -> list[dict[str, Any]]:
    neighbors: list[dict[str, Any]] = []
    for block in re.split(r"-{5,}", output):
        if "Device ID:" not in block:
            continue
        name = _first_match(block, r"Device ID:\s*(\S+)")
        address = _first_match(block, r"IP address:\s*([0-9.]+)")
        platform = _first_match(block, r"Platform:\s*([^,\n]+)")
        interface = _first_match(block, r"Interface:\s*([^,\n]+)")
        port_id = _first_match(block, r"Port ID.*?:\s*([^\n]+)")
        if name or address:
            neighbors.append(
                {
                    "protocol": "cdp",
                    "name": name or address,
                    "address": address,
                    "platform": platform,
                    "source_interface": interface,
                    "target_interface": port_id,
                }
            )
    return neighbors


def _parse_lldp_neighbors(output: str) -> list[dict[str, Any]]:
    neighbors: list[dict[str, Any]] = []
    blocks = re.split(r"\n\s*\n", output)
    for block in blocks:
        if "System Name:" not in block and "Local Intf:" not in block:
            continue
        name = _first_match(block, r"System Name:\s*(\S+)")
        address = _first_match(block, r"(?:Management Address|IP):\s*([0-9.]+)")
        interface = _first_match(block, r"Local Intf:\s*([^\n]+)") or _first_match(
            block,
            r"Local Interface:\s*([^\n]+)",
        )
        port_id = _first_match(block, r"Port id:\s*([^\n]+)") or _first_match(
            block,
            r"Port ID:\s*([^\n]+)",
        )
        if name or address:
            neighbors.append(
                {
                    "protocol": "lldp",
                    "name": name or address,
                    "address": address,
                    "platform": None,
                    "source_interface": interface,
                    "target_interface": port_id,
                }
            )
    return neighbors


def _first_match(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text, re.IGNORECASE)
    if not match:
        return None
    return match.group(1).strip()
