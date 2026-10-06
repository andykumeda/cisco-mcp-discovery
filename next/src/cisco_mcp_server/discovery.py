"""Depth-limited Cisco topology discovery."""

from __future__ import annotations

from collections import deque
from typing import Any

from cisco_mcp_server.connected_devices import build_connected_device_audit
from cisco_mcp_server.device import DeviceClient
from cisco_mcp_server.exceptions import InventoryError
from cisco_mcp_server.inventory_update import InventoryUpdater
from cisco_mcp_server.models import DeviceTarget
from cisco_mcp_server.parsers import parse_ip_interface_brief, parse_neighbors, parse_version
from cisco_mcp_server.storage import TrustedTargetStore, utc_now

DISCOVERY_COMMANDS = [
    "show version",
    "show cdp neighbors detail",
    "show lldp neighbors detail",
    "show ip interface brief",
    "show interfaces",
    "show ip route",
    "show interfaces status",
    "show mac address-table",
    "show ip arp",
    "show interfaces trunk",
    "show spanning-tree detail",
]


class DiscoveryEngine:
    def __init__(
        self,
        *,
        device_client: DeviceClient,
        trusted_targets: TrustedTargetStore,
        inventory_updater: InventoryUpdater | None = None,
    ) -> None:
        self.device_client = device_client
        self.trusted_targets = trusted_targets
        self.inventory_updater = inventory_updater

    def run(
        self,
        *,
        seed_hosts: list[str],
        depth: int = 2,
        max_devices: int = 100,
        timeout_seconds: int = 60,
        full_discovery: bool = True,
    ) -> dict[str, Any]:
        if not seed_hosts:
            raise InventoryError("Discovery requires at least one seed host.")
        if depth < 0:
            raise InventoryError("Discovery depth must be zero or greater.")
        if max_devices < 1:
            raise InventoryError("Discovery max_devices must be at least one.")

        queue: deque[tuple[DeviceTarget, int | None, str, str]] = deque()
        queued: set[str] = set()
        for seed in seed_hosts:
            target = self.device_client.inventory.resolve(seed)
            remaining_depth = None if full_discovery else depth
            if _node_id(target) not in queued:
                queue.append((target, remaining_depth, target.name, target.address))
                queued.add(_node_id(target))

        nodes: dict[str, dict[str, Any]] = {}
        links: list[dict[str, Any]] = []
        warnings: list[str] = []
        visited: set[str] = set()

        while queue and len(visited) < max_devices:
            target, remaining_depth, seed_name, seed_address = queue.popleft()
            node_id = _node_id(target)
            queued.discard(node_id)
            if node_id in visited:
                continue
            visited.add(node_id)

            batch = self.device_client.run_commands_for_target(
                target,
                DISCOVERY_COMMANDS,
                mode="exec",
                timeout_seconds=timeout_seconds,
            )
            output_by_command = {
                result.command: result.output for result in batch.results if result.success
            }
            if not batch.success:
                warnings.append(
                    f"Discovery command failure on {target.name}: {batch.results[-1].error}"
                )

            node = _base_node(target)
            node.update(parse_version(output_by_command.get("show version", "")))
            node["interfaces"] = parse_ip_interface_brief(
                output_by_command.get("show ip interface brief", "")
            )
            node["connected_device_audit"] = build_connected_device_audit(
                batch,
                include_raw_outputs=False,
            )
            nodes[node_id] = {**nodes.get(node_id, {}), **node}

            neighbors = parse_neighbors(
                output_by_command.get("show cdp neighbors detail", ""),
                output_by_command.get("show lldp neighbors detail", ""),
            )
            for neighbor in neighbors:
                neighbor_name = str(neighbor.get("name") or neighbor.get("address"))
                neighbor_address = neighbor.get("address")
                neighbor_id = str(neighbor_address or neighbor_name)

                nodes.setdefault(
                    neighbor_id,
                    {
                        "id": neighbor_id,
                        "label": neighbor_name,
                        "hostname": neighbor_name,
                        "address": neighbor_address,
                        "platform": neighbor.get("platform"),
                        "source": "discovered",
                    },
                )
                links.append(
                    {
                        "source": node_id,
                        "target": neighbor_id,
                        "protocol": neighbor.get("protocol"),
                        "source_interface": neighbor.get("source_interface"),
                        "target_interface": neighbor.get("target_interface"),
                    }
                )

                if neighbor_address:
                    credential_source = target.credential_source or target.name
                    self.trusted_targets.add(
                        name=neighbor_name,
                        address=str(neighbor_address),
                        credential_source=credential_source,
                        discovered_from=target.name,
                        protocol=str(neighbor.get("protocol") or "unknown"),
                    )
                    self._persist_discovered_neighbor(
                        name=neighbor_name,
                        address=str(neighbor_address),
                        seed_name=seed_name,
                        seed_address=seed_address,
                        discovered_from=target.name,
                        protocol=str(neighbor.get("protocol") or "unknown"),
                    )

                if (
                    neighbor_address
                    and _should_continue_discovery(remaining_depth)
                    and len(visited) + len(queue) < max_devices
                ):
                    discovered_target = self.trusted_targets.resolve(
                        neighbor_name, self.device_client.inventory,
                        address=str(neighbor_address), discovered_from=target.name,
                        protocol=str(neighbor.get("protocol") or "unknown"),
                    )
                    discovered_id = _node_id(discovered_target)
                    if discovered_id not in visited and discovered_id not in queued:
                        queued.add(discovered_id)
                        queue.append(
                            (
                                discovered_target,
                                _next_depth(remaining_depth),
                                seed_name,
                                seed_address,
                            )
                        )

        if queue:
            warnings.append(f"Discovery stopped after reaching max_devices={max_devices}.")

        node_list = sorted(nodes.values(), key=lambda item: item["id"])
        link_list = links
        return {
            "metadata": {
                "created_at": utc_now(),
                "seed_hosts": seed_hosts,
                "depth": None if full_discovery else depth,
                "full_discovery": full_discovery,
                "max_devices": max_devices,
                "commands": DISCOVERY_COMMANDS,
            },
            "nodes": node_list,
            "links": link_list,
            "tables": {
                "network_devices": build_network_device_table(node_list, link_list),
                "connected_interfaces": build_connected_interface_table(node_list),
                "learned_endpoints": build_learned_endpoint_table(node_list),
            },
            "warnings": warnings,
        }

    def _persist_discovered_neighbor(
        self,
        *,
        name: str,
        address: str,
        seed_name: str,
        seed_address: str,
        discovered_from: str,
        protocol: str,
    ) -> None:
        if self.inventory_updater is None:
            return
        self.inventory_updater.add_discovered_host(
            name=name,
            address=address,
            seed_name=seed_name,
            seed_address=seed_address,
            discovered_from=discovered_from,
            protocol=protocol,
        )


def _base_node(target: DeviceTarget) -> dict[str, Any]:
    node_id = _node_id(target)
    return {
        "id": node_id,
        "label": target.name,
        "hostname": target.name,
        "address": target.address,
        "source": target.source,
        "credential_source": target.credential_source,
        "reachable_via": target.reachable_via,
        "device_type": target.device_type,
        "groups": list(target.groups),
    }


def _node_id(target: DeviceTarget) -> str:
    return target.address or target.name


def _should_continue_discovery(remaining_depth: int | None) -> bool:
    return remaining_depth is None or remaining_depth > 0


def _next_depth(remaining_depth: int | None) -> int | None:
    if remaining_depth is None:
        return None
    return remaining_depth - 1


def build_network_device_table(
    nodes: list[dict[str, Any]],
    links: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    links_by_target: dict[str, list[dict[str, Any]]] = {}
    for link in links:
        links_by_target.setdefault(str(link.get("target")), []).append(link)

    rows: list[dict[str, Any]] = []
    for node in nodes:
        inbound = links_by_target.get(str(node.get("id")), [])
        first_link = inbound[0] if inbound else {}
        rows.append(
            {
                "device": node.get("hostname") or node.get("label") or node.get("id"),
                "address": node.get("address") or node.get("id"),
                "platform": node.get("platform"),
                "software_version": node.get("software_version"),
                "source": node.get("source"),
                "credential_source": node.get("credential_source"),
                "reachable_via": node.get("reachable_via"),
                "discovered_via": first_link.get("protocol"),
                "upstream_device": first_link.get("source"),
                "upstream_interface": first_link.get("source_interface"),
                "local_interface_on_device": first_link.get("target_interface"),
                "groups": node.get("groups", []),
            }
        )
    return rows


def build_connected_interface_table(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for node in nodes:
        audit = node.get("connected_device_audit") or {}
        evidence = audit.get("evidence") or {}
        for interface in evidence.get("connected_interfaces") or []:
            rows.append(
                {
                    "device": node.get("hostname") or node.get("label") or node.get("id"),
                    "device_address": node.get("address") or node.get("id"),
                    "interface": interface.get("interface"),
                    "name": interface.get("name"),
                    "status": interface.get("status"),
                    "vlan": interface.get("vlan"),
                    "trunk": interface.get("trunk"),
                    "neighbor_names": [
                        neighbor.get("name")
                        for neighbor in interface.get("cdp_lldp_neighbors", [])
                        if neighbor.get("name")
                    ],
                    "neighbor_addresses": [
                        neighbor.get("address")
                        for neighbor in interface.get("cdp_lldp_neighbors", [])
                        if neighbor.get("address")
                    ],
                    "learned_mac_count": interface.get("learned_mac_count"),
                    "learned_ips": [
                        item.get("ip")
                        for item in interface.get("learned_ips", [])
                        if item.get("ip")
                    ],
                }
            )
    return rows


def build_learned_endpoint_table(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for node in nodes:
        audit = node.get("connected_device_audit") or {}
        evidence = audit.get("evidence") or {}
        for interface in evidence.get("connected_interfaces") or []:
            for mac in interface.get("learned_macs", []):
                learned_ips = [
                    item.get("ip")
                    for item in interface.get("learned_ips", [])
                    if item.get("mac") == mac.get("mac") and item.get("ip")
                ]
                rows.append(
                    {
                        "observed_on_device": (
                            node.get("hostname") or node.get("label") or node.get("id")
                        ),
                        "observed_on_address": node.get("address") or node.get("id"),
                        "interface": interface.get("interface"),
                        "vlan": mac.get("vlan") or interface.get("vlan"),
                        "mac": mac.get("mac"),
                        "ips": learned_ips,
                        "trunk": interface.get("trunk"),
                        "neighbor_names": [
                            neighbor.get("name")
                            for neighbor in interface.get("cdp_lldp_neighbors", [])
                            if neighbor.get("name")
                        ],
                    }
                )
    return rows
