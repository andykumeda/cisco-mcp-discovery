"""Markdown discovery report generation."""

from __future__ import annotations

from typing import Any


def generate_markdown_report(topology: dict[str, Any]) -> str:
    metadata = topology.get("metadata", {})
    nodes = topology.get("nodes", [])
    links = topology.get("links", [])
    warnings = topology.get("warnings", [])
    tables = topology.get("tables", {})

    lines = [
        "# Cisco Discovery Report",
        "",
        f"- Created: {metadata.get('created_at', 'unknown')}",
        f"- Seeds: {', '.join(metadata.get('seed_hosts', [])) or 'none'}",
        f"- Depth: {metadata.get('depth', 'unknown')}",
        f"- Devices: {len(nodes)}",
        f"- Links: {len(links)}",
        "",
        "## Devices",
        "",
    ]

    for node in nodes:
        lines.extend(
            [
                f"### {node.get('label') or node.get('id')}",
                "",
                f"- Address: {node.get('address') or node.get('id')}",
                f"- Source: {node.get('source', 'unknown')}",
                f"- Platform: {node.get('platform', 'unknown')}",
                f"- Software: {node.get('software_version', 'unknown')}",
                f"- Credential Source: {node.get('credential_source', 'unknown')}",
                "",
            ]
        )
        interfaces = node.get("interfaces") or []
        if interfaces:
            lines.append("| Interface | IP | Status | Protocol |")
            lines.append("|---|---:|---|---|")
            for item in interfaces:
                interface_row = (
                    f"| {item.get('name')} | {item.get('ip')} | "
                    f"{item.get('status')} | {item.get('protocol')} |"
                )
                lines.append(interface_row)
            lines.append("")

    lines.extend(["## Links", ""])
    if links:
        lines.append("| Source | Target | Protocol | Source Interface | Target Interface |")
        lines.append("|---|---|---|---|---|")
        for link in links:
            link_row = (
                "| {source} | {target} | {protocol} | "
                "{source_interface} | {target_interface} |"
            ).format(
                source=link.get("source", ""),
                target=link.get("target", ""),
                protocol=link.get("protocol", ""),
                source_interface=link.get("source_interface", ""),
                target_interface=link.get("target_interface", ""),
            )
            lines.append(link_row)
    else:
        lines.append("No neighbor links were discovered.")
    lines.append("")

    lines.extend(["## Network Device Table", ""])
    network_devices = tables.get("network_devices") or []
    if network_devices:
        lines.append(
            "| Device | Address | Platform | Version | Upstream Device | "
            "Upstream Interface | Via |"
        )
        lines.append("|---|---|---|---|---|---|---|")
        for row in network_devices:
            lines.append(
                (
                    "| {device} | {address} | {platform} | {version} | {upstream} | "
                    "{interface} | {via} |"
                ).format(
                    device=row.get("device", ""),
                    address=row.get("address", ""),
                    platform=row.get("platform") or "",
                    version=row.get("software_version") or "",
                    upstream=row.get("upstream_device") or "",
                    interface=row.get("upstream_interface") or "",
                    via=row.get("discovered_via") or "",
                )
            )
    else:
        lines.append("No device table rows were generated.")
    lines.append("")

    lines.extend(["## Connected Interface Table", ""])
    connected_interfaces = tables.get("connected_interfaces") or []
    if connected_interfaces:
        lines.append(
            "| Device | Interface | VLAN | Trunk | Neighbors | Learned MACs | Learned IPs |"
        )
        lines.append("|---|---|---|---|---|---:|---|")
        for row in connected_interfaces:
            lines.append(
                (
                    "| {device} | {interface} | {vlan} | {trunk} | {neighbors} | "
                    "{macs} | {ips} |"
                ).format(
                    device=row.get("device", ""),
                    interface=row.get("interface") or "",
                    vlan=row.get("vlan") or "",
                    trunk=row.get("trunk"),
                    neighbors=", ".join(row.get("neighbor_names") or []),
                    macs=row.get("learned_mac_count") or 0,
                    ips=", ".join(row.get("learned_ips") or []),
                )
            )
    else:
        lines.append("No connected interface table rows were generated.")
    lines.append("")

    lines.extend(["## Learned Endpoint Table", ""])
    endpoints = tables.get("learned_endpoints") or []
    if endpoints:
        lines.append("| Observed On | Interface | VLAN | MAC | IPs | Neighbor Context |")
        lines.append("|---|---|---|---|---|---|")
        for row in endpoints:
            lines.append(
                "| {device} | {interface} | {vlan} | {mac} | {ips} | {neighbors} |".format(
                    device=row.get("observed_on_device", ""),
                    interface=row.get("interface") or "",
                    vlan=row.get("vlan") or "",
                    mac=row.get("mac") or "",
                    ips=", ".join(row.get("ips") or []),
                    neighbors=", ".join(row.get("neighbor_names") or []),
                )
            )
    else:
        lines.append("No learned endpoint table rows were generated.")
    lines.append("")

    lines.extend(["## Warnings", ""])
    if warnings:
        for warning in warnings:
            lines.append(f"- {warning}")
    else:
        lines.append("No warnings.")
    lines.append("")
    return "\n".join(lines)
