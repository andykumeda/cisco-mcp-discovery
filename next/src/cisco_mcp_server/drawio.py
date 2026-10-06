"""Draw.io XML topology export."""

from __future__ import annotations

import datetime
import xml.etree.ElementTree as ET
from collections import defaultdict, deque
from typing import Any


def generate_drawio_xml(topology: dict[str, Any]) -> str:
    nodes = {node["id"]: node for node in topology.get("nodes", []) if node.get("id")}
    links = topology.get("links", [])

    root = ET.Element(
        "mxfile",
        host="app.diagrams.net",
        modified=datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        agent="CiscoMCP",
        version="24.0.0",
    )
    diagram = ET.SubElement(root, "diagram", id="topology", name="Network Topology")
    graph_model = ET.SubElement(diagram, "mxGraphModel")
    root_element = ET.SubElement(graph_model, "root")
    ET.SubElement(root_element, "mxCell", id="0")
    ET.SubElement(root_element, "mxCell", id="1", parent="0")

    if not nodes:
        return ET.tostring(root, encoding="unicode")

    positions = _layout(nodes, links)
    node_id_map: dict[str, str] = {}
    for index, (node_id, node) in enumerate(nodes.items(), start=1):
        cell_id = f"node_{index}"
        node_id_map[node_id] = cell_id
        x, y = positions[node_id]
        label = node.get("label") or node.get("hostname") or node_id
        cell = ET.SubElement(
            root_element,
            "mxCell",
            id=cell_id,
            value=str(label),
            style="shape=rectangle;rounded=0;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;",
            vertex="1",
            parent="1",
        )
        ET.SubElement(
            cell,
            "mxGeometry",
            x=str(x),
            y=str(y),
            width="180",
            height="80",
            **{"as": "geometry"},
        )

    for index, link in enumerate(links, start=1):
        source = link.get("source")
        target = link.get("target")
        if source not in node_id_map or target not in node_id_map:
            continue
        label = _link_label(link)
        edge = ET.SubElement(
            root_element,
            "mxCell",
            id=f"edge_{index}",
            value=label,
            style="edgeStyle=elbowEdgeStyle;rounded=1;html=1;",
            edge="1",
            source=node_id_map[source],
            target=node_id_map[target],
            parent="1",
        )
        ET.SubElement(edge, "mxGeometry", relative="1", **{"as": "geometry"})

    return ET.tostring(root, encoding="unicode")


def _layout(
    nodes: dict[str, dict[str, Any]], links: list[dict[str, Any]]
) -> dict[str, tuple[int, int]]:
    adjacency: dict[str, set[str]] = defaultdict(set)
    for link in links:
        source = link.get("source")
        target = link.get("target")
        if source in nodes and target in nodes:
            adjacency[source].add(target)
            adjacency[target].add(source)

    start = next(iter(nodes))
    levels: dict[str, int] = {start: 0}
    queue: deque[str] = deque([start])
    while queue:
        current = queue.popleft()
        for neighbor in sorted(adjacency[current]):
            if neighbor not in levels:
                levels[neighbor] = levels[current] + 1
                queue.append(neighbor)

    extra_level = max(levels.values(), default=0) + 1
    for node_id in nodes:
        if node_id not in levels:
            levels[node_id] = extra_level
            extra_level += 1

    by_level: dict[int, list[str]] = defaultdict(list)
    for node_id, level in levels.items():
        by_level[level].append(node_id)

    positions: dict[str, tuple[int, int]] = {}
    for level, level_nodes in sorted(by_level.items()):
        level_nodes.sort()
        start_x = -((len(level_nodes) - 1) * 220) // 2
        for index, node_id in enumerate(level_nodes):
            positions[node_id] = (start_x + index * 220, 80 + level * 170)
    return positions


def _link_label(link: dict[str, Any]) -> str:
    source_int = link.get("source_interface") or ""
    target_int = link.get("target_interface") or ""
    if source_int or target_int:
        return f"{source_int} -> {target_int}".strip()
    return str(link.get("protocol") or "")
