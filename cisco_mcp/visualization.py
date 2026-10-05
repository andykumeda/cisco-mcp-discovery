import os
from html import escape
import datetime
import xml.etree.ElementTree as ET
import zlib
import base64
import urllib.parse
from typing import Dict, Any, Tuple, Optional, List
from collections import defaultdict, deque
import logging
import re

# Set up logger
logger = logging.getLogger(__name__)

from cisco_mcp.config import DATA_DIR

# User Data setup (mirrored from storage.py)
USER_DATA_DIR = DATA_DIR

class VisualizationEngine:
    def _get_node_style(self, node: Dict[str, Any], is_seed: bool = False) -> str:
        """Determine Draw.io style based on node metadata."""
        os_type = str(node.get("os", "")).lower()
        platform = str(node.get("platform", "")).lower()

        # Default styles (Rectangle)
        fill_color = "#dae8fc" # Blue (Default to Catalyst-like)
        stroke_color = "#6c8ebf"
        shape = "rectangle"

        if is_seed:
            fill_color = "#f8cecc" # Red
            stroke_color = "#b85450"
            shape = "mxgraph.cisco.switches.layer_3_switch"
        elif "nexus" in platform or "nxos" in os_type or "nx-os" in os_type:
            fill_color = "#d5e8d4" # Green
            stroke_color = "#82b366"
            shape = "mxgraph.cisco.switches.nexus_7000"
        elif "9300" in platform or "9500" in platform or "catalyst" in platform or "iosxe" in os_type:
            fill_color = "#dae8fc" # Blue
            stroke_color = "#6c8ebf"
            shape = "mxgraph.cisco.switches.layer_3_switch"
        elif "router" in platform or "isr" in platform or "asr" in platform:
            fill_color = "#ffe6cc" # Orange
            stroke_color = "#d79b00"
            shape = "mxgraph.cisco.routers.router"

        return f"shape={shape};rounded=0;whiteSpace=wrap;html=1;fillColor={fill_color};strokeColor={stroke_color};"

    def _shorten_interface(self, name: str) -> str:
        """Abbreviate common Cisco interface names to 3-letter chunks (e.g., TenGigEth)."""
        if not name: return ""

        # Separate the name from the port numbers (e.g., "TenGigabitEthernet" and "1/0/26")
        match = re.match(r'^([a-zA-Z\s\-]+)([0-9].*)$', name)
        if not match:
            # If no number found, just try to abbreviate the whole thing
            text_part = name
            num_part = ""
        else:
            text_part, num_part = match.groups()

        # Break text_part into chunks based on case changes or common Cisco words
        # e.g., "TenGigabitEthernet" -> "Ten", "Gigabit", "Ethernet"
        chunks = re.findall(r'(Ten|Gigabit|Ethernet|Fast|Forty|Hundred|TwentyFive|Port|Channel|Vlan|Loopback|Management|Serial|AppGigabit|Tunnel|[A-Z][a-z]+)', text_part.replace("-", ""), re.IGNORECASE)

        if not chunks:
            # Fallback if no chunks found: just take first 3 of the text_part
            return text_part[:3].capitalize() + num_part

        short_parts = []
        for c in chunks:
            # Handle special cases or just take first 3
            c_clean = c.replace("-", "")
            if len(c_clean) <= 3:
                short_parts.append(c_clean.capitalize())
            else:
                short_parts.append(c_clean[:3].capitalize())

        return "".join(short_parts) + num_part

    def export_topology_to_drawio(
        self,
        topology: Dict[str, Any],
        start_host: str,
        output_path: Optional[str] = None,
    ) -> Tuple[Optional[str], Optional[str]]:
        if not topology.get("nodes"):
            return None, None

        nodes = {node["id"]: node for node in topology.get("nodes", []) if node.get("id")}
        if not nodes:
            return None, None

        start_node_id = start_host if start_host in nodes else next(iter(nodes))

        adjacency: Dict[str, set] = defaultdict(set)
        for link in topology.get("links", []):
            source = link.get("source")
            target = link.get("target")
            if source in nodes and target in nodes:
                adjacency[source].add(target)
                adjacency[target].add(source)

        levels: Dict[str, int] = {start_node_id: 0}
        queue: deque = deque([start_node_id])
        while queue:
            current = queue.popleft()
            for neighbor in adjacency[current]:
                if neighbor not in levels:
                    levels[neighbor] = levels[current] + 1
                    queue.append(neighbor)

        extra_level = max(levels.values()) + 1 if levels else 0
        for node_id in nodes:
            if node_id not in levels:
                levels[node_id] = extra_level
                extra_level += 1

        level_nodes: Dict[int, List[str]] = defaultdict(list)
        for node_id, level in levels.items():
            level_nodes[level].append(node_id)

        cell_width = 180
        cell_height = 90
        x_spacing = 220
        y_spacing = 180

        top_padding = 80
        positions: Dict[str, Tuple[int, int]] = {}
        for level in sorted(level_nodes.keys()):
            nodes_in_level = level_nodes[level]

            # Heuristic: Sort nodes in current level based on the average X position of their neighbors in PREVIOUS level
            # to minimize line crossings.
            if level > 0:
                def get_neighbor_avg_x(nid):
                    connected = adjacency.get(nid, set())
                    prev_neighbors = [positions[n][0] for n in connected if n in positions and levels.get(n) < level]
                    if not prev_neighbors: return 0
                    return sum(prev_neighbors) / len(prev_neighbors)

                nodes_in_level.sort(key=get_neighbor_avg_x)
            else:
                nodes_in_level.sort()

            total_width = (len(nodes_in_level) - 1) * x_spacing
            start_x = -total_width // 2
            for index, node_id in enumerate(nodes_in_level):
                x = start_x + index * x_spacing
                y = level * y_spacing + top_padding
                positions[node_id] = (x, y)

        mx_root = ET.Element(
            "mxfile",
            host="app.diagrams.net",
            modified=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            agent="CiscoMCP",
            version="20.8.23",
            etag="0",
            type="device"
        )
        diagram = ET.SubElement(mx_root, "diagram", id="R2l669v_9Z9S4TcvXN_P", name="Network Topology")
        graph_model = ET.SubElement(
            diagram,
            "mxGraphModel",
            dx="1422",
            dy="762",
            grid="1",
            gridSize="10",
            guides="1",
            tooltips="1",
            connect="1",
            arrows="1",
            fold="1",
            page="1",
            pageScale="1",
            pageWidth="827",
            pageHeight="1169",
            math="0",
            shadow="0"
        )
        root_element = ET.SubElement(graph_model, "root")
        ET.SubElement(root_element, "mxCell", id="0")
        ET.SubElement(root_element, "mxCell", id="1", parent="0")

        # Track connections per node for spreading out edges
        node_link_indices: Dict[str, int] = defaultdict(int)
        node_total_links: Dict[str, int] = defaultdict(int)
        for link in topology.get("links", []):
            s, t = link.get("source"), link.get("target")
            if s in nodes and t in nodes:
                node_total_links[s] += 1
                node_total_links[t] += 1

        node_id_map: Dict[str, str] = {}
        for index, (node_id, node_data) in enumerate(nodes.items(), start=1):
            cell_id = f"node_{index}"
            node_id_map[node_id] = cell_id
            x, y = positions.get(node_id, (0, 0))

            # Use hostname if available, otherwise ID (which might be IP)
            hostname = node_data.get("hostname")
            label = hostname if hostname and hostname != "unknown" else node_data.get("label") or node_id

            # Strip domain names only if it's NOT a numeric IP address
            if not re.match(r'^[0-9\.]+$', label):
                label = label.split('.')[0]

            # Only use IP in label if the label itself is an IP (meaning no hostname found)
            if re.match(r'^[0-9\.]+$', label) and node_data.get("id") != label:
                # If we have a better label, we don't need the IP here as it moves to interfaces
                pass
            elif not re.match(r'^[0-9\.]+$', label):
                # We have a hostname, so we don't need the IP in the rectangle
                pass
            else:
                # Label is likely an IP, keep it
                pass

            # Include Platform if available
            platform = node_data.get("platform")
            if platform and platform != "unknown":
                # Strip noise like "cisco", "nexus", "software", "operating system"
                clean_plat = re.sub(r'(?i)cisco|platform|nexus|software|operating|system', '', platform).strip()
                if clean_plat:
                    label = f"{label}\n{clean_plat}"

            is_seed = (node_id == start_node_id)
            style = self._get_node_style(node_data, is_seed=is_seed)

            cell = ET.SubElement(
                root_element,
                "mxCell",
                id=cell_id,
                value=escape(str(label)),
                style=style,
                vertex="1",
                parent="1",
            )
            ET.SubElement(cell, "mxGeometry", {"x": str(x), "y": str(y), "width": str(cell_width), "height": str(cell_height), "as": "geometry"})

        for index, link in enumerate(topology.get("links", []), start=1):
            source = link.get("source")
            target = link.get("target")
            if source in node_id_map and target in node_id_map:
                source_int = self._shorten_interface(str(link.get("source_int", "")))
                target_int = self._shorten_interface(str(link.get("target_int", "")))

                source_ip = link.get("source_ip", "")
                if source_ip:
                    # Append IP to source interface label
                    source_int = f"{source_int}\n({source_ip})"

                target_ip = link.get("target_ip", "")
                if target_ip:
                    # Append IP to target interface label
                    target_int = f"{target_int}\n({target_ip})"

                # Calculate connection points (distribute across bottom for source, top for target)
                # We use a simple 0.1 to 0.9 distribution
                s_count = node_total_links[source]
                t_count = node_total_links[target]
                s_idx = node_link_indices[source]
                t_idx = node_link_indices[target]

                # Use a wider distribution (0.05 to 0.95) for better spreading
                exit_x = 0.5 if s_count <= 1 else 0.05 + (s_idx * 0.9 / (s_count - 1))
                entry_x = 0.5 if t_count <= 1 else 0.05 + (t_idx * 0.9 / (t_count - 1))

                node_link_indices[source] += 1
                node_link_indices[target] += 1

                style = (
                    "edgeStyle=orthogonalEdgeStyle;"
                    "rounded=1;"
                    "html=1;"
                    "endArrow=none;"
                    "startArrow=none;"
                    "curved=1;"
                    f"exitX={exit_x:.2f};exitY=1;exitDx=0;exitDy=0;"
                    f"entryX={entry_x:.2f};entryY=0;entryDx=0;entryDy=0;"
                )

                edge_id = f"edge_{index}"
                edge_cell = ET.SubElement(
                    root_element,
                    "mxCell",
                    id=edge_id,
                    value="", # No center label
                    style=style,
                    edge="1",
                    source=node_id_map[source],
                    target=node_id_map[target],
                    parent="1",
                )
                ET.SubElement(edge_cell, "mxGeometry", {"relative": "1", "as": "geometry"})

                # Source Interface Label
                if source_int:
                    s_label = ET.SubElement(root_element, "mxCell",
                        id=f"{edge_id}_s", value=escape(str(source_int)),
                        style="edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];",
                        vertex="1", connectable="0", parent=edge_id)
                    ET.SubElement(s_label, "mxGeometry", {"x": "-0.8", "relative": "1", "as": "geometry"})

                # Target Interface Label
                if target_int:
                    t_label = ET.SubElement(root_element, "mxCell",
                        id=f"{edge_id}_t", value=escape(str(target_int)),
                        style="edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];",
                        vertex="1", connectable="0", parent=edge_id)
                    ET.SubElement(t_label, "mxGeometry", {"x": "0.8", "relative": "1", "as": "geometry"})

        # --- Add Topology Summary Table ---
        # Calculate table position
        max_x = max([pos[0] for pos in positions.values()]) if positions else 0
        max_y = max([pos[1] for pos in positions.values()]) if positions else 0

        table_x = 50
        table_y = max_y + 300 # Place below the diagram

        # Create HTML Table content
        table_html = [
            '<table border="1" style="width:100%; border-collapse: collapse; font-family: Arial, sans-serif; font-size: 10pt;">',
            '<tr style="background-color: #f2f2f2;">',
            '<th>Local Device</th><th>Model</th><th>Local Intf</th><th>Local IP</th><th>Remote Device</th><th>Remote Intf</th>',
            '</tr>'
        ]

        # Sort links by source device name then interface for a clean table
        def get_node_label(nid):
            n = next((node for node in topology.get("nodes", []) if node["id"] == nid), {})
            return n.get("label") or n.get("hostname") or nid

        sorted_links = sorted(topology.get("links", []), key=lambda x: (get_node_label(x.get("source", "")), x.get("source_int", "")))

        for link in sorted_links:
            src_node = next((n for n in topology.get("nodes", []) if n["id"] == link["source"]), {})
            tgt_node = next((n for n in topology.get("nodes", []) if n["id"] == link["target"]), {})

            src_name = get_node_label(link["source"])
            src_model = src_node.get("platform", "unknown")
            src_int = link.get("source_int", "")
            src_ip = link.get("source_ip", "")

            tgt_name = get_node_label(link["target"])
            tgt_int = link.get("target_int", "")

            # Clean up model string for table
            clean_m = re.sub(r'(?i)cisco|platform|nexus|software|operating|system', '', src_model).strip() if src_model != "unknown" else src_model

            src_name, clean_m, src_int, src_ip, tgt_name, tgt_int = [escape(str(v or '')) for v in (src_name, clean_m, src_int, src_ip, tgt_name, tgt_int)]
            table_html.append(f'<tr><td>{src_name}</td><td>{clean_m}</td><td>{src_int}</td><td>{src_ip}</td><td>{tgt_name}</td><td>{tgt_int}</td></tr>')

        table_html.append('</table>')

        # Add table vertex
        table_xml = ET.SubElement(root_element, "mxCell",
            id=f"table_summary",
            value='<div style="box-sizing:border-box;width:100%;height:100%;overflow:hidden;">' + "".join(table_html) + '</div>',
            style="text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=top;whiteSpace=wrap;overflow=hidden;rounded=0;",
            vertex="1",
            parent="1"
        )
        ET.SubElement(table_xml, "mxGeometry", {
            "x": str(table_x),
            "y": str(table_y),
            "width": "850",
            "height": str(len(sorted_links) * 40 + 60),
            "as": "geometry"
        })

        # --- Footer ---
        footer_y = table_y + len(sorted_links) * 40 + 100
        footer_text = f"Generated by Cisco MCP on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        footer_cell = ET.SubElement(
            root_element,
            "mxCell",
            id="footer",
            value=footer_text,
            style="text;html=1;align=center;verticalAlign=middle;resizable=0;points=[];labelBackgroundColor=none;fontColor=#666666;",
            vertex="1",
            parent="1",
        )
        ET.SubElement(footer_cell, "mxGeometry", {"x": "0", "y": str(footer_y), "width": "800", "height": "30", "as": "geometry"})

        # Draw.io often prefers no XML declaration headers and clean starts
        xml_bytes = ET.tostring(mx_root, encoding="utf-8")
        xml_text = xml_bytes.decode("utf-8")

        xml_text = xml_text.strip()

        # ALWAYS save a clean copy to disk to avoid AI-induced formatting issues in chat
        try:
            os.makedirs(USER_DATA_DIR, mode=0o700, exist_ok=True)
            default_path = os.path.join(USER_DATA_DIR, "topology.drawio")
            with open(os.open(default_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8") as fh:
                fh.write(xml_text)
            logger.info(f"Saved clean Draw.io XML to {default_path}")
        except Exception as e:
            logger.error(f"Failed to save default topology file: {e}")

        if output_path:
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(xml_text)
            return output_path, xml_text

        return os.path.join(USER_DATA_DIR, "topology.drawio"), xml_text

    def export_topology_to_url(self, xml_text: str) -> str:
        """Encode the XML into a Draw.io open URL."""
        try:
            # Draw.io format: deflate -> base64 -> urlencode
            # Use raw deflate (no headers)
            compressed = zlib.compress(xml_text.encode("utf-8"), wbits=-15)
            encoded = base64.b64encode(compressed).decode("utf-8")
            return f"https://app.diagrams.net/#R{urllib.parse.quote(encoded)}"
        except Exception as e:
            logger.error(f"Failed to generate Draw.io URL: {e}")
            return ""

    def export_topology_to_base64(self, xml_text: str) -> str:
        """Return base64 encoded XML for safe transfer."""
        return base64.b64encode(xml_text.encode("utf-8")).decode("utf-8")
