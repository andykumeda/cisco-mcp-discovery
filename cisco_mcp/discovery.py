from __future__ import annotations
import logging
import asyncio
import re
from typing import Dict, Any, List, Set, Optional
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from cisco_mcp.ssh import CiscoSSHManager

logger = logging.getLogger(__name__)

class DiscoveryEngine:
    def __init__(self, ssh_manager: CiscoSSHManager):
        self.ssh = ssh_manager

    def _get_canonical_id(self, node_data: Dict[str, Any], existing_nodes: Dict[str, Any]) -> str:
        """Determine the canonical ID for a node (prefer hostname)."""
        hostname = node_data.get("hostname")
        if hostname and hostname != "unknown":
            # Clean hostname (strip domain)
            clean_name = hostname.split('.')[0].lower()
            return clean_name
        return node_data["id"]

    def _merge_node(self, existing_nodes: Dict[str, Any], new_node: Dict[str, Any], alias_map: Dict[str, str]) -> str:
        """Smart merge of a new node into the existing map. Returns the canonical ID."""
        raw_id = new_node["id"]
        hostname = new_node.get("hostname")

        # Determine canonical ID
        canonical_id = self._get_canonical_id(new_node, existing_nodes)

        # Check if this canonical ID or any of its aliases already exist
        matching_id = None
        if canonical_id in existing_nodes:
            matching_id = canonical_id
        elif hostname:
            clean_h = hostname.split('.')[0].lower()
            if clean_h in existing_nodes:
                matching_id = clean_h

        if matching_id:
            self._update_node_attributes(existing_nodes[matching_id], new_node)
            alias_map[raw_id] = matching_id
            if hostname: alias_map[hostname.lower()] = matching_id
            return matching_id

        # Check if raw_id is an alias for something else
        if raw_id in alias_map:
            matching_id = alias_map[raw_id]
            self._update_node_attributes(existing_nodes[matching_id], new_node)
            return matching_id

        # Add new
        new_node["id"] = canonical_id
        existing_nodes[canonical_id] = new_node
        alias_map[raw_id] = canonical_id
        if hostname: alias_map[hostname.lower()] = canonical_id
        return canonical_id

    def _update_node_attributes(self, target: Dict[str, Any], source: Dict[str, Any]):
        """Update fields in target if source has better data."""
        for k, v in source.items():
            if k not in target or not target[k] or target[k] == "unknown":
                if v:
                    target[k] = v
        # Merge lists (ip_addresses, etc)
        for list_field in ["ip_addresses", "routes", "cdp_neighbors"]:
            if list_field in source and source[list_field]:
                existing_set = set(str(x) for x in target.get(list_field, []))
                for item in source[list_field]:
                    if str(item) not in existing_set:
                         target.setdefault(list_field, []).append(item)

    def _parse_cdp_regex(self, raw_output: str) -> List[Dict[str, Any]]:
        """Fallback regex parser for 'show cdp neighbors detail' (IOS-XE and NX-OS)"""
        neighbors = []
        # Split by the separator (variable dashes) or Device ID starts
        blocks = re.split(r'-{20,}|Device ID:', raw_output)
        for block in blocks:
            if not block.strip():
                continue

            neighbor = {}
            # Device ID (if not caught by split)
            id_match = re.search(r'^[:\s]*(\S+)', block)
            neighbor['device_id'] = id_match.group(1).split('(')[0] if id_match else None

            # IP Address (Supports 'IP address:' and 'IPv4 Address:')
            ip_match = re.search(r'(?:IP|IPv4) address(?::|es:)?\s*([0-9\.]+)', block, re.IGNORECASE)
            # Some NX-OS versions have it on the next line
            if not ip_match:
                ip_match = re.search(r'IPv4 Address:\s*([0-9\.]+)', block, re.IGNORECASE)

            neighbor['entry_address'] = ip_match.group(1) if ip_match else None
            mac_match = re.search(r'Remote Interface MAC:\s*(\S+)', block, re.IGNORECASE)
            neighbor['remote_mac'] = mac_match.group(1) if mac_match else None

            # Platform
            plat_match = re.search(r'Platform: ([^,]+)', block)
            neighbor['platform'] = plat_match.group(1).strip() if plat_match else None

            # Interfaces
            int_match = re.search(r'Interface: ([^,]+)', block)
            neighbor['local_interface'] = int_match.group(1).strip() if int_match else None

            port_match = re.search(r'Port ID \(outgoing port\): (\S+)', block)
            neighbor['port_id'] = port_match.group(1).strip() if port_match else None

            if neighbor.get('device_id') or neighbor.get('entry_address'):
                neighbors.append(neighbor)
        return neighbors

    def _parse_lldp_regex(self, raw_output: str) -> List[Dict[str, Any]]:
        """Fallback regex parser for 'show lldp neighbors detail'"""
        neighbors = []
        # Split by Chasis id or System Name
        blocks = re.split(r'(?=Local Intf:)', raw_output)
        for block in blocks:
            if not block.strip():
                continue
            neighbor = {}
            local_match = re.search(r'Local Intf:\s*(\S+)', block)
            neighbor['local_interface'] = local_match.group(1) if local_match else None
            # System Name
            name_match = re.search(r'System Name:\s*(\S+)', block)
            neighbor['device_id'] = name_match.group(1) if name_match else None

            # Management Address
            ip_match = re.search(r'Management Address:\s*([0-9\.]+)', block)
            neighbor['entry_address'] = ip_match.group(1) if ip_match else None

            # Platform (System Description)
            plat_match = re.search(r'System Description:\s*([^,\n]+)', block)
            neighbor['platform'] = plat_match.group(1).strip() if plat_match else None

            # Interfaces
            port_match = re.search(r'Port id:\s*(\S+)', block)
            neighbor['port_id'] = port_match.group(1).strip() if port_match else None

            if neighbor.get('device_id') or neighbor.get('entry_address'):
                neighbors.append(neighbor)
        return neighbors

    def _parse_version_regex(self, raw_output: str) -> Dict[str, Any]:
        """Fallback regex for 'show version' extracting OS and Platform"""
        data = {"os": "unknown", "platform": "unknown", "hostname": "unknown"}

        # OS Detection
        if "NX-OS" in raw_output or "Nexus" in raw_output:
            data["os"] = "NX-OS"
        elif "IOS XE" in raw_output:
            data["os"] = "IOS-XE"
        elif "IOS Software" in raw_output:
            data["os"] = "IOS"

        # Platform Detection - Look for specific model patterns
        plat_match = re.search(r'cisco\s+(Nexus\s*\d{4}\s+\S+|C\d{4}\S+|ISR\s*\d{4}\S+|ASR\s*\d{4}\S+)', raw_output, re.IGNORECASE)
        if not plat_match:
             # Fallback for generic Catalyst or Nexus without 'cisco' prefix
             plat_match = re.search(r'(C9[0-9]{3}\S+|Nexus\s*[0-9]{4}\S+)', raw_output, re.IGNORECASE)

        if plat_match:
            data["platform"] = plat_match.group(1).strip()

        # Hostname Detection
        host_match = re.search(r'Device name: (\S+)', raw_output)
        if not host_match:
            # Handle "NAME uptime is..." or "NAME  uptime is..."
            host_match = re.search(r'^(\S+)\s+(?:\d+\s+)?uptime is', raw_output, re.MULTILINE)
        if not host_match:
            # Check if hostname matches the prompt-like pattern often at the top of some version outputs
            host_match = re.search(r'^(\S+)[#>]show version', raw_output, re.MULTILINE)

        if host_match:
            data["hostname"] = host_match.group(1).strip().rstrip(',').rstrip(':')

        return data

    async def _get_arp_table(self, host: str) -> Dict[str, str]:
        """Fetch and parse ARP table: MAC -> IP"""
        arp_map = {}
        res = await self.ssh.execute_ssh_command_direct(host, "show ip arp", enforce_whitelist=False, use_genie=True)
        if res["success"]:
            parsed = res.get("parsed_output")
            if parsed and "interfaces" in parsed:
                # Genie format for ARP
                for intf, data in parsed["interfaces"].items():
                    if "ipv4" in data and "neighbors" in data["ipv4"]:
                        for ip, detail in data["ipv4"]["neighbors"].items():
                            mac = detail.get("link_layer_address")
                            if mac: arp_map[re.sub(r"[.:-]", "", mac).lower()] = ip
            else:
                # Regex fallback for ARP
                # Format: Protocol  Address          Age (min)  Hardware Addr   Type   Interface
                matches = re.finditer(r'Internet\s+([0-9\.]+)\s+\S+\s+([0-9a-f\.]+)', res["output"], re.IGNORECASE)
                for m in matches:
                    ip, mac = m.groups()
                    arp_map[mac.replace(".", "").lower()] = ip
        return arp_map

    async def discover_devices(self, start_host: str, depth: int, max_devices: int = 100) -> Dict[str, Any]:
        """Discovery entry point."""
        if type(depth) is not int or not 0 <= depth <= 10:
            raise ValueError("Depth must be an integer from 0 to 10.")
        if type(max_devices) is not int or not 1 <= max_devices <= 100:
            raise ValueError("Device limit must be an integer from 1 to 100.")
        visited = set()
        nodes_map: Dict[str, Any] = {}
        alias_map: Dict[str, str] = {} # Maps IP/Hostname -> Canonical ID
        links: List[Dict[str, Any]] = []
        warnings: List[str] = []

        queue = asyncio.Queue()
        queue.put_nowait((start_host, depth))

        while not queue.empty():
            host, current_depth = await queue.get()

            if host in visited or current_depth < 0:
                continue
            visited.add(host)

            allowed = (self.ssh.config.is_host_allowed(host) if host == start_host
                       else self.ssh.config.is_discovery_host_allowed(host))
            if not allowed:
                warnings.append(f"Host {host} skipped (outside permitted scope)")
                continue
            if len(visited) > max_devices:
                warnings.append("Device limit reached; discovery is incomplete.")
                break

            logger.info(f"Discovering {host} (Depth: {current_depth})")

            # Create base node
            node = {
                "id": host,
                "label": host,
                "ip_addresses": [host],
                "platform": "unknown",
                "os": "unknown"
            }

            # 1. Gather Device Details (OS, Version)
            ver = await self.ssh.execute_ssh_command_direct(host, "show version", enforce_whitelist=False, use_genie=True)
            if ver["success"]:
                node["version_raw"] = ver["output"]
                parsed = ver.get("parsed_output")
                if not parsed:
                    parsed = self._parse_version_regex(ver["output"])

                # Update node with parsed data
                node.update({
                    "os": parsed.get("os") or "unknown",
                    "platform": parsed.get("platform") or "unknown",
                    "hostname": parsed.get("hostname") or host
                })
                if node.get("hostname") and node["hostname"] != "unknown":
                    node["label"] = node["hostname"].split('.')[0]
            else:
                 warnings.append(f"Failed to connect to {host}: {ver.get('error')}")
                 self._merge_node(nodes_map, node, alias_map)
                 continue

            # Merge now to get canonical ID
            current_canonical_id = self._merge_node(nodes_map, node, alias_map)

            # 2. Get CDP Neighbors
            cdp = await self.ssh.execute_ssh_command_direct(host, "show cdp neighbors detail", enforce_whitelist=False, use_genie=True)
            neighbors_data = []
            if cdp["success"]:
                 parsed_cdp = cdp.get("parsed_output")
                 if parsed_cdp and "index" in parsed_cdp:
                      for idx, n_data in parsed_cdp["index"].items():
                           neighbors_data.append({
                               "entry_address": next(iter(n_data.get("entry_addresses", {}).keys()), None),
                               "device_id": n_data.get("device_id"),
                               "local_interface": n_data.get("local_interface"),
                               "port_id": n_data.get("port_id"),
                               "platform": n_data.get("platform")
                           })
                 else:
                      neighbors_data = self._parse_cdp_regex(cdp["output"])

            logger.info(f"Found {len(neighbors_data)} CDP neighbors on {host}")

            # 2b. Try LLDP if CDP is thin or failed
            if len(neighbors_data) < 2:
                 lldp = await self.ssh.execute_ssh_command_direct(host, "show lldp neighbors detail", enforce_whitelist=False, use_genie=True)
                 if lldp["success"]:
                      parsed_lldp = lldp.get("parsed_output")
                      lldp_data = []
                      if parsed_lldp and "interfaces" in parsed_lldp:
                           lldp_data = self._parse_lldp_regex(lldp["output"])
                      else:
                           lldp_data = self._parse_lldp_regex(lldp["output"])

                      # Merge unique neighbors
                      known_ids = {n.get("device_id") for n in neighbors_data if n.get("device_id")}
                      for n in lldp_data:
                           if n.get("device_id") not in known_ids:
                                neighbors_data.append(n)
                 logger.info(f"Total neighbors after LLDP check: {len(neighbors_data)}")

            # 3. ARP table for potential IP resolution
            arp_map = await self._get_arp_table(host)
            if arp_map:
                 logger.debug(f"Fetched ARP table for {host} ({len(arp_map)} entries)")

            # 4. Resolve CDC neighbors with missing IPs using ARP
            for n_data in neighbors_data:
                 if not n_data.get("entry_address"):
                      remote_mac = n_data.get("remote_mac")
                      if remote_mac:
                           mac = re.sub(r"[.:-]", "", remote_mac).lower()
                           if mac in arp_map:
                                n_data["entry_address"] = arp_map[mac]

            # 5. Process Neighbors & Create Links
            seen_links = set() # Avoid duplicates within this device's discovery
            neighbors_to_visit = []
            for n_data in neighbors_data:
                 neighbor_ip = n_data.get("entry_address")
                 neighbor_id = n_data.get("device_id")

                 if not neighbor_ip and not neighbor_id:
                     continue

                 # Create a stub for the neighbor to get its canonical ID
                 stub = {
                     "id": neighbor_ip or neighbor_id,
                     "hostname": neighbor_id,
                     "platform": n_data.get("platform")
                 }

                 # Merge neighbor stub to ensure we use the same canonical ID everywhere
                 if len(nodes_map) >= max_devices and self._get_canonical_id(stub, nodes_map) not in nodes_map and stub["id"] not in alias_map:
                     warnings.append("Device limit reached; additional neighbor omitted.")
                     continue
                 n_canonical_id = self._merge_node(nodes_map, stub, alias_map)

                 # Deduplicate link (canonical key handles bidirectional/redundant protocols)
                 local_int = n_data.get("local_interface")
                 remote_int = n_data.get("port_id")
                 target_ip = n_data.get("entry_address")

                 # source_ip should be the IP address of the device we are CURRENTLY discovering (host)
                 # We prefer the numeric host IP if it was provided, otherwise use the node's first known IP
                 source_ip = host if re.match(r'^[0-9\.]+$', host) else (node.get("ip_addresses")[0] if node.get("ip_addresses") else None)

                 # Form a canonical link key: sorted tuple of (node, interface)
                 link_pair = tuple(sorted([
                     (current_canonical_id, local_int),
                     (n_canonical_id, remote_int)
                 ]))

                 # Check if this link already exists in the master list
                 existing_link = None
                 for existing in links:
                     e_p1 = (existing["source"], existing.get("source_int"))
                     e_p2 = (existing["target"], existing.get("target_int"))
                     e_key = tuple(sorted([e_p1, e_p2]))
                     if e_key == link_pair:
                         existing_link = existing
                         break

                 if existing_link:
                     # Merge IP information if we found it from the other side
                     # If the existing link's source matches our canonical target,
                     # then our 'target_ip' is their 'source_ip'.
                     if existing_link["source"] == n_canonical_id:
                         if not existing_link.get("source_ip") and target_ip:
                             existing_link["source_ip"] = target_ip
                         if not existing_link.get("target_ip") and source_ip:
                             existing_link["target_ip"] = source_ip
                     else:
                         if not existing_link.get("target_ip") and target_ip:
                             existing_link["target_ip"] = target_ip
                         if not existing_link.get("source_ip") and source_ip:
                             existing_link["source_ip"] = source_ip
                 else:
                     links.append({
                         "source": current_canonical_id,
                         "target": n_canonical_id,
                         "source_int": local_int,
                         "target_int": remote_int,
                         "source_ip": source_ip,
                         "target_ip": target_ip
                     })

                 if neighbor_ip:
                      if neighbor_ip not in visited:
                           logger.info(f"Adding downstream node to discovery queue: {neighbor_ip} (discovered from {host})")
                           neighbors_to_visit.append(neighbor_ip)
                      else:
                           logger.debug(f"Skipping downstream node {neighbor_ip} - already visited")
                 else:
                      warnings.append(f"Neighbor {neighbor_id} has no management address; cannot recurse.")

            # Recurse
            if current_depth > 0:
                next_depth = current_depth - 1
                for n_ip in neighbors_to_visit:
                    logger.info(f"Queueing {n_ip} for discovery at depth {next_depth}")
                    queue.put_nowait((n_ip, next_depth))
            else:
                if neighbors_to_visit:
                    logger.info(f"Depth limit reached (0). Not recursing to: {', '.join(neighbors_to_visit)}")

        return {
            "nodes": list(nodes_map.values()),
            "links": links,
            "warnings": warnings
        }
