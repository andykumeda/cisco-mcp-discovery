"""Persist discovered devices back into the configured inventory file."""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

import yaml

from cisco_mcp_server.exceptions import InventoryError

DISCOVERED_GROUP = "discovered"


class InventoryUpdater:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def add_discovered_host(
        self,
        *,
        name: str,
        address: str,
        seed_name: str,
        seed_address: str,
        discovered_from: str,
        protocol: str,
    ) -> bool:
        if not self.path.exists():
            raise InventoryError(f"Inventory file does not exist: {self.path}")

        if self.path.suffix.lower() in {".yml", ".yaml"}:
            return self._add_yaml_host(
                name=name,
                address=address,
                seed_name=seed_name,
                seed_address=seed_address,
                discovered_from=discovered_from,
                protocol=protocol,
            )
        return self._add_ini_host(
            name=name,
            address=address,
            seed_name=seed_name,
            seed_address=seed_address,
            discovered_from=discovered_from,
            protocol=protocol,
        )

    def _add_yaml_host(
        self,
        *,
        name: str,
        address: str,
        seed_name: str,
        seed_address: str,
        discovered_from: str,
        protocol: str,
    ) -> bool:
        raw = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise InventoryError("YAML inventory must be a mapping.")

        root = raw.setdefault("all", {})
        if not isinstance(root, dict):
            raise InventoryError("YAML inventory 'all' group must be a mapping.")
        if _yaml_host_exists(root, name, address):
            return False

        children = root.setdefault("children", {})
        if not isinstance(children, dict):
            raise InventoryError("YAML inventory children must be a mapping.")
        discovered = children.setdefault(DISCOVERED_GROUP, {})
        if not isinstance(discovered, dict):
            raise InventoryError("YAML discovered group must be a mapping.")
        hosts = discovered.setdefault("hosts", {})
        if not isinstance(hosts, dict):
            raise InventoryError("YAML discovered hosts must be a mapping.")

        host_key = _host_key(name, address)
        while host_key in hosts:
            host_key = f"{host_key}-1"
        hosts[host_key] = {
            "ansible_host": address,
            "cisco_mcp_discovered_from_seed": seed_address,
            "cisco_mcp_discovered_seed_name": seed_name,
            "cisco_mcp_discovered_from_host": discovered_from,
            "cisco_mcp_discovery_protocol": protocol,
        }
        self._write_yaml_with_discovery_comments(raw)
        return True

    def _write_yaml_with_discovery_comments(self, raw: dict[str, Any]) -> None:
        text = yaml.safe_dump(raw, sort_keys=False, default_flow_style=False)
        lines = text.splitlines()
        discovered_hosts = _discovered_yaml_hosts(raw)
        output: list[str] = []
        in_discovered_hosts = False
        pending_comment = False

        for line in lines:
            stripped = line.strip()
            if stripped == f"{DISCOVERED_GROUP}:":
                pending_comment = True
                output.append(line)
                continue
            if pending_comment and stripped == "hosts:":
                in_discovered_hosts = True
                pending_comment = False
                output.append(line)
                continue
            if in_discovered_hosts and re.match(r"^\s{8}\S.*:\s*$", line):
                host_key = stripped.removesuffix(":")
                host_vars = discovered_hosts.get(host_key, {})
                indent = line[: len(line) - len(line.lstrip())]
                seed_address = str(host_vars.get("cisco_mcp_discovered_from_seed", "unknown"))
                seed_name = str(host_vars.get("cisco_mcp_discovered_seed_name", "unknown"))
                discovered_from = str(host_vars.get("cisco_mcp_discovered_from_host", "unknown"))
                protocol = str(host_vars.get("cisco_mcp_discovery_protocol", "unknown"))
                output.append(
                    f"{indent}# added from seed {seed_address} ({seed_name}); "
                    f"discovered from {discovered_from} via {protocol}"
                )
            output.append(line)

        self.path.write_text("\n".join(output) + "\n", encoding="utf-8")

    def _add_ini_host(
        self,
        *,
        name: str,
        address: str,
        seed_name: str,
        seed_address: str,
        discovered_from: str,
        protocol: str,
    ) -> bool:
        text = self.path.read_text(encoding="utf-8")
        if _ini_host_exists(text, name, address):
            return False

        host_key = _host_key(name, address)
        lines = text.splitlines()
        section_index = _find_ini_section(lines, DISCOVERED_GROUP)
        comment = (
            f"# added from seed {seed_address} ({seed_name}); "
            f"discovered from {discovered_from} via {protocol}"
        )
        host_line = " ".join(
            [
                host_key,
                f"ansible_host={shlex.quote(address)}",
                f"cisco_mcp_discovered_from_seed={shlex.quote(seed_address)}",
                f"cisco_mcp_discovered_seed_name={shlex.quote(seed_name)}",
                f"cisco_mcp_discovered_from_host={shlex.quote(discovered_from)}",
                f"cisco_mcp_discovery_protocol={shlex.quote(protocol)}",
            ]
        )

        if section_index is None:
            if lines and lines[-1].strip():
                lines.append("")
            lines.extend([f"[{DISCOVERED_GROUP}]", comment, host_line])
        else:
            insert_at = section_index + 1
            while insert_at < len(lines) and not (
                lines[insert_at].startswith("[") and lines[insert_at].endswith("]")
            ):
                insert_at += 1
            lines[insert_at:insert_at] = [comment, host_line]

        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return True


def _yaml_host_exists(node: dict[str, Any], name: str, address: str) -> bool:
    hosts = node.get("hosts", {})
    if isinstance(hosts, dict):
        for host_name, host_vars in hosts.items():
            if str(host_name) == name or str(host_name) == address:
                return True
            if isinstance(host_vars, dict) and str(host_vars.get("ansible_host")) == address:
                return True

    children = node.get("children", {})
    if isinstance(children, dict):
        return any(
            isinstance(child, dict) and _yaml_host_exists(child, name, address)
            for child in children.values()
        )
    return False


def _discovered_yaml_hosts(raw: dict[str, Any]) -> dict[str, dict[str, Any]]:
    all_group = raw.get("all", {})
    if not isinstance(all_group, dict):
        return {}
    children = all_group.get("children", {})
    if not isinstance(children, dict):
        return {}
    discovered = children.get(DISCOVERED_GROUP, {})
    if not isinstance(discovered, dict):
        return {}
    hosts = discovered.get("hosts", {})
    if not isinstance(hosts, dict):
        return {}
    return {str(name): values for name, values in hosts.items() if isinstance(values, dict)}


def _ini_host_exists(text: str, name: str, address: str) -> bool:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        try:
            parts = shlex.split(line, comments=True, posix=True)
        except ValueError:
            continue
        if not parts:
            continue
        if parts[0] in {name, address}:
            return True
        for token in parts[1:]:
            if token == f"ansible_host={address}":
                return True
    return False


def _find_ini_section(lines: list[str], section: str) -> int | None:
    target = f"[{section}]"
    for index, line in enumerate(lines):
        if line.strip() == target:
            return index
    return None


def _host_key(name: str, address: str) -> str:
    candidate = name or address
    candidate = candidate.strip().rstrip(".")
    candidate = re.sub(r"[^A-Za-z0-9_.-]+", "-", candidate)
    if not candidate or candidate.replace(".", "").isdigit():
        candidate = f"discovered-{address.replace('.', '-')}"
    return candidate
