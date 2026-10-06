"""Core Ansible-style inventory loading.

This intentionally supports the common static INI/YAML inventory forms without
depending on Ansible itself. Dynamic inventory plugins and Vault are out of
scope for v1.
"""

from __future__ import annotations

import os
import re
import shlex
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from cisco_mcp_server.exceptions import InventoryError
from cisco_mcp_server.models import DeviceTarget

ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
DEFAULT_DEVICE_USER = "lab-reader"
DEFAULT_DEVICE_KEY_FILE = "~/.ssh/cisco_mcp_id_ed25519"


class Inventory:
    def __init__(
        self,
        hosts: dict[str, dict[str, Any]],
        group_vars: dict[str, dict[str, Any]] | None = None,
        host_groups: dict[str, set[str]] | None = None,
    ) -> None:
        self._hosts = hosts
        self._group_vars = group_vars or {}
        self._host_groups = host_groups or defaultdict(set)

    @property
    def hosts(self) -> tuple[str, ...]:
        return tuple(sorted(self._hosts))

    @property
    def groups(self) -> dict[str, list[str]]:
        grouped: dict[str, list[str]] = defaultdict(list)
        for host, groups in self._host_groups.items():
            for group in groups:
                grouped[group].append(host)
        return {group: sorted(hosts) for group, hosts in sorted(grouped.items())}

    def has_host(self, host: str) -> bool:
        return host in self._hosts or any(
            self._hosts[name].get("ansible_host") == host for name in self._hosts
        )

    def resolve(self, host: str) -> DeviceTarget:
        name = host if host in self._hosts else self._name_by_address(host)
        if name is None:
            raise InventoryError(f"Host '{host}' is not present in inventory.")

        merged: dict[str, Any] = {}
        groups = sorted(self._host_groups.get(name, set()))
        for group in groups:
            merged.update(self._group_vars.get(group, {}))
        merged.update(self._hosts[name])
        merged = _resolve_env_values(merged)

        address = str(merged.get("ansible_host") or name)
        username = _optional_string(
            merged.get("ansible_user") or merged.get("username") or _default_device_user()
        )
        password = _optional_string(
            merged.get("ansible_password")
            or merged.get("ansible_ssh_pass")
            or merged.get("password")
        )
        key_file = _optional_string(
            merged.get("ansible_ssh_private_key_file")
            or merged.get("private_key_file")
            or merged.get("key_file")
        )
        if password is None and key_file is None:
            key_file = _default_device_key_file()
        port = int(merged.get("ansible_port") or merged.get("port") or 22)
        device_type = _device_type_from_vars(merged)

        return DeviceTarget(
            name=name,
            address=address,
            username=username,
            password=password,
            key_file=key_file,
            port=port,
            device_type=device_type,
            groups=tuple(groups),
            vars=merged,
            source="inventory",
            credential_source=name,
        )

    def public_hosts(self, group: str | None = None) -> list[dict[str, Any]]:
        names = self.hosts
        if group:
            names = tuple(
                sorted(name for name in names if group in self._host_groups.get(name, set()))
            )
        return [self.resolve(name).public_dict() for name in names]

    def _name_by_address(self, address: str) -> str | None:
        for name, values in self._hosts.items():
            if values.get("ansible_host") == address:
                return name
        return None


def load_inventory(path: str | Path) -> Inventory:
    inventory_path = Path(path)
    if not inventory_path.exists():
        raise InventoryError(f"Inventory file does not exist: {inventory_path}")

    if inventory_path.suffix.lower() in {".yml", ".yaml"}:
        return _load_yaml_inventory(inventory_path)
    return _load_ini_inventory(inventory_path)


def _load_ini_inventory(path: Path) -> Inventory:
    hosts: dict[str, dict[str, Any]] = {}
    group_vars: dict[str, dict[str, Any]] = defaultdict(dict)
    host_groups: dict[str, set[str]] = defaultdict(set)
    group_children: dict[str, set[str]] = defaultdict(set)
    current_group = "ungrouped"
    mode = "hosts"

    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("[") and line.endswith("]"):
            header = line[1:-1].strip()
            if header.endswith(":vars"):
                current_group = header.removesuffix(":vars")
                mode = "vars"
                group_vars.setdefault(current_group, {})
            elif header.endswith(":children"):
                current_group = header.removesuffix(":children")
                mode = "children"
                group_vars.setdefault(current_group, {})
            else:
                current_group = header
                mode = "hosts"
            continue

        if mode == "vars":
            parts = _split_ini_words(line, line_no)
            if not parts:
                continue
            key, value = _parse_ini_key_value(parts[0], line_no)
            group_vars[current_group][key] = value
            continue

        if mode == "children":
            parts = _split_ini_words(line, line_no)
            if not parts:
                continue
            group_vars.setdefault(current_group, {})
            group_vars.setdefault(parts[0], {})
            group_children[current_group].add(parts[0])
            continue

        host_name, values = _parse_ini_host_line(line, line_no)
        hosts.setdefault(host_name, {}).update(values)
        host_groups[host_name].add(current_group)

    if not hosts:
        raise InventoryError(f"Inventory contains no hosts: {path}")
    _propagate_ini_group_membership(host_groups, group_children, "all" in group_vars)
    return Inventory(hosts=hosts, group_vars=dict(group_vars), host_groups=host_groups)


def _load_yaml_inventory(path: Path) -> Inventory:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise InventoryError("YAML inventory must be a mapping.")

    hosts: dict[str, dict[str, Any]] = {}
    group_vars: dict[str, dict[str, Any]] = defaultdict(dict)
    host_groups: dict[str, set[str]] = defaultdict(set)

    root = raw.get("all", raw)
    _walk_yaml_group("all", root, hosts, group_vars, host_groups, (), {})

    if not hosts:
        raise InventoryError(f"Inventory contains no hosts: {path}")
    return Inventory(hosts=hosts, group_vars=dict(group_vars), host_groups=host_groups)


def _walk_yaml_group(
    group: str,
    node: Any,
    hosts: dict[str, dict[str, Any]],
    group_vars: dict[str, dict[str, Any]],
    host_groups: dict[str, set[str]],
    inherited_groups: tuple[str, ...],
    inherited_vars: dict[str, Any],
) -> None:
    if node is None:
        return
    if not isinstance(node, dict):
        raise InventoryError(f"Inventory group '{group}' must be a mapping.")

    vars_node = node.get("vars", {})
    if vars_node:
        if not isinstance(vars_node, dict):
            raise InventoryError(f"Inventory vars for group '{group}' must be a mapping.")
        group_vars[group].update(vars_node)
    current_vars = {**inherited_vars, **dict(vars_node or {})}
    current_groups = (*inherited_groups, group)

    hosts_node = node.get("hosts", {})
    if hosts_node:
        if not isinstance(hosts_node, dict):
            raise InventoryError(f"Inventory hosts for group '{group}' must be a mapping.")
        for host_name, host_vars in hosts_node.items():
            values = host_vars or {}
            if not isinstance(values, dict):
                raise InventoryError(f"Host vars for '{host_name}' must be a mapping.")
            hosts.setdefault(str(host_name), {}).update({**current_vars, **values})
            host_groups[str(host_name)].update(current_groups)

    children = node.get("children", {})
    if children:
        if not isinstance(children, dict):
            raise InventoryError(f"Children for group '{group}' must be a mapping.")
        for child_name, child_node in children.items():
            _walk_yaml_group(
                str(child_name),
                child_node,
                hosts,
                group_vars,
                host_groups,
                current_groups,
                current_vars,
            )


def _parse_ini_host_line(line: str, line_no: int) -> tuple[str, dict[str, Any]]:
    parts = _split_ini_words(line, line_no)
    if not parts:
        raise InventoryError(f"Invalid empty host line at {line_no}.")
    host = parts[0]
    values: dict[str, Any] = {}
    for token in parts[1:]:
        key, value = _parse_ini_key_value(token, line_no)
        values[key] = value
    return host, values


def _split_ini_words(line: str, line_no: int) -> list[str]:
    try:
        return shlex.split(line, comments=True, posix=True)
    except ValueError as exc:
        raise InventoryError(f"Invalid inventory syntax at line {line_no}: {exc}") from exc


def _propagate_ini_group_membership(
    host_groups: dict[str, set[str]],
    group_children: dict[str, set[str]],
    include_all: bool,
) -> None:
    changed = True
    while changed:
        changed = False
        for host, groups in host_groups.items():
            inherited = set(groups)
            for parent, children in group_children.items():
                if groups.intersection(children):
                    inherited.add(parent)
            if include_all:
                inherited.add("all")
            if inherited != groups:
                host_groups[host] = inherited
                changed = True


def _parse_ini_key_value(token: str, line_no: int) -> tuple[str, str]:
    if "=" not in token:
        raise InventoryError(f"Expected key=value at line {line_no}: {token}")
    key, value = token.split("=", 1)
    if not key:
        raise InventoryError(f"Expected key at line {line_no}: {token}")
    return key, value


def _resolve_env_values(values: dict[str, Any]) -> dict[str, Any]:
    return {key: _resolve_env_value(value) for key, value in values.items()}


def _resolve_env_value(value: Any) -> Any:
    if isinstance(value, str):

        def replace(match: re.Match[str]) -> str:
            env_name = match.group(1)
            if env_name not in os.environ:
                raise InventoryError(f"Missing required environment variable: {env_name}")
            return os.environ[env_name]

        return ENV_PATTERN.sub(replace, value)
    return value


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _default_device_key_file() -> str:
    return os.path.expanduser(os.getenv("CISCO_MCP_DEFAULT_KEY_FILE", DEFAULT_DEVICE_KEY_FILE))


def _default_device_user() -> str:
    return os.getenv("CISCO_MCP_DEFAULT_USER", DEFAULT_DEVICE_USER)


def _device_type_from_vars(values: dict[str, Any]) -> str:
    explicit = values.get("netmiko_device_type") or values.get("device_type")
    if explicit:
        return str(explicit)

    network_os = str(values.get("ansible_network_os", "ios")).lower()
    if "nxos" in network_os:
        return "cisco_nxos"
    return "cisco_ios"
