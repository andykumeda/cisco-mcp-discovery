from __future__ import annotations

import pytest

from cisco_mcp_server.exceptions import InventoryError
from cisco_mcp_server.inventory import load_inventory


def test_ini_inventory_resolves_explicit_password_env_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("CISCO_MCP_DEVICE_PASSWORD", "super-secret")
    inventory_path = tmp_path / "inventory.ini"
    inventory_path.write_text(
        """
[iosxe]
edge-1 ansible_host=192.0.2.10 ansible_port=2222

[iosxe:vars]
ansible_user=netops
ansible_password=${CISCO_MCP_DEVICE_PASSWORD}
ansible_network_os=ios
""",
        encoding="utf-8",
    )

    inventory = load_inventory(inventory_path)
    target = inventory.resolve("edge-1")

    assert target.name == "edge-1"
    assert target.address == "192.0.2.10"
    assert target.port == 2222
    assert target.username == "netops"
    assert target.password == "super-secret"
    assert target.key_file is None
    assert target.device_type == "cisco_ios"
    assert "iosxe" in target.groups
    assert target.public_dict()["password"] == "<redacted>"


def test_ini_inventory_applies_all_vars_children_and_default_key(tmp_path, monkeypatch):
    key_path = tmp_path / "lab-reader_id_rsa"
    monkeypatch.setenv("CISCO_MCP_DEFAULT_KEY_FILE", str(key_path))
    monkeypatch.setenv("CISCO_MCP_DEFAULT_USER", "lab-reader")
    inventory_path = tmp_path / "inventory.ini"
    inventory_path.write_text(
        """
[all:vars]

[campus:children]
iosxe

[campus:vars]
ansible_network_os=ios

[iosxe]
edge-1 ansible_host=192.0.2.10
""",
        encoding="utf-8",
    )

    inventory = load_inventory(inventory_path)
    target = inventory.resolve("edge-1")

    assert target.username == "lab-reader"
    assert target.password is None
    assert target.key_file == str(key_path)
    assert target.public_dict()["key_file"] == "<redacted>"
    assert set(target.groups) == {"all", "campus", "iosxe"}


def test_ini_inventory_ignores_inline_comments_and_children_comments(tmp_path):
    inventory_path = tmp_path / "inventory.ini"
    inventory_path.write_text(
        """
# Production-style inventory with comments next to device addresses.
[lab-group-2]
203.0.113.1  # Server Switch

[lab-parent:children]
lab-group-2  # include lab devices
""",
        encoding="utf-8",
    )

    inventory = load_inventory(inventory_path)
    target = inventory.resolve("203.0.113.1")

    assert target.name == "203.0.113.1"
    assert target.address == "203.0.113.1"
    assert set(target.groups) == {"lab-parent", "lab-group-2"}


def test_yaml_inventory_resolves_parent_child_group_vars_and_key_file(tmp_path):
    inventory_path = tmp_path / "inventory.yml"
    inventory_path.write_text(
        """
all:
  vars:
    ansible_user: netops
    ansible_ssh_private_key_file: ~/.ssh/cisco_mcp_id_ed25519
  children:
    campus:
      vars:
        ansible_network_os: ios
      hosts:
        dist-1:
          ansible_host: 192.0.2.20
""",
        encoding="utf-8",
    )

    inventory = load_inventory(inventory_path)
    target = inventory.resolve("192.0.2.20")

    assert target.name == "dist-1"
    assert target.username == "netops"
    assert target.password is None
    assert target.key_file == "~/.ssh/cisco_mcp_id_ed25519"
    assert set(target.groups) == {"all", "campus"}


def test_inventory_missing_env_var_fails_when_resolved(tmp_path):
    inventory_path = tmp_path / "inventory.ini"
    inventory_path.write_text(
        """
[iosxe]
edge-1 ansible_host=192.0.2.10 ansible_password=${MISSING_PASSWORD}
""",
        encoding="utf-8",
    )

    inventory = load_inventory(inventory_path)
    with pytest.raises(InventoryError, match="MISSING_PASSWORD"):
        inventory.resolve("edge-1")


def test_inventory_requires_hosts(tmp_path):
    inventory_path = tmp_path / "inventory.ini"
    inventory_path.write_text("[iosxe:vars]\nansible_user=netops\n", encoding="utf-8")

    with pytest.raises(InventoryError, match="contains no hosts"):
        load_inventory(inventory_path)
