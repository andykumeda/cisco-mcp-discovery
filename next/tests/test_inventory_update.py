from __future__ import annotations

from cisco_mcp_server.inventory import load_inventory
from cisco_mcp_server.inventory_update import InventoryUpdater


def test_yaml_inventory_updater_adds_discovered_host_with_comment(tmp_path):
    inventory_path = tmp_path / "inventory.yml"
    inventory_path.write_text(
        """
all:
  vars:
    ansible_user: lab-reader
    ansible_ssh_private_key_file: ~/.ssh/cisco_mcp_id_ed25519
    ansible_network_os: ios
  children:
    campus:
      hosts:
        lab-seed:
          ansible_host: 192.0.2.10
""",
        encoding="utf-8",
    )

    changed = InventoryUpdater(inventory_path).add_discovered_host(
        name="dist-1.example.test",
        address="192.0.2.20",
        seed_name="lab-seed",
        seed_address="192.0.2.10",
        discovered_from="lab-seed",
        protocol="cdp",
    )

    text = inventory_path.read_text(encoding="utf-8")
    inventory = load_inventory(inventory_path)

    assert changed is True
    assert "# added from seed 192.0.2.10 (lab-seed)" in text
    assert "dist-1.example.test:" in text
    assert "cisco_mcp_discovered_from_seed: 192.0.2.10" in text
    assert inventory.resolve("192.0.2.20").address == "192.0.2.20"


def test_yaml_inventory_updater_skips_existing_address(tmp_path):
    inventory_path = tmp_path / "inventory.yml"
    inventory_path.write_text(
        """
all:
  children:
    campus:
      hosts:
        lab-seed:
          ansible_host: 192.0.2.10
""",
        encoding="utf-8",
    )

    changed = InventoryUpdater(inventory_path).add_discovered_host(
        name="lab-seed",
        address="192.0.2.10",
        seed_name="lab-seed",
        seed_address="192.0.2.10",
        discovered_from="lab-seed",
        protocol="cdp",
    )

    assert changed is False


def test_ini_inventory_updater_adds_discovered_host_with_comment(tmp_path):
    inventory_path = tmp_path / "inventory.ini"
    inventory_path.write_text(
        """
[all:vars]
ansible_user=lab-reader

[campus]
lab-seed ansible_host=192.0.2.10
""",
        encoding="utf-8",
    )

    changed = InventoryUpdater(inventory_path).add_discovered_host(
        name="dist-1",
        address="192.0.2.20",
        seed_name="lab-seed",
        seed_address="192.0.2.10",
        discovered_from="lab-seed",
        protocol="lldp",
    )

    text = inventory_path.read_text(encoding="utf-8")

    assert changed is True
    assert "[discovered]" in text
    assert "# added from seed 192.0.2.10 (lab-seed)" in text
    assert "dist-1 ansible_host=192.0.2.20" in text
