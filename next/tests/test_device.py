from __future__ import annotations

from cisco_mcp_server.device import DeviceClient
from cisco_mcp_server.inventory import load_inventory


class FakeConnection:
    def __init__(self, **params):
        self.params = params
        self.commands: list[str] = []
        self.config_entered = False
        self.disconnected = False

    def send_command_timing(self, command, **_kwargs):
        self.commands.append(command)
        return f"output for {command}"

    def config_mode(self):
        self.config_entered = True

    def exit_config_mode(self):
        self.config_entered = False

    def disconnect(self):
        self.disconnected = True


class FakeTransport:
    def __init__(self):
        self.channels: list[tuple[str, tuple[str, int], tuple[str, int]]] = []

    def open_channel(self, kind, destination, source):
        self.channels.append((kind, destination, source))
        return object()


class FakeSSHClient:
    def __init__(self, transport):
        self.transport = transport

    def get_transport(self):
        return self.transport


class FakeJumpConnection(FakeConnection):
    def __init__(self, **params):
        super().__init__(**params)
        self.transport = FakeTransport()
        self.remote_conn_pre = FakeSSHClient(self.transport)


def test_device_client_runs_exec_batch(tmp_path):
    inventory_path = tmp_path / "inventory.ini"
    inventory_path.write_text(
        "[iosxe]\nedge-1 ansible_host=192.0.2.10 ansible_user=netops\n",
        encoding="utf-8",
    )
    inventory = load_inventory(inventory_path)
    created: list[FakeConnection] = []

    def factory(**params):
        conn = FakeConnection(**params)
        created.append(conn)
        return conn

    client = DeviceClient(inventory=inventory, connection_factory=factory)
    result = client.run_batch("edge-1", ["show version", "show ip interface brief"])

    assert result.success
    assert result.address == "192.0.2.10"
    assert [item.command for item in result.results] == ["show version", "show ip interface brief"]
    assert created[0].params["host"] == "192.0.2.10"
    assert created[0].disconnected


def test_device_client_runs_config_batch(tmp_path):
    inventory_path = tmp_path / "inventory.ini"
    inventory_path.write_text("[iosxe]\nedge-1 ansible_host=192.0.2.10\n", encoding="utf-8")
    inventory = load_inventory(inventory_path)
    created: list[FakeConnection] = []

    def factory(**params):
        conn = FakeConnection(**params)
        created.append(conn)
        return conn

    client = DeviceClient(inventory=inventory, connection_factory=factory)
    result = client.run_batch("edge-1", ["interface Loopback100", "description MCP"], mode="config")

    assert result.success
    assert [item.output for item in result.results] == [
        "output for interface Loopback100",
        "output for description MCP",
    ]
    assert created[0].disconnected


def test_device_client_records_connection_failure(tmp_path):
    inventory_path = tmp_path / "inventory.ini"
    inventory_path.write_text("[iosxe]\nedge-1 ansible_host=192.0.2.10\n", encoding="utf-8")
    inventory = load_inventory(inventory_path)

    def factory(**_params):
        raise RuntimeError("auth failed")

    client = DeviceClient(inventory=inventory, connection_factory=factory)
    result = client.run_command("edge-1", "show version")

    assert not result.success
    assert "auth failed" in (result.results[0].error or "")


def test_device_client_can_proxy_to_trusted_discovered_target(tmp_path):
    inventory_path = tmp_path / "inventory.ini"
    inventory_path.write_text(
        "[iosxe]\nseed ansible_host=192.0.2.10 ansible_user=netops\n",
        encoding="utf-8",
    )
    inventory = load_inventory(inventory_path)

    from cisco_mcp_server.storage import TrustedTargetStore

    trusted = TrustedTargetStore(tmp_path)
    trusted.add(
        name="downstream",
        address="192.0.2.20",
        credential_source="seed",
        discovered_from="seed",
        protocol="cdp",
    )
    created: list[FakeConnection] = []

    def factory(**params):
        if params["host"] == "192.0.2.20" and "sock" not in params:
            raise RuntimeError("no route to host")
        if params["host"] == "192.0.2.10":
            conn = FakeJumpConnection(**params)
        else:
            conn = FakeConnection(**params)
        created.append(conn)
        return conn

    client = DeviceClient(
        inventory=inventory,
        trusted_targets=trusted,
        connection_factory=factory,
    )

    result = client.run_command("downstream", "show version")

    assert result.success
    assert result.address == "192.0.2.20"
    assert [conn.params["host"] for conn in created] == ["192.0.2.10", "192.0.2.20"]
    assert "sock" in created[-1].params
    assert created[0].disconnected
    assert created[-1].disconnected


def test_public_default_connection_factory_requires_explicit_opt_in(monkeypatch):
    import pytest
    from cisco_mcp_server.exceptions import DeviceConnectionError
    monkeypatch.delenv('CISCO_MCP_ENABLE_SSH', raising=False)
    with pytest.raises(DeviceConnectionError, match='Live SSH is disabled'):
        DeviceClient._default_connection_factory()


def test_persisted_discovery_keeps_seed_credentials_after_reload(tmp_path):
    from cisco_mcp_server.inventory_update import InventoryUpdater
    from cisco_mcp_server.storage import TrustedTargetStore
    for suffix in ['ini', 'yml']:
        path = tmp_path / ('inventory.' + suffix)
        if suffix == 'ini':
            path.write_text('[iosxe]\nseed ansible_host=192.0.2.10 ansible_user=fixture-user ansible_password=fixture-secret ansible_port=2222\n')
        else:
            path.write_text('all:\n  hosts:\n    seed:\n      ansible_host: 192.0.2.10\n      ansible_user: fixture-user\n      ansible_password: fixture-secret\n      ansible_port: 2222\n')
        store = TrustedTargetStore(tmp_path / suffix)
        store.add(name='neighbor', address='192.0.2.20', credential_source='seed', discovered_from='seed', protocol='cdp')
        InventoryUpdater(path).add_discovered_host(name='neighbor', address='192.0.2.20', seed_name='seed', seed_address='192.0.2.10', discovered_from='seed', protocol='cdp')
        client = DeviceClient(inventory=load_inventory(path), trusted_targets=store)
        for host in ['neighbor', '192.0.2.20']:
            target = client.resolve_target(host)
            assert (target.username, target.password, target.port) == ('fixture-user', 'fixture-secret', 2222)
            assert target.credential_source == 'seed'
        assert client.resolve_target('seed').source == 'inventory'
        assert 'fixture-secret' not in path.read_text().split('neighbor')[-1]
