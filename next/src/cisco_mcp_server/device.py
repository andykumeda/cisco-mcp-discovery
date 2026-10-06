"""Cisco device command execution through Netmiko."""

from __future__ import annotations

import os

from collections.abc import Callable
from typing import Any

from cisco_mcp_server.command import validate_batch, validate_command, validate_mode
from cisco_mcp_server.exceptions import DeviceConnectionError, InventoryError
from cisco_mcp_server.inventory import Inventory
from cisco_mcp_server.models import BatchResult, CommandResult, DeviceTarget
from cisco_mcp_server.storage import AuditLog, TrustedTargetStore

ConnectionFactory = Callable[..., Any]


class DeviceClient:
    def __init__(
        self,
        *,
        inventory: Inventory,
        trusted_targets: TrustedTargetStore | None = None,
        audit_log: AuditLog | None = None,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        self.inventory = inventory
        self.trusted_targets = trusted_targets
        self.audit_log = audit_log
        self.connection_factory = connection_factory

    def resolve_target(self, host: str) -> DeviceTarget:
        try:
            target = self.inventory.resolve(host)
        except InventoryError:
            if self.trusted_targets is None:
                raise
            return self.trusted_targets.resolve(host, self.inventory)
        if target.vars.get("cisco_mcp_discovered_from_seed"):
            if self.trusted_targets is None:
                raise InventoryError("Persisted discovery requires its trusted credential provenance.")
            return self.trusted_targets.resolve(target.address, self.inventory)
        return target

    def run_command(self, host: str, command: str, timeout_seconds: int = 60) -> BatchResult:
        return self.run_batch(host, [command], mode="exec", timeout_seconds=timeout_seconds)

    def run_batch(
        self,
        host: str,
        commands: list[str],
        *,
        mode: str = "exec",
        timeout_seconds: int = 60,
    ) -> BatchResult:
        target = self.resolve_target(host)
        return self.run_commands_for_target(
            target,
            commands,
            mode=mode,
            timeout_seconds=timeout_seconds,
        )

    def run_commands_for_target(
        self,
        target: DeviceTarget,
        commands: list[str] | tuple[str, ...],
        *,
        mode: str = "exec",
        timeout_seconds: int = 60,
    ) -> BatchResult:
        clean_commands = validate_batch(list(commands))
        clean_mode = validate_mode(mode)
        connection = None
        results: list[CommandResult] = []
        try:
            connection = self._connect(target, timeout_seconds)
            if clean_mode == "config":
                self._enter_config_mode(connection)
            for command in clean_commands:
                output = self._send_command(connection, command, timeout_seconds)
                results.append(CommandResult(command=command, output=output))
        except Exception as exc:
            if not results:
                results.append(
                    CommandResult(
                        command="; ".join(clean_commands),
                        output="",
                        success=False,
                        error=str(exc),
                    )
                )
            else:
                results.append(
                    CommandResult(command="<session>", output="", success=False, error=str(exc))
                )
        finally:
            if connection is not None:
                if clean_mode == "config":
                    self._exit_config_mode(connection)
                self._disconnect(connection)

        batch = BatchResult(
            host=target.name,
            address=target.address,
            mode=clean_mode,
            results=tuple(results),
        )
        self._audit(target, batch)
        return batch

    def _connect(self, target: DeviceTarget, timeout_seconds: int) -> Any:
        try:
            return self._connect_direct(target, timeout_seconds)
        except Exception as direct_exc:
            if not target.reachable_via or self.trusted_targets is None:
                raise
            try:
                return self._connect_via_upstream(target, timeout_seconds)
            except Exception as proxy_exc:
                raise DeviceConnectionError(
                    f"Failed to connect to {target.name} ({target.address}) directly "
                    f"or via trusted upstream {target.reachable_via}. Direct error: "
                    f"{direct_exc}. Upstream proxy error: {proxy_exc}"
                ) from proxy_exc

    def _connect_direct(self, target: DeviceTarget, timeout_seconds: int) -> Any:
        factory = self.connection_factory or self._default_connection_factory()
        params = self._connection_params(target, timeout_seconds)
        try:
            return factory(**params)
        except Exception as exc:
            raise DeviceConnectionError(
                f"Failed to connect to {target.name} ({target.address}): {exc}"
            ) from exc

    def _connect_via_upstream(self, target: DeviceTarget, timeout_seconds: int) -> Any:
        if not target.reachable_via:
            raise DeviceConnectionError("Target has no trusted upstream for proxy connection.")
        upstream = self.resolve_target(target.reachable_via)
        if upstream.address == target.address:
            raise DeviceConnectionError("Trusted upstream resolves to the target itself.")

        upstream_connection = self._connect(upstream, timeout_seconds)
        try:
            transport = _paramiko_transport_from_connection(upstream_connection)
            channel = transport.open_channel(
                "direct-tcpip",
                (target.address, target.port),
                ("127.0.0.1", 0),
            )
            factory = self.connection_factory or self._default_connection_factory()
            params = self._connection_params(target, timeout_seconds)
            params["sock"] = channel
            target_connection = factory(**params)
            return ProxiedConnection(target_connection, upstream_connection)
        except Exception:
            self._disconnect(upstream_connection)
            raise

    @staticmethod
    def _connection_params(target: DeviceTarget, timeout_seconds: int) -> dict[str, Any]:
        params: dict[str, Any] = {
            "device_type": target.device_type,
            "host": target.address,
            "port": target.port,
            "timeout": timeout_seconds,
            "conn_timeout": timeout_seconds,
            "banner_timeout": timeout_seconds,
            "auth_timeout": timeout_seconds,
            "fast_cli": False,
        }
        if target.username:
            params["username"] = target.username
        if target.password:
            params["password"] = target.password
        if target.key_file:
            params["key_file"] = target.key_file
            params["use_keys"] = True
        return params

    @staticmethod
    def _default_connection_factory() -> ConnectionFactory:
        if os.getenv("CISCO_MCP_ENABLE_SSH") != "1":
            raise DeviceConnectionError("Live SSH is disabled; enable only for an explicitly authorized lab.")
        try:
            from netmiko import ConnectHandler
        except ImportError as exc:
            raise DeviceConnectionError("Netmiko is not installed in this environment.") from exc
        return ConnectHandler

    @staticmethod
    def _send_command(connection: Any, command: str, timeout_seconds: int) -> str:
        try:
            return str(
                connection.send_command_timing(
                    command,
                    strip_prompt=False,
                    strip_command=False,
                    read_timeout=timeout_seconds,
                )
            )
        except TypeError:
            return str(
                connection.send_command_timing(command, strip_prompt=False, strip_command=False)
            )

    @staticmethod
    def _enter_config_mode(connection: Any) -> None:
        if hasattr(connection, "config_mode"):
            connection.config_mode()

    @staticmethod
    def _exit_config_mode(connection: Any) -> None:
        if hasattr(connection, "exit_config_mode"):
            connection.exit_config_mode()

    @staticmethod
    def _disconnect(connection: Any) -> None:
        if hasattr(connection, "disconnect"):
            connection.disconnect()

    def _audit(self, target: DeviceTarget, batch: BatchResult) -> None:
        if self.audit_log is None:
            return
        self.audit_log.append(
            {
                "event": "command_batch",
                "target": target.public_dict(),
                "mode": batch.mode,
                "commands": [item.command for item in batch.results if item.command != "<session>"],
                "success": batch.success,
                "errors": [item.error for item in batch.results if item.error],
            }
        )


class ProxiedConnection:
    def __init__(self, target_connection: Any, upstream_connection: Any) -> None:
        self.target_connection = target_connection
        self.upstream_connection = upstream_connection

    def __getattr__(self, name: str) -> Any:
        return getattr(self.target_connection, name)

    def disconnect(self) -> None:
        DeviceClient._disconnect(self.target_connection)
        DeviceClient._disconnect(self.upstream_connection)


def _paramiko_transport_from_connection(connection: Any) -> Any:
    for attr_name in ("remote_conn_pre", "ssh_ctl_chan"):
        ssh_client = getattr(connection, attr_name, None)
        if ssh_client is not None and hasattr(ssh_client, "get_transport"):
            transport = ssh_client.get_transport()
            if transport is not None:
                return transport

    transport = getattr(connection, "transport", None)
    if transport is not None and hasattr(transport, "open_channel"):
        return transport

    raise DeviceConnectionError(
        "Trusted upstream connection does not expose an SSH transport for proxy forwarding."
    )


def validate_single_command_for_transport(command: str) -> str:
    return validate_command(command)
