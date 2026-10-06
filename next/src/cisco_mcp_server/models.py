"""Core data models used across the server."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SENSITIVE_KEYS = {
    "ansible_password",
    "ansible_ssh_pass",
    "password",
    "secret",
    "enable_secret",
    "ansible_become_password",
    "ansible_ssh_private_key_file",
    "private_key_file",
    "key_file",
}


@dataclass(frozen=True)
class DeviceTarget:
    name: str
    address: str
    username: str | None = None
    password: str | None = None
    key_file: str | None = None
    port: int = 22
    device_type: str = "cisco_ios"
    groups: tuple[str, ...] = ()
    vars: dict[str, Any] = field(default_factory=dict)
    source: str = "inventory"
    credential_source: str | None = None
    reachable_via: str | None = None

    def public_dict(self) -> dict[str, Any]:
        data = {
            "name": self.name,
            "address": self.address,
            "port": self.port,
            "device_type": self.device_type,
            "groups": list(self.groups),
            "source": self.source,
            "credential_source": self.credential_source,
            "reachable_via": self.reachable_via,
            "vars": {
                key: ("<redacted>" if key in SENSITIVE_KEYS else value)
                for key, value in self.vars.items()
            },
        }
        if self.username:
            data["username"] = self.username
        if self.password:
            data["password"] = "<redacted>"
        if self.key_file:
            data["key_file"] = "<redacted>"
        return data


@dataclass(frozen=True)
class CommandResult:
    command: str
    output: str
    success: bool = True
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "success": self.success,
            "output": self.output,
            "error": self.error,
        }


@dataclass(frozen=True)
class BatchResult:
    host: str
    address: str
    mode: str
    results: tuple[CommandResult, ...]

    @property
    def success(self) -> bool:
        return all(item.success for item in self.results)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "address": self.address,
            "mode": self.mode,
            "success": self.success,
            "results": [item.to_dict() for item in self.results],
        }
