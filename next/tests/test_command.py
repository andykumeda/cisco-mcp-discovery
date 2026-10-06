from __future__ import annotations

import pytest

from cisco_mcp_server.command import validate_batch, validate_command, validate_mode
from cisco_mcp_server.exceptions import CommandValidationError


def test_arbitrary_config_command_is_allowed():
    assert validate_command("interface Loopback100") == "interface Loopback100"
    assert validate_command("no shutdown") == "no shutdown"


def test_command_rejects_newline_and_control_characters():
    with pytest.raises(CommandValidationError):
        validate_command("show version\nreload")
    with pytest.raises(CommandValidationError):
        validate_command("show version\t")
    with pytest.raises(CommandValidationError):
        validate_command("\x1b[31mshow version")


def test_batch_validation():
    assert validate_batch(["configure terminal", "hostname demo"]) == (
        "configure terminal",
        "hostname demo",
    )
    with pytest.raises(CommandValidationError):
        validate_batch([])


def test_mode_validation():
    assert validate_mode("exec") == "exec"
    assert validate_mode("config") == "config"
    with pytest.raises(CommandValidationError):
        validate_mode("enable")
