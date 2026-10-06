"""Command input validation.

The server intentionally permits arbitrary Cisco CLI content at the semantic
level. Validation here is only about making command transport predictable:
single-line strings for one command and bounded ordered lists for batches.
"""

from __future__ import annotations

from cisco_mcp_server.exceptions import CommandValidationError

MAX_COMMAND_LENGTH = 4096
MAX_BATCH_COMMANDS = 100


def validate_command(command: str) -> str:
    if not isinstance(command, str):
        raise CommandValidationError("Command must be a string.")

    for char in command:
        codepoint = ord(char)
        if codepoint < 32 or codepoint == 127:
            raise CommandValidationError("Command contains control characters or newlines.")

    cleaned = command.strip()
    if not cleaned:
        raise CommandValidationError("Command must not be empty.")
    if len(cleaned) > MAX_COMMAND_LENGTH:
        raise CommandValidationError(f"Command exceeds {MAX_COMMAND_LENGTH} characters.")

    return cleaned


def validate_batch(commands: list[str]) -> tuple[str, ...]:
    if not isinstance(commands, list):
        raise CommandValidationError("Commands must be provided as a list.")
    if not commands:
        raise CommandValidationError("Command batch must not be empty.")
    if len(commands) > MAX_BATCH_COMMANDS:
        raise CommandValidationError(f"Command batch exceeds {MAX_BATCH_COMMANDS} commands.")

    return tuple(validate_command(command) for command in commands)


def validate_mode(mode: str) -> str:
    if mode not in {"exec", "config"}:
        raise CommandValidationError("Mode must be either 'exec' or 'config'.")
    return mode
