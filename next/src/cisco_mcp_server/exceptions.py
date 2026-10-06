"""Domain exceptions for Cisco MCP Server."""


class CiscoMCPError(Exception):
    """Base exception for expected application errors."""


class InventoryError(CiscoMCPError):
    """Raised when inventory loading or resolution fails."""


class CommandValidationError(CiscoMCPError):
    """Raised when command input is not safe to transport."""


class DeviceConnectionError(CiscoMCPError):
    """Raised when a device session cannot be established or used."""


class ArtifactError(CiscoMCPError):
    """Raised when stored artifacts cannot be found or read."""
