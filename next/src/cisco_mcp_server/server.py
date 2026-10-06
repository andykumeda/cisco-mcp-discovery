"""MCP stdio server surface."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.types import (
    GetPromptResult,
    Prompt,
    PromptArgument,
    PromptMessage,
    Resource,
    TextContent,
    Tool,
)

from cisco_mcp_server.connected_devices import ConnectedDeviceAuditor
from cisco_mcp_server.device import DeviceClient
from cisco_mcp_server.discovery import DiscoveryEngine
from cisco_mcp_server.drawio import generate_drawio_xml
from cisco_mcp_server.exceptions import CiscoMCPError
from cisco_mcp_server.inventory import load_inventory
from cisco_mcp_server.inventory_update import InventoryUpdater
from cisco_mcp_server.network_investigation import investigate_network_question
from cisco_mcp_server.reporting import generate_markdown_report
from cisco_mcp_server.settings import Settings
from cisco_mcp_server.storage import ArtifactStore, AuditLog, TrustedTargetStore

logger = logging.getLogger(__name__)


class CiscoMCPServer:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings.from_env()
        self.app = Server("cisco-mcp-server")
        self.app.list_resources()(self.list_resources)  # type: ignore[no-untyped-call]
        self.app.read_resource()(self.read_resource)  # type: ignore[no-untyped-call]
        self.app.list_prompts()(self.list_prompts)  # type: ignore[no-untyped-call]
        self.app.get_prompt()(self.get_prompt)  # type: ignore[no-untyped-call]
        self.app.list_tools()(self.list_tools)  # type: ignore[no-untyped-call]
        self.app.call_tool()(self.call_tool)

    async def list_resources(self) -> list[Resource]:
        return [
            Resource(
                uri="cisco://discovery-runs",  # type: ignore[arg-type]
                name="Discovery Runs",
                description="Stored discovery run metadata",
                mimeType="application/json",
            ),
            Resource(
                uri="cisco://trusted-targets",  # type: ignore[arg-type]
                name="Trusted Discovered Targets",
                description="Targets learned from CDP/LLDP discovery",
                mimeType="application/json",
            ),
            Resource(
                uri="cisco://investigation-standards",  # type: ignore[arg-type]
                name="Senior Network Investigation Standards",
                description=(
                    "Minimum evidence and answer discipline for network investigations."
                ),
                mimeType="text/markdown",
            ),
        ]

    async def read_resource(self, uri: str) -> list[ReadResourceContents]:
        uri = str(uri)
        context = self._context()
        if uri == "cisco://discovery-runs":
            return [ReadResourceContents(content=json.dumps(context["artifacts"].list_runs(), indent=2), mime_type="application/json")]
        if uri == "cisco://trusted-targets":
            return [ReadResourceContents(content=json.dumps(context["trusted_targets"].public_records(), indent=2), mime_type="application/json")]
        if uri == "cisco://investigation-standards":
            return [ReadResourceContents(content=INVESTIGATION_STANDARDS, mime_type="text/markdown")]
        raise ValueError(f"Unknown resource: {uri}")

    async def list_prompts(self) -> list[Prompt]:
        return [
            Prompt(
                name="senior_network_investigation",
                description=(
                    "Use before answering network state questions. Requires separating "
                    "observed facts, inference, confidence, and limitations."
                ),
                arguments=[
                    PromptArgument(
                        name="question",
                        description="The user's network question to investigate.",
                        required=True,
                    ),
                    PromptArgument(
                        name="host",
                        description="Inventory host, IP address, or trusted discovered target.",
                        required=False,
                    ),
                ],
            )
        ]

    async def get_prompt(
        self,
        name: str,
        arguments: dict[str, str] | None = None,
    ) -> GetPromptResult:
        if name != "senior_network_investigation":
            raise ValueError(f"Unknown prompt: {name}")
        args = arguments or {}
        question = args.get("question", "<question>")
        host = args.get("host", "<host>")
        return GetPromptResult(
            description="Senior network investigation operating procedure.",
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text=(
                            f"Investigate this network question as a senior network engineer: "
                            f"{question}\nTarget: {host}\n\n{INVESTIGATION_STANDARDS}"
                        ),
                    ),
                )
            ],
        )

    async def list_tools(self) -> list[Tool]:
        return [
            Tool(
                name="list_inventory_hosts",
                description="List normalized public inventory hosts. Secrets are redacted.",
                inputSchema={
                    "type": "object",
                    "properties": {"group": {"type": "string"}},
                },
            ),
            Tool(
                name="execute_command",
                description=(
                    "Run one arbitrary single-line Cisco CLI command on an inventory "
                    "or trusted discovered target. Use high-level investigation tools "
                    "instead of a single command when answering state, topology, "
                    "reachability, or exclusivity questions."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "command": {"type": "string"},
                        "timeout_seconds": {
                            "type": "integer",
                            "default": self.settings.default_timeout_seconds,
                        },
                    },
                    "required": ["host", "command"],
                },
            ),
            Tool(
                name="execute_command_batch",
                description=(
                    "Run ordered Cisco CLI commands in one session. "
                    "Mode may be exec or config."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "commands": {"type": "array", "items": {"type": "string"}},
                        "mode": {"type": "string", "enum": ["exec", "config"], "default": "exec"},
                        "timeout_seconds": {
                            "type": "integer",
                            "default": self.settings.default_timeout_seconds,
                        },
                    },
                    "required": ["host", "commands"],
                },
            ),
            Tool(
                name="run_discovery",
                description=(
                    "Run CDP/LLDP depth-limited Cisco discovery and store JSON, "
                    "Markdown, and Draw.io artifacts. This is neighbor-protocol "
                    "topology discovery, not proof that no other physical or "
                    "MAC-learning devices are connected. Full discovery walks "
                    "multiple hops through discovered neighbors and returns tables "
                    "for network devices, connected interfaces, and learned endpoints."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "seed_hosts": {"type": "array", "items": {"type": "string"}},
                        "depth": {"type": "integer", "default": 2},
                        "full_discovery": {"type": "boolean", "default": True},
                        "max_devices": {"type": "integer", "default": 100},
                        "timeout_seconds": {
                            "type": "integer",
                            "default": self.settings.default_timeout_seconds,
                        },
                    },
                    "required": ["seed_hosts"],
                },
            ),
            Tool(
                name="investigate_network_question",
                description=(
                    "Question-driven senior network investigation. Use this for broad "
                    "network questions instead of guessing a single show command. It "
                    "classifies the question, runs the relevant evidence set, and "
                    "returns command evidence, confidence, gaps, and answer requirements."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "question": {"type": "string"},
                        "timeout_seconds": {
                            "type": "integer",
                            "default": self.settings.default_timeout_seconds,
                        },
                        "include_raw_outputs": {
                            "type": "boolean",
                            "default": True,
                            "description": "Include clipped command outputs for answer synthesis.",
                        },
                        "max_output_chars_per_command": {
                            "type": "integer",
                            "default": 12000,
                        },
                    },
                    "required": ["host", "question"],
                },
            ),
            Tool(
                name="audit_connected_devices",
                description=(
                    "Senior-level audit for questions like 'what is connected' or "
                    "'is this the only connected device'. Collects CDP, LLDP, "
                    "physical interface status, MAC address table, ARP, trunk, and "
                    "spanning-tree evidence, then returns an assessment with "
                    "confidence and limitations."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "timeout_seconds": {
                            "type": "integer",
                            "default": self.settings.default_timeout_seconds,
                        },
                        "include_raw_outputs": {
                            "type": "boolean",
                            "default": False,
                            "description": "Include full command outputs in the response.",
                        },
                    },
                    "required": ["host"],
                },
            ),
            Tool(
                name="get_discovery_artifact",
                description="Read a stored discovery artifact by run ID.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "run_id": {"type": "string"},
                        "artifact": {
                            "type": "string",
                            "enum": ["topology_json", "report_markdown", "drawio_xml"],
                        },
                    },
                    "required": ["run_id", "artifact"],
                },
            ),
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> list[TextContent]:
        try:
            context = self._context()
            inventory = context["inventory"]
            device_client = context["device_client"]
            artifacts = context["artifacts"]

            if name == "list_inventory_hosts":
                return [_json_text(inventory.public_hosts(arguments.get("group")))]

            if name == "execute_command":
                result = device_client.run_command(
                    arguments["host"],
                    arguments["command"],
                    timeout_seconds=int(
                        arguments.get("timeout_seconds", self.settings.default_timeout_seconds)
                    ),
                )
                return [_json_text(result.to_dict())]

            if name == "execute_command_batch":
                result = device_client.run_batch(
                    arguments["host"],
                    arguments["commands"],
                    mode=arguments.get("mode", "exec"),
                    timeout_seconds=int(
                        arguments.get("timeout_seconds", self.settings.default_timeout_seconds)
                    ),
                )
                return [_json_text(result.to_dict())]

            if name == "run_discovery":
                discovery = context["discovery"]
                topology = discovery.run(
                    seed_hosts=arguments["seed_hosts"],
                    depth=int(arguments.get("depth", 2)),
                    max_devices=int(arguments.get("max_devices", 100)),
                    timeout_seconds=int(
                        arguments.get("timeout_seconds", self.settings.default_timeout_seconds)
                    ),
                    full_discovery=bool(arguments.get("full_discovery", True)),
                )
                report = generate_markdown_report(topology)
                drawio = generate_drawio_xml(topology)
                metadata = artifacts.create_run(
                    topology=topology,
                    report_markdown=report,
                    drawio_xml=drawio,
                )
                return [_json_text({"run": metadata, "topology": topology})]

            if name == "audit_connected_devices":
                audit = ConnectedDeviceAuditor(device_client).audit(
                    arguments["host"],
                    timeout_seconds=int(
                        arguments.get("timeout_seconds", self.settings.default_timeout_seconds)
                    ),
                    include_raw_outputs=bool(arguments.get("include_raw_outputs", False)),
                )
                return [_json_text(audit)]

            if name == "investigate_network_question":
                investigation = investigate_network_question(
                    device_client,
                    host=arguments["host"],
                    question=arguments["question"],
                    timeout_seconds=int(
                        arguments.get("timeout_seconds", self.settings.default_timeout_seconds)
                    ),
                    include_raw_outputs=bool(arguments.get("include_raw_outputs", True)),
                    max_output_chars_per_command=int(
                        arguments.get("max_output_chars_per_command", 12000)
                    ),
                )
                return [_json_text(investigation)]

            if name == "get_discovery_artifact":
                text = artifacts.read_artifact(arguments["run_id"], arguments["artifact"])
                return [TextContent(type="text", text=text)]

            raise CiscoMCPError(f"Unknown tool: {name}")
        except Exception as exc:
            logger.exception("Tool call failed: %s", name)
            return [TextContent(type="text", text=f"Error: {exc}")]

    async def run(self) -> None:
        from mcp.server.stdio import stdio_server

        async with stdio_server() as (read_stream, write_stream):
            await self.app.run(read_stream, write_stream, self.app.create_initialization_options())

    def _context(self) -> dict[str, Any]:
        inventory = load_inventory(self.settings.inventory_path)
        data_dir = Path(self.settings.data_dir)
        trusted_targets = TrustedTargetStore(data_dir)
        audit_log = AuditLog(data_dir)
        inventory_updater = InventoryUpdater(self.settings.inventory_path)
        device_client = DeviceClient(
            inventory=inventory,
            trusted_targets=trusted_targets,
            audit_log=audit_log,
        )
        discovery = DiscoveryEngine(
            device_client=device_client,
            trusted_targets=trusted_targets,
            inventory_updater=inventory_updater,
        )
        return {
            "inventory": inventory,
            "trusted_targets": trusted_targets,
            "audit_log": audit_log,
            "device_client": device_client,
            "discovery": discovery,
            "artifacts": ArtifactStore(data_dir),
        }


def _json_text(value: Any) -> TextContent:
    return TextContent(type="text", text=json.dumps(value, indent=2, sort_keys=True))


INVESTIGATION_STANDARDS = """# Senior Network Investigation Standards

Answer from evidence, not from a single convenient command.

Minimum discipline:

- State exactly which commands or data sources were checked.
- Separate protocol advertisements from physical link state, learned MACs, ARP,
  routing, and configuration.
- Do not say "only", "all", "none", or "confirmed" unless the evidence supports
  that strength.
- Include limitations when a protocol is disabled, a command is unsupported, or a
  data source can be stale or traffic-dependent.
- Prefer high-level audit tools when available. For connected-device questions,
  use `audit_connected_devices` rather than CDP/LLDP discovery alone.
- For broad network questions, use `investigate_network_question` with the
  user's exact question so the server chooses a relevant evidence profile before
  the answer is written.
- For requests to create tables of devices across the network, use
  `run_discovery` with `full_discovery: true` and inspect the returned
  `tables.network_devices`, `tables.connected_interfaces`, and
  `tables.learned_endpoints` data. Explain that tables are based on reachable
  inventory and discovered neighbors plus MAC/ARP evidence, not omniscient
  proof of every silent endpoint.
- Authorization starts from inventory seed devices. Any CDP/LLDP-discovered
  downstream device is trusted by provenance even if it is not in inventory. The
  server first tries direct SSH from the MCP host; if unavailable, it attempts
  trusted-upstream SSH transport forwarding. If the upstream device does not
  support forwarding, report the target as trusted but not queryable with the
  available transport rather than treating it as unauthorized.

Connected-device questions require, at minimum:

- CDP neighbors and LLDP neighbors for advertised identity.
- Interface status for physical link state.
- MAC address table for L2 learning.
- ARP for local L3 identity mapping where available.
- Trunk and spanning-tree evidence for possible downstream switching.

Routing questions require, at minimum:

- The specific route lookup requested.
- The relevant routing table summary or prefix entry.
- Next-hop reachability evidence when the answer depends on forwarding.
- A distinction between configured static routes, learned routes, and selected
  forwarding entries.
"""
