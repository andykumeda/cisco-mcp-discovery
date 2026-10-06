"""Audit, artifact, and trusted-target storage."""

from __future__ import annotations

import getpass
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cisco_mcp_server.exceptions import ArtifactError, InventoryError
from cisco_mcp_server.inventory import Inventory
from cisco_mcp_server.models import DeviceTarget


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except PermissionError:
        # Keep going; ownership/permissions may be managed by deployment.
        pass


class AuditLog:
    def __init__(self, data_dir: Path) -> None:
        ensure_private_dir(data_dir)
        self.path = data_dir / "command_audit.jsonl"

    def append(self, event: dict[str, Any]) -> None:
        payload = {
            "timestamp": utc_now(),
            "os_user": getpass.getuser(),
            **event,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True) + "\n")


@dataclass(frozen=True)
class TrustedTargetRecord:
    name: str
    address: str
    credential_source: str
    discovered_from: str
    protocol: str
    first_seen: str
    last_seen: str


class TrustedTargetStore:
    def __init__(self, data_dir: Path) -> None:
        ensure_private_dir(data_dir)
        self.path = data_dir / "trusted_targets.json"

    def add(
        self,
        *,
        name: str,
        address: str,
        credential_source: str,
        discovered_from: str,
        protocol: str,
    ) -> TrustedTargetRecord:
        records = self._read()
        now = utc_now()
        key = self._key(name, address)
        existing = records.get(key)
        if existing:
            existing["last_seen"] = now
            existing["discovered_from"] = discovered_from
            existing["protocol"] = protocol
            records[key] = existing
        else:
            records[key] = {
                "name": name,
                "address": address,
                "credential_source": credential_source,
                "discovered_from": discovered_from,
                "protocol": protocol,
                "first_seen": now,
                "last_seen": now,
            }
        self._write(records)
        return TrustedTargetRecord(**records[key])

    def resolve(self, host: str, inventory: Inventory, *, address: str | None = None,
                discovered_from: str | None = None, protocol: str | None = None) -> DeviceTarget:
        records = self._read()
        candidates = [item for item in records.values()
                      if (address is None or item["address"] == address)
                      and (discovered_from is None or item["discovered_from"] == discovered_from)
                      and (protocol is None or item["protocol"] == protocol)]
        matches = [item for item in candidates if item["name"] == host]
        if not matches:
            matches = [item for item in candidates if item["address"] == (address or host)]
        if not matches:
            raise InventoryError(f"Host '{host}' is not present in inventory or trusted discovery.")
        if len(matches) != 1:
            raise InventoryError(f"Host '{host}' has ambiguous trusted discovery provenance.")
        record = matches[0]

        credential_target = inventory.resolve(record["credential_source"])
        return DeviceTarget(
            name=record["name"],
            address=record["address"],
            username=credential_target.username,
            password=credential_target.password,
            key_file=credential_target.key_file,
            port=credential_target.port,
            device_type=credential_target.device_type,
            groups=credential_target.groups,
            vars={
                **credential_target.vars,
                "cisco_mcp_discovered_from_host": record["discovered_from"],
                "cisco_mcp_discovery_protocol": record["protocol"],
            },
            source="discovered",
            credential_source=record["credential_source"],
            reachable_via=record["discovered_from"],
        )

    def public_records(self) -> list[dict[str, Any]]:
        return sorted(self._read().values(), key=lambda item: (item["address"], item["name"]))

    def _read(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        with self.path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        if not isinstance(raw, dict):
            return {}
        return raw

    def _write(self, records: dict[str, dict[str, Any]]) -> None:
        tmp_path = self.path.with_suffix(".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2, sort_keys=True)
        tmp_path.replace(self.path)

    @staticmethod
    def _key(name: str, address: str) -> str:
        return f"{address}|{name}"


class ArtifactStore:
    def __init__(self, data_dir: Path) -> None:
        ensure_private_dir(data_dir)
        self.runs_dir = data_dir / "runs"
        ensure_private_dir(self.runs_dir)

    def create_run(
        self,
        *,
        topology: dict[str, Any],
        report_markdown: str,
        drawio_xml: str,
    ) -> dict[str, Any]:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
        run_dir = self.runs_dir / run_id
        ensure_private_dir(run_dir)

        files = {
            "topology_json": run_dir / "topology.json",
            "report_markdown": run_dir / "report.md",
            "drawio_xml": run_dir / "topology.drawio.xml",
        }
        files["topology_json"].write_text(
            json.dumps(topology, indent=2, sort_keys=True), encoding="utf-8"
        )
        files["report_markdown"].write_text(report_markdown, encoding="utf-8")
        files["drawio_xml"].write_text(drawio_xml, encoding="utf-8")

        metadata = {
            "run_id": run_id,
            "created_at": utc_now(),
            "artifacts": {name: str(path) for name, path in files.items()},
        }
        (run_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return metadata

    def read_artifact(self, run_id: str, artifact: str) -> str:
        if not isinstance(run_id, str) or not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}", run_id):
            raise ArtifactError("Invalid run ID.")
        if artifact not in {"topology_json", "report_markdown", "drawio_xml"}:
            raise ArtifactError("Artifact must be topology_json, report_markdown, or drawio_xml.")

        filenames = {
            "topology_json": "topology.json",
            "report_markdown": "report.md",
            "drawio_xml": "topology.drawio.xml",
        }
        path = (self.runs_dir / run_id / filenames[artifact]).resolve()
        if not path.is_relative_to(self.runs_dir.resolve()):
            raise ArtifactError("Artifact path must remain within the run directory.")
        if not path.exists():
            raise ArtifactError(f"Artifact not found: {run_id}/{artifact}")
        return path.read_text(encoding="utf-8")

    def list_runs(self) -> list[dict[str, Any]]:
        runs: list[dict[str, Any]] = []
        for metadata_path in sorted(self.runs_dir.glob("*/metadata.json"), reverse=True):
            try:
                runs.append(json.loads(metadata_path.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                continue
        return runs


def dataclass_dict(value: Any) -> dict[str, Any]:
    return asdict(value)
