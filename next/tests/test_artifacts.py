from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from cisco_mcp_server.drawio import generate_drawio_xml
from cisco_mcp_server.reporting import generate_markdown_report
from cisco_mcp_server.storage import ArtifactStore


def sample_topology():
    return {
        "metadata": {"created_at": "2026-06-02T00:00:00Z", "seed_hosts": ["edge-1"], "depth": 1},
        "nodes": [
            {
                "id": "192.0.2.10",
                "label": "edge-1",
                "address": "192.0.2.10",
                "source": "inventory",
                "interfaces": [
                    {
                        "name": "GigabitEthernet1/0/1",
                        "ip": "192.0.2.10",
                        "status": "up",
                        "protocol": "up",
                    }
                ],
            },
            {
                "id": "192.0.2.20",
                "label": "dist-1",
                "address": "192.0.2.20",
                "source": "discovered",
            },
        ],
        "links": [
            {
                "source": "192.0.2.10",
                "target": "192.0.2.20",
                "protocol": "cdp",
                "source_interface": "GigabitEthernet1/0/1",
                "target_interface": "GigabitEthernet1/0/24",
            }
        ],
        "warnings": [],
    }


def test_report_and_drawio_generation_are_valid():
    topology = sample_topology()
    report = generate_markdown_report(topology)
    drawio = generate_drawio_xml(topology)

    assert "# Cisco Discovery Report" in report
    assert "edge-1" in report
    root = ET.fromstring(drawio)
    assert root.tag == "mxfile"
    assert 'as_="geometry"' not in drawio
    assert 'as="geometry"' in drawio


def test_artifact_store_round_trips_outputs(tmp_path):
    topology = sample_topology()
    store = ArtifactStore(tmp_path)
    metadata = store.create_run(
        topology=topology,
        report_markdown=generate_markdown_report(topology),
        drawio_xml=generate_drawio_xml(topology),
    )

    loaded_topology = json.loads(store.read_artifact(metadata["run_id"], "topology_json"))
    assert loaded_topology["nodes"][0]["id"] == "192.0.2.10"
    assert "Cisco Discovery Report" in store.read_artifact(metadata["run_id"], "report_markdown")
    assert "<mxfile" in store.read_artifact(metadata["run_id"], "drawio_xml")
