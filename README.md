# Cisco MCP network discovery prototype

Independent project by Andy Kumeda; not an official Cisco product. Start with a seed host, collect CDP/LLDP neighbor evidence and device information, and generate an editable Draw.io topology for engineer review.

## Which source to use

The later recovered application is in [next/](next/README.md): batch sessions, richer discovery tables, endpoint audits and question-based investigations. Use it for future application development. The root package is the smaller, verified offline demo. These have different live-access policies; read the newer source’s limitations before use. Both remain in this single repository.

## Try the offline example

Python 3.10 or newer. No packages, credentials or network access required:

```sh
python3 -m cisco_mcp.demo --output-dir demo-output
```

Open `demo-output/index.html` for a readable summary, or import `demo-output/topology.drawio` into a trusted local Draw.io editor. `topology.json` contains the evidence. All three devices and addresses are fictional. The demo executes the discovery and diagram code with simulated command responses; it does not connect to Cisco equipment or validate Genie parsing.

## What is implemented

- SSH command tool, optional Genie parsing, and MCP tools/resources.
- Seed-host traversal with CDP, LLDP fallback when CDP is sparse, and ARP-assisted address resolution.
- Hostname/alias merging, bidirectional link deduplication, interface labels and a topology summary in Draw.io XML.
- Explicit host/CIDR scope, bounded depth and device count, command restrictions and strict SSH host-key checks.

The diagram is a starting point, not proof of a complete network. Missing discovery protocols, unreachable devices, ambiguous identities and parser differences limit coverage. Routes, VLANs, VRFs, tunnels and full Layer 3 reconstruction are not implemented. Raw-output parsers cover selected output formats; optional Genie behavior needs validation against target platforms. No configuration changes are offered by the default command policy.

## Authorized lab use

Live SSH is disabled by default. See [CONFIGURATION.md](CONFIGURATION.md) for deliberate setup, credentials, host keys, discovery scope and the MCP client example. Do not enable it against a network without permission. Keep collected topology and operational history private.

## Verify

```sh
python3 -m unittest discover -s tests -v
python3 scripts/check_public_history.py
# To include the MCP SDK handler checks:
.venv/bin/python -m unittest discover -s tests -v
```

[RECOVERY.md](RECOVERY.md) explains how the newer implementation was recovered from the existing private project into this clean portfolio snapshot without importing private Git history. The original backup and private history remain separate. This public version is the canonical portfolio/demo source.
