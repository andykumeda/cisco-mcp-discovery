# Later MCP application prototype

This is the fuller application recovered from the same backup after the earlier implementation was published. Source timestamps extend to June 23, 2026. Its archived Git repository had no commits, so this recovery preserves the working files rather than inventing a commit history. The original source is retained privately, including file hashes.

Use this directory for future development of the newer application. The root `cisco_mcp` package remains the smaller three-device offline demonstration. Both are in this one repository; neither requires another backup search. This is an independent project, not an official Cisco product or a claim of production readiness.

## Recovered features

- Netmiko-backed sessions and single/batch command tools, including an explicit configuration-session mode.
- INI/YAML inventory, discovered-target provenance, recursive CDP/LLDP traversal and optional upstream SSH forwarding.
- Connected-device auditing across neighbor protocols, interfaces, MAC learning, ARP, trunks and spanning-tree evidence.
- Question-based investigation profiles for routing, interface health, switching, protocols, security and system state, with evidence/gaps and interpretation requirements.
- Network-device, interface and learned-endpoint tables; JSON, Markdown and Draw.io artifacts.

These tools collect evidence; they do not prove a complete topology or independently validate an AI conclusion. The confidence labels are implementation heuristics, not measured accuracy.

## Public adaptation and limitations

Live SSH is disabled unless `CISCO_MCP_ENABLE_SSH=1`. No production inventory, keys, account names, hostnames, customer acronyms, logs or real topology artifacts are included. Examples and tests are fictional. The original deployment paths and sample private address were replaced. Inventory defaults to `~/.config/cisco-mcp/inventory.yml`, artifacts to `~/.local/share/cisco-mcp-next/artifacts`, the example account to `lab-reader`, and the example key path to `~/.ssh/cisco_mcp_id_ed25519`.

This later prototype has a different policy from the root demo: after deliberate live-access opt-in, it supports arbitrary Cisco CLI and configuration mode, trusts discovered neighbors by provenance, and can append discoveries to the configured inventory. Do not assume the root application's exact allowlist/read-only policy applies here. Narrow discovery scope, command authorization, explicit inventory-mutation control and strict host-key verification need further review before live use. Device access also requires permission and suitable AAA/privilege restrictions. The public version was not exercised against equipment.

## Verify without devices

From the `next` directory, install test-only dependencies into a temporary environment, then run:

```sh
python -m pip install pytest PyYAML
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m pytest tests -q -p no:cacheprovider
```

The 27 recovered tests and public SSH-opt-in and MCP SDK dispatch tests use fixtures/fake connections and do not access devices. Recovery verification additionally blocked socket connections. The root offline demo remains `python3 -m cisco_mcp.demo` and requires no dependencies.

From the repository root, for future authorized lab setup, install this package in a virtual environment with `pip install -e ./next`, provide your own private inventory/credentials, and review [docs/SECURITY.md](docs/SECURITY.md). The `cisco-mcp-server` entry point belongs to this newer package. Installing it alone does not enable SSH. Do not run backup operational scripts or import private recovery history.
