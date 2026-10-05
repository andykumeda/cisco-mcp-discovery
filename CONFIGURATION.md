# Configuration

The offline demo is the default path and needs no setup. The following is only for explicitly authorized live lab use; it has not been exercised against devices in this recovery.

## Runtime

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
# Optional structured parsing; platform support must be verified separately:
.venv/bin/python -m pip install -r requirements-genie.txt
```

The runtime process must belong to the configured OS group (`CISCO_MCP_GROUP`, default `mcpusers`). Configure this using your system's normal account administration. The demo does not use this group guard. Root is not a recommended runtime account.

## Live SSH opt-in

- `CISCO_MCP_ENABLE_SSH=1` enables live SSH. Omit it to keep SSH disabled.
- `CISCO_MCP_USER`: least-privileged device account, default `mcpuser`.
- `CISCO_MCP_KEY_PATH`: private key outside the repo; default `~/.ssh/cisco_mcp_id_ed25519`.
- `CISCO_MCP_HOSTS_FILE`: exact seed/run-command allowlist; default local ignored `hosts` file. Copy `hosts.example` and replace fictional entries with authorized targets privately.
- `CISCO_MCP_DISCOVERY_CIDRS`: optional comma-separated numeric CIDRs for discovered neighbors. Without it, each neighbor must have an exact hosts entry. DNS names do not inherit CIDR access. Use the narrowest permitted scope.
- `CISCO_MCP_DATA_DIR`: collected history/topology; default `~/.local/share/cisco-mcp`. Treat this as private operational data. The directory and runtime JSON/default diagram files are created with owner-only permissions.

Provision device host keys in the runtime user's normal `known_hosts` file after verifying fingerprints through a trusted channel. SSH requires strict host-key validation and does not accept unknown keys automatically.

`discover_network` depth is 0–10, default 3. Depth 0 queries the seed and records advertised neighbors without following them. A 100-device budget bounds the recorded graph and traversal; warnings identify omitted/out-of-scope observations. A successful command or completed traversal is not complete network validation.

Default commands: `show version`, `show cdp neighbors detail`, `show lldp neighbors detail`, `show ip arp`. `CISCO_MCP_CMD_WHITELIST` and `CISCO_MCP_CMD_BLACKLIST` may point to administrator-reviewed pattern files. Blacklist wins; default deny follows. Command separators/control characters remain blocked regardless of patterns. Do not broaden to configuration dumps or shell commands casually.

Launch `.venv/bin/python cisco_mcp_server.py` via an MCP client's stdio transport. Edit `mcp-client.example.json` with your absolute executable/script paths and private environment configuration. Diagram output is a local file and MCP resource `cisco://topology.drawio`. Use a local editor for sensitive diagrams; encoded share URLs contain topology data and must not be sent to external services without approval.
