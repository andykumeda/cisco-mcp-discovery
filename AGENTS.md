# Cisco MCP source instructions

This is the canonical public portfolio/demo source. Read README.md, CONFIGURATION.md and RECOVERY.md before editing. Preserve the separate private recovery archive and original backup; never merge their Git history or copy credentials/customer data into this repo.

Use synthetic/offline data for routine verification. Run `python3 -m unittest discover -s tests -v`, `python3 -m cisco_mcp.demo` and `python3 scripts/check_public_history.py`. The demo requires no external packages and must never open a device connection. Live access requires explicit user authorization and deliberate lab configuration; retain opt-in, bounded traversal, explicit target scope, default-deny commands and strict host-key validation.

Document prototype limitations honestly. No official Cisco affiliation, complete topology, production safety, security certification or measured time-saving claims. Keep generated demo outputs ignored and operational inventory/keys outside Git. Do not delete or overwrite the original recovery records.
