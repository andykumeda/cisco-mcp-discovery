# Cisco MCP source instructions

This is the canonical public portfolio/demo source. Read README.md, CONFIGURATION.md and RECOVERY.md before editing. Preserve the separate private recovery archive and original backup; never merge their Git history or copy credentials/customer data into this repo.

Use synthetic/offline data for routine verification. Run `python3 -m unittest discover -s tests -v`, `python3 -m cisco_mcp.demo` and `python3 scripts/check_public_history.py`. The demo requires no external packages and must never open a device connection. Live access requires explicit user authorization and deliberate lab configuration; retain opt-in, bounded traversal, explicit target scope, default-deny commands and strict host-key validation.

Document prototype limitations honestly. No official Cisco affiliation, complete topology, production safety, security certification or measured time-saving claims. Keep generated demo outputs ignored and operational inventory/keys outside Git. Do not delete or overwrite the original recovery records.

The full archive review recovered a later application in next/. Use next/ for future expanded-server work, and keep the root offline demo reproducible. The newer prototype supports arbitrary CLI, configuration sessions, provenance trust and inventory updates after explicit SSH opt-in; its restrictions differ from the root application. Read next/README.md and next/docs/SECURITY.md. Live use requires additional authorization/scope/host-key review. Run its 27 fixture tests with PYTHONPATH=next/src; never query devices for routine checks.
