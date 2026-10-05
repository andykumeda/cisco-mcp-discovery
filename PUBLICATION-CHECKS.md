# Publication checks and future changes

Reviewed October 5, 2026. This portfolio repository starts with a clean reviewed source snapshot. The original repository, private development history and operational backup remain private; their Git objects were not copied here.

## What was excluded or replaced

- Device inventory, actual customer hostnames/domain names and customer acronyms.
- Actual operational IP addresses, private keys, client configuration, environment files and credentials.
- Command history, saved discovery runs, real diagrams and customer-specific deployment records.
- The archived server address and its remote diagram-copy instructions.

The offline demo uses fictional `lab-*` names, `example.invalid` domains and reserved documentation address ranges. Public protocol/product acronyms such as MCP, CDP, LLDP, ARP, SSH and Cisco platform names describe the implementation; they are not customer identifiers.

## Verification performed

All tracked files and all reachable Git commit blobs were inspected for private-key blocks, forbidden operational filenames and address literals. The public data was also compared locally against the recovered private inventory's identifiers, without copying that identifier list into this repository or public logs. Customer acronyms and hostname references were reviewed separately. The audit script permits only reserved documentation/loopback IPv4 literals and reports filenames rather than potentially sensitive values.

Ten synthetic tests passed with MCP 1.30. They cover neighbor traversal, deduplication, LLDP interface extraction, per-neighbor ARP resolution, depth/device/scope limits, command restrictions, SSH opt-in, strict host-key arguments, XML geometry, escaped labels, OS-group enforcement and MCP diagram-resource handling. The three-device/two-link demo summary was visually inspected. No live network devices were contacted; optional Genie parsing and complete topology coverage were not validated.

## Before publishing future changes

1. Use fictional data for examples and tests. Keep inventory, credentials and collected runtime artifacts outside Git.
2. Run `python3 scripts/check_public_history.py` and the tests in README.md. Review the diff and any generated artifacts before committing.
3. Compare against any private source identifiers locally when transferring more source. Do not publish the private comparison list or its raw matches.
4. Inspect all branches/tags and Git history, not just the current files. Never merge the preserved private development history.
5. If actual sensitive data reaches a remote, stop publication and address remote history/caches as well as the working tree. A later deletion alone does not remove an earlier disclosure.

The automated checks are focused controls, not a guarantee that an arbitrary future file is sanitized. Human review remains necessary for acronyms, contextual identifiers and non-text artifacts. No real customer artifacts are included in this publication.
