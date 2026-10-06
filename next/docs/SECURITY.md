# Access boundaries and remaining review

Live Netmiko connections default off. Only explicit `CISCO_MCP_ENABLE_SSH=1` enables the default connection factory. Tests inject fake connection factories; no real equipment was accessed during verification.

The inventory is the seed boundary. The recovered implementation trusts CDP/LLDP-discovered targets by provenance, can reuse seed credentials, attempt forwarding through an upstream device, and persist discoveries into inventory. These are implemented behaviors, not proof that an advertised neighbor is authorized. Before live use, add explicit permitted discovery scope and review inventory mutation/credential propagation.

Command validation bounds strings and batches and rejects control characters. It does not classify commands as read-only. Both exec and configuration sessions are supported after opt-in. A low-privilege account/AAA and explicit command authorization are necessary for an authorized lab; do not treat this as the root demo's restricted-command implementation.

Strict device host-key verification still needs review in the newer transport. Collected outputs, audit records, topology and trusted-target cache can contain sensitive data; keep them private outside Git and review permissions, retention and redaction. Inventory can reference secret environment variables. Public examples contain fictional values only.

No production-readiness, full-topology, security/compliance or current operational-health claim is established by the recovered tests. See the repository's PUBLICATION-CHECKS.md before publishing any future source or artifact.
