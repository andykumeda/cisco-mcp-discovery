# October 6 review corrections

Owner: Codex. Review: [PR #1](https://github.com/andykumeda/cisco-mcp-discovery/pull/1).

| Finding | Change and acceptance criterion | State |
|---|---|---|
| Persisted discovery credentials | Marked discovered entries resolve through trusted provenance after reload, retaining seed credentials/port without copying secrets into discoveries. | Verified |
| Artifact path escape | Generated run-ID format required; resolved paths including symlinks must remain beneath runs directory. | Verified |
| Empty evidence confidence | Empty/disabled core evidence counts as missing; both empty sources produce low confidence. | Verified |
| Discovery device budget | Seed aliases and neighbors deduplicated against queued and visited IDs, retaining budget for distinct CDP/LLDP targets. | Verified |

The four regression cases were checked against the prior implementation. Verification uses fixtures/fake connections, blocks socket connections, and includes the root offline demo and publication format/history scan. No equipment queried. Existing broader live-use limitations in SECURITY.md still apply.

Release: follow-up PR pending CI and review. Private recovery sources and the ZTP interview demo remain unchanged.
