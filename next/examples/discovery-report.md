# Cisco Discovery Report

- Created: 2026-06-02T00:00:00Z
- Seeds: edge-1
- Depth: 1
- Devices: 2
- Links: 1

## Devices

### edge-1

- Address: 192.0.2.10
- Source: inventory
- Platform: C9300
- Software: 17.09
- Credential Source: edge-1

| Interface | IP | Status | Protocol |
|---|---:|---|---|
| GigabitEthernet1/0/1 | 192.0.2.10 | up | up |

### dist-1

- Address: 192.0.2.20
- Source: discovered
- Platform: C9300
- Software: 17.09
- Credential Source: edge-1

## Links

| Source | Target | Protocol | Source Interface | Target Interface |
|---|---|---|---|---|
| 192.0.2.10 | 192.0.2.20 | cdp | GigabitEthernet1/0/1 | GigabitEthernet1/0/24 |

## Warnings

No warnings.
