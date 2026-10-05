"""Check every reachable commit for forbidden operational files and key material.

This is a focused publication check, not a general secret scanner.
"""
from pathlib import Path
import re
import ipaddress
import subprocess
import sys

def git(*args):
    return subprocess.check_output(['git', *args])

forbidden = {'hosts', 'README.INTERNAL.md', 'command_history.json', 'last_topology.json', '.env'}
key_pattern = re.compile(rb'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----')
issues = set()
ip_pattern = re.compile(rb"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
allowed_ranges = [ipaddress.ip_network(x) for x in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8")]
def inspect_blob(path, data):
    if key_pattern.search(data):
        issues.add(path)
    for raw in ip_pattern.findall(data):
        try:
            address = ipaddress.ip_address(raw.decode())
        except ValueError:
            continue
        if not any(address in network for network in allowed_ranges):
            issues.add(path)

blobs = {}
for commit in git('rev-list', '--all').decode().splitlines():
    for row in git('ls-tree', '-r', '-z', commit).split(b'\0'):
        if not row: continue
        meta, name = row.split(b'\t', 1)
        path = name.decode(errors='replace')
        basename = Path(path).name
        if basename in forbidden or basename.startswith('.mcpuser_id_rsa') or basename.endswith(('.pem', '.key')):
            issues.add(path)
        object_id = meta.split()[-1].decode()
        if object_id not in blobs:
            blobs[object_id] = git('cat-file', 'blob', object_id)
        inspect_blob(path, blobs[object_id])
for raw in git('ls-files', '-z').split(b'\0'):
    if raw:
        path = raw.decode()
        inspect_blob(path, Path(path).read_bytes())
if issues:
    print('Publication check failed; inspect these paths privately:', ', '.join(sorted(issues)))
    sys.exit(1)
print(f'Publication check passed: {len(blobs)} unique blobs across all reachable commits; no forbidden operational files, private-key blocks or non-documentation IPv4 addresses.')
