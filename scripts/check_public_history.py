"""Check every reachable commit for forbidden operational files and key material.

This is a focused publication check, not a general secret scanner.
"""
from pathlib import Path
import re
import subprocess
import sys

def git(*args):
    return subprocess.check_output(['git', *args])

forbidden = {'hosts', 'README.INTERNAL.md', 'command_history.json', 'last_topology.json', '.env'}
key_pattern = re.compile(rb'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----')
issues = set()
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
        if key_pattern.search(blobs[object_id]):
            issues.add(path)
if issues:
    print('Publication check failed; inspect these paths privately:', ', '.join(sorted(issues)))
    sys.exit(1)
print(f'Publication check passed: {len(blobs)} unique blobs across all reachable commits; no forbidden operational files or private-key blocks.')
