#!/usr/bin/env python3
"""Fail if any listed release source differs from the exact checked-out bytes."""
import hashlib,json,sys
from pathlib import Path
repo=Path(__file__).resolve().parents[2]
manifest=json.loads((repo/'phishing-email-analyser/RELEASE_MANIFEST.json').read_text())
issues=[]
for entry in manifest.get('source_sha256',[]):
    path=repo/entry['path']
    if not path.is_file():issues.append('MISSING: '+entry['path']);continue
    actual=path.read_bytes()
    if len(actual)!=entry['bytes'] or hashlib.sha256(actual).hexdigest()!=entry['sha256']:
        issues.append('MISMATCH: '+entry['path'])
for msg in issues:print(msg,file=sys.stderr)
print(f'Verified {len(manifest.get("source_sha256",[]))-len(issues)}/{len(manifest.get("source_sha256",[]))} release hashes')
sys.exit(bool(issues))
