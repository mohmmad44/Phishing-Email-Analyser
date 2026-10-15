#!/usr/bin/env python3
"""Rebuild integrity records for every source file. Run only when ready to release.
The manifest file itself is excluded; no need for circular self-hashing.
"""
from pathlib import Path
import hashlib,json
repo=Path(__file__).resolve().parents[2]
manifest_path=repo/'phishing-email-analyser/RELEASE_MANIFEST.json'
manifest=json.loads(manifest_path.read_text())
entries=[]
for file in sorted(repo.rglob('*')):
    if not file.is_file():continue
    relative=file.relative_to(repo).as_posix()
    if file==manifest_path or any(part in ('.git','.idea','__pycache__','node_modules','.vscode','evaluation_data') for part in file.parts):continue
    if file.suffix in ('.pyc','.log'):continue
    b=file.read_bytes()
    entries.append({'path':relative,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
manifest['source_sha256']=entries
manifest['release']='12.2.1-qr-decoder-one-time-pinned-installer'
manifest['documentation']='README.md and phishing-email-analyser/README.md'
manifest['markdown_files']=sum(1 for entry in entries if entry['path'].endswith('.md'))
manifest['test_evidence']='phishing-email-analyser/docs/V12_2_SAMPLE_PACK_RELEASE.md'
manifest['test_limitations']='v12.2 adds 48 entirely fictional MIME demonstration emails. The 20/24 phishing High-risk and 0/18 legitimate High-risk observations are synthetic regression behavior, NOT independent real-world accuracy evidence. A separate limited v12.1 public corpus exploratory study remains documented. QR decoding requires a one-time verified npm jsQR install where BarcodeDetector is unavailable; this package includes the pinned installer, not unverified third-party bytes. Original public dataset and private case review are excluded.'
manifest.pop('reported_checks_passed',None)
manifest_path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
print('Wrote',len(entries),'verified source entries')
