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
    if file==manifest_path or any(part in ('.git','.idea','__pycache__','node_modules','.vscode') for part in file.parts):continue
    if file.suffix in ('.pyc','.log'):continue
    b=file.read_bytes()
    entries.append({'path':relative,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
manifest['source_sha256']=entries
manifest['release']='11.0-team-final-evidence-first-verification-triage'
manifest['documentation']='README.md and phishing-email-analyser/README.md'
manifest['markdown_files']=sum(1 for entry in entries if entry['path'].endswith('.md'))
manifest['test_evidence']='phishing-email-analyser/docs/V11_DECISION_QUALITY_STUDY.md'
manifest['test_limitations']='v11 adds independent-verification recommendations for under-evidenced action requests, without changing production risk scores, and measures human-review workload separately from phishing classifications. An independent external labeled CSV could not be downloaded in this environment. NO new real-world accuracy or calibrated probabilities are claimed. Remote CI not executed.'
manifest.pop('reported_checks_passed',None)
manifest_path.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
print('Wrote',len(entries),'verified source entries')
