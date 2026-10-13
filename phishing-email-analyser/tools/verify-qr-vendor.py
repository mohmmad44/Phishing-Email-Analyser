#!/usr/bin/env python3
"""Check vendored jsQR lock, license and source if included (does not fetch URLs)."""
from pathlib import Path
import hashlib,json,sys
root=Path(__file__).resolve().parents[1]
folder=root/'js/vendor'
html=(root/'index.html').read_text(encoding='utf-8')
script='<script src="js/vendor/jsQR.js"></script>'
paths=[folder/'jsQR.js',folder/'jsQR.LICENSE',folder/'jsQR.lock.json']
if not any(p.exists() for p in paths):
    if script in html:sys.exit('QR vendor script referenced but missing!')
    print('QR vendor: OPTIONAL NOT INSTALLED; native BarcodeDetector still available on compatible browsers')
    sys.exit(0)
if not all(p.is_file() for p in paths):sys.exit('QR vendor incomplete: require JS + license + lock JSON')
if script not in html:sys.exit('QR vendor files installed but missing local script tag')
lock=json.loads(paths[2].read_text(encoding='utf-8'))
if lock.get('library')!='jsqr' or lock.get('version')!='1.4.0' or lock.get('license')!='Apache-2.0':sys.exit('Unexpected QR dependency lock metadata')
for asset in paths[:2]:
    expected=lock.get('sha256',{}).get(asset.name)
    if not isinstance(expected,str) or len(expected)!=64 or hashlib.sha256(asset.read_bytes()).hexdigest()!=expected:sys.exit('QR vendor checksum mismatch: '+asset.name)
if b'Apache License' not in paths[1].read_bytes():sys.exit('QR vendor license missing')
print('QR vendor: verified SHA-256 on bundled jsQR 1.4.0 and Apache-2.0 license')
