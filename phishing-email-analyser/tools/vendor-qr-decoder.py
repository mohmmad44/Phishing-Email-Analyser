#!/usr/bin/env python3
"""Install jsQR 1.4.0 only from integrity-verified bytes; offline sources supported.

Expected hashes MUST be independently verified. The installer cannot establish
package provenance by merely hashing the bytes it downloaded. No runtime network.

Online:
 python3 tools/vendor-qr-decoder.py --js-sha256 HASH --license-sha256 HASH
Offline (recommended on air-gapped systems):
 python3 tools/vendor-qr-decoder.py --js-sha256 HASH --license-sha256 HASH \
   --js-file /trusted/jsQR.js --license-file /trusted/LICENSE
"""
from pathlib import Path
import argparse, hashlib, json, re, urllib.request

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--js-sha256',required=True)
p.add_argument('--license-sha256',required=True)
p.add_argument('--js-file',type=Path)
p.add_argument('--license-file',type=Path)
a=p.parse_args()
for digest in (a.js_sha256,a.license_sha256):
    if not re.fullmatch(r'[0-9a-fA-F]{64}',digest):p.error('Expected SHA-256 must contain 64 hex digits')
if bool(a.js_file)!=bool(a.license_file):p.error('Provide BOTH --js-file and --license-file for offline installation')
root=Path(__file__).resolve().parents[1]
assets=(
 ('jsQR.js',a.js_file,'https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js',a.js_sha256.lower()),
 ('jsQR.LICENSE',a.license_file,'https://cdn.jsdelivr.net/npm/jsqr@1.4.0/LICENSE',a.license_sha256.lower()),
)
# Validate injection anchor before writing ANY asset.
html=root/'index.html'
source=html.read_text(encoding='utf-8')
anchor='<!-- Optional offline jsQR decoder may be installed by tools/vendor-qr-decoder.py. -->'
script='<script src="js/vendor/jsQR.js"></script>'
if script not in source and anchor not in source:raise SystemExit('Missing approved HTML injection anchor; no writes performed')
validated={}
for name,local,url,expected in assets:
    if local:
        payload=local.read_bytes()
    else:
        req=urllib.request.Request(url,headers={'User-Agent':'CyberstepsPinnedVendoring/2.0'})
        with urllib.request.urlopen(req,timeout=20) as response:payload=response.read(500001)
    if not payload or len(payload)>500000:raise SystemExit('Asset missing or over 500k limit: '+name)
    observed=hashlib.sha256(payload).hexdigest()
    if observed!=expected:raise SystemExit('SHA-256 mismatch for '+name+': expected '+expected+' observed '+observed)
    validated[name]=payload
if b'Apache License' not in validated['jsQR.LICENSE'] or b'Version 2.0' not in validated['jsQR.LICENSE']:
    raise SystemExit('License text does not appear to be Apache License 2.0')
if b'jsQR' not in validated['jsQR.js']:
    raise SystemExit('Decoder bundle does not appear to export jsQR')
lock={'library':'jsqr','version':'1.4.0','license':'Apache-2.0','runtime_network':False,
      'sha256':{'jsQR.js':a.js_sha256.lower(),'jsQR.LICENSE':a.license_sha256.lower()},
      'provenance':'expected digests provided externally; caller must independently verify'}
folder=root/'js/vendor';folder.mkdir(exist_ok=True)
for name,blob in validated.items():
    (folder/name).write_bytes(blob)
(folder/'jsQR.lock.json').write_text(json.dumps(lock,indent=2)+'\n',encoding='utf-8')
if script not in source:
    html.write_text(source.replace(anchor,anchor+'\n'+script),encoding='utf-8')
print('Offline jsQR 1.4.0 installed from SHA-256-verified assets; keep lock and license in git, then regenerate release manifest.')
