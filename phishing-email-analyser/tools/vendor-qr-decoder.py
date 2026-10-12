#!/usr/bin/env python3
"""Optional OFFLINE jsQR installer: fail closed without independently verified SHA-256 pins.

Usage: python3 tools/vendor-qr-decoder.py --js-sha256 <64 hex> --license-sha256 <64 hex>
Retrieve expected digests from an independently verified release package/source
and review them BEFORE executing this script. Never trust computed digests of an
unverified download as an expected value. No runtime network dependencies.
"""
from pathlib import Path
import argparse, hashlib, re, urllib.request

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--js-sha256',required=True,help='Independently verified SHA-256 of jsQR.js v1.4.0')
parser.add_argument('--license-sha256',required=True,help='Independently verified SHA-256 of LICENSE in jsqr npm 1.4.0 package')
args=parser.parse_args()
for digest in (args.js_sha256,args.license_sha256):
    if not re.fullmatch('[0-9a-fA-F]{64}',digest):parser.error('Expected hash must contain 64 hexadecimal characters')
root=Path(__file__).resolve().parents[1]
assets=(
 ('js/vendor/jsQR.js','https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js',args.js_sha256),
 ('js/vendor/jsQR.LICENSE','https://cdn.jsdelivr.net/npm/jsqr@1.4.0/LICENSE',args.license_sha256),
)
pending=[]
for filename,url,expected in assets:
    req=urllib.request.Request(url,headers={'User-Agent':'CyberstepsPinnedVendoring/1.1'})
    with urllib.request.urlopen(req,timeout=30) as response:
        data=response.read(500_001)
    if not data or len(data)>=500_001:raise ValueError('Downloaded asset empty/too large: '+filename)
    actual=hashlib.sha256(data).hexdigest()
    if actual!=expected.lower():raise ValueError('SHA-256 mismatch for '+filename+'; expected '+expected+' got '+actual)
    pending.append((root/filename,data))
# No partial writes until BOTH artifacts have validated.
for path,data in pending:
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(data)
html=root/'index.html'
source=html.read_text()
anchor='<!-- Optional offline jsQR decoder may be installed by tools/vendor-qr-decoder.py. -->'
if '<script src="js/vendor/jsQR.js"></script>' not in source:
    if anchor not in source:raise ValueError('Missing approved HTML injection anchor; no script changes made')
    html.write_text(source.replace(anchor,anchor+'\n<script src="js/vendor/jsQR.js"></script>'))
print('Verified, installed offline jsQR 1.4.0 and its version-matched npm license. Rerun tests and update release manifest.')
