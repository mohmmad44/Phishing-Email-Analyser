#!/usr/bin/env python3
"""Install jsQR 1.4.0 from npm's immutable, integrity-pinned tarball.

No runtime requests are added to Cybersteps. The archive's SHA-512 is pinned to
npm's published v1.4.0 integrity value and checked BEFORE extracting any bytes.
Use --archive PATH on systems where the published tarball has been downloaded
independently. This command is a one-time development/deployment step.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tarfile
import tempfile
import urllib.request

NPM_TARBALL = 'https://registry.npmjs.org/jsqr/-/jsqr-1.4.0.tgz'
NPM_INTEGRITY = 'sha512-dxLob7q65Xg2DvstYkRpkYtmKm2sPJ9oFhrhmudT1dZvNFFTlroai3AWSpLey/w5vMcLBXRgOJsbXpdN9HzU/A=='
MAX_ARCHIVE_BYTES = 1_500_000
MAX_JS_BYTES = 500_000
ROOT = Path(__file__).resolve().parents[1]
ANCHOR = '<!-- The verified offline jsQR decoder is installed by tools/install-qr-decoder.py or tools/install-qr-decoder.ps1. -->'
SCRIPT = '<script src="js/vendor/jsQR.js"></script>'


def get_verified_archive(archive_path: Path | None) -> bytes:
    if archive_path is None:
        req = urllib.request.Request(NPM_TARBALL, headers={'User-Agent': 'Cybersteps-Verified-jsQR-Installer/1.0'})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read(MAX_ARCHIVE_BYTES + 1)
    else:
        if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError('npm tarball exceeds size cap')
        data = archive_path.read_bytes()
    if not data or len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError('npm tarball empty or exceeds size cap')
    actual = 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode('ascii')
    if actual != NPM_INTEGRITY:
        raise ValueError('npm archive SHA-512 mismatch. No files installed; check the published package integrity.')
    return data


def read_assets(archive: bytes) -> dict[str, bytes]:
    target = {'package/dist/jsQR.js': 'jsQR.js', 'package/LICENSE': 'jsQR.LICENSE'}
    output = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        for name, out in target.items():
            member = tar.getmember(name)
            if not member.isfile() or not 0 < member.size <= MAX_JS_BYTES:
                raise ValueError('Invalid jsQR asset: ' + name)
            with tar.extractfile(member) as fd:
                output[out] = fd.read(MAX_JS_BYTES + 1)
    if b'Apache License' not in output['jsQR.LICENSE'] or b'Version 2.0' not in output['jsQR.LICENSE']:
        raise ValueError('Expected Apache 2.0 license missing')
    if b'jsQR' not in output['jsQR.js'] or b'webpackUniversalModuleDefinition' not in output['jsQR.js']:
        raise ValueError('Expected browser jsQR bundle missing')
    return output


def install_assets(assets: dict[str, bytes]):
    html_file = ROOT / 'index.html'
    source = html_file.read_text('utf-8')
    if SCRIPT not in source and source.count(ANCHOR) != 1:
        raise ValueError('Expected HTML insertion anchor missing or ambiguous; refusing changes')
    directory = ROOT / 'js/vendor'
    directory.mkdir(exist_ok=True)
    lock = {
        'library': 'jsqr', 'version': '1.4.0', 'license': 'Apache-2.0',
        'runtime_network': False, 'npm_tarball': NPM_TARBALL,
        'npm_integrity': NPM_INTEGRITY,
        'sha256': {name: hashlib.sha256(data).hexdigest() for name, data in assets.items()},
        'provenance': 'npm published v1.4.0 integrity; verified SHA-512 before extraction',
    }
    # Write library bytes before referencing them from the page.
    for name, data in assets.items():
        target = directory / name
        with tempfile.NamedTemporaryFile(dir=directory, prefix='.jsqr-', delete=False) as fd:
            tmp = Path(fd.name)
            fd.write(data)
        os.replace(tmp, target)
    (directory / 'jsQR.lock.json').write_text(json.dumps(lock, indent=2) + '\n', encoding='utf-8')
    if SCRIPT not in source:
        html_file.write_text(source.replace(ANCHOR, ANCHOR + '\n' + SCRIPT), encoding='utf-8')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--archive', type=Path, help='Optional locally downloaded jsqr-1.4.0.tgz; exact npm SHA-512 is still verified')
    a = p.parse_args()
    assets = read_assets(get_verified_archive(a.archive))
    install_assets(assets)
    print('Installed pinned offline jsQR 1.4.0. Reload index.html, then test typeof window.jsQR.\n'
          'Rebuild RELEASE_MANIFEST.json before committing with: python tools/build-release-manifest.py')

if __name__ == '__main__':
    main()
