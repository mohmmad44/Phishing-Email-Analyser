#!/usr/bin/env python3
"""Download the exact Zenodo 13474746 CSV and verify its published checksum.

Run voluntarily from a machine with network access; the browser application never
fetches external data. No dataset is redistributed in the release ZIP.
"""
import argparse
import hashlib
import os
from pathlib import Path
from urllib.request import Request, urlopen

SOURCE = 'https://zenodo.org/records/13474746/files/Phishing_validation_emails.csv?download=1'
PUBLISHED_MD5 = '1bf8ec0fe3f67e12dd275ce5b2b91b69'
MAX_SIZE = 5 * 1024 * 1024


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='evaluation_data/Phishing_validation_emails.csv')
    args = parser.parse_args()
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        req = Request(SOURCE, headers={'User-Agent':'Cybersteps-course-evaluation/1.0'})
        with urlopen(req, timeout=30) as response:
            if response.geturl().split(':', 1)[0] != 'https':
                raise ValueError('Refused insecure download redirect')
            contents = response.read(MAX_SIZE + 1)
        if len(contents) > MAX_SIZE:
            raise ValueError('Dataset exceeded 5 MiB size limit')
        actual = hashlib.md5(contents).hexdigest()  # Published source integrity only, not a security signature.
        if actual != PUBLISHED_MD5:
            raise ValueError(f'Published MD5 mismatch (expected {PUBLISHED_MD5}, received {actual}); file not written')
        if destination.exists():
            raise FileExistsError(f'Destination exists; refusing overwrite: {destination}')
        with destination.open('xb') as f:
            os.chmod(destination, 0o600)
            f.write(contents)
        print(f'Verified published MD5: {actual}')
        print(f'Local SHA-256: {hashlib.sha256(contents).hexdigest()}')
        print(f'Saved {len(contents)} bytes to {destination}')
        print('WARNING: Dataset mixes real and generated emails; never claim independent real-world accuracy.')
    except Exception as exc:
        parser.exit(2, f'Unable to retrieve/validate CSV: {exc}\nDownload directly from {SOURCE} if blocked, then verify MD5 yourself.\n')

if __name__ == '__main__':
    main()
