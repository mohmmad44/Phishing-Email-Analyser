# QR decoder integration — Cybersteps 12.2.1

## Why the warning appears

`BarcodeDetector` is not universally implemented, and the optional local `jsQR` decoder was not included in the preceding 12.2 release. If both `typeof BarcodeDetector` and `typeof window.jsQR` are `undefined`, the app cannot decode QR pixels; its static URL/HTML/email analysis continues to work.

## Fixed delivery path

A one-time Windows installer (`INSTALL_QR_DECODER_WINDOWS.cmd`) invokes a PowerShell installation script using built-in Windows components. A Python alternative (`tools/install-qr-decoder.py`) is supplied for other platforms. Both download the *version-locked npm tarball* (or verify an offline copy), enforce the published SHA-512 **before extracting**, then place `js/vendor/jsQR.js`, `js/vendor/jsQR.LICENSE`, and `js/vendor/jsQR.lock.json` into the project and insert the local script before `qr-security.js` in `index.html`.

The expected npm tarball integrity is pinned in both installers:

`sha512-dxLob7q65Xg2DvstYkRpkYtmKm2sPJ9oFhrhmudT1dZvNFFTlroai3AWSpLey/w5vMcLBXRgOJsbXpdN9HzU/A==`

Package source: `https://registry.npmjs.org/jsqr/-/jsqr-1.4.0.tgz`. Verify the hash against independent npm package metadata or a lockfile when changing versions. If a package differs, **installation fails closed**.

## Windows usage

1. Extract the full Cybersteps project.
2. Double-click **`phishing-email-analyser/INSTALL_QR_DECODER_WINDOWS.cmd`** with an internet connection. Windows 10/11 needs built-in `tar.exe` and PowerShell.
3. Restart the browser tab (or hard reload). Use **F12 / Console**: `typeof window.jsQR` should be `"function"`.
4. Import `examples/eml/01_phishing/P18...eml` (find P18 by filename) or the dedicated QR demonstration `.eml` from the demo pack. Scan result depends on the QR image; no website is visited.
5. After checking, Cybersteps operates **offline**. Only the installer makes a one-time download.

If Windows blocks execution, inspect the installer source; alternatively install using Python:

`python tools/install-qr-decoder.py`

An offline installation is also possible using `--archive jsqr-1.4.0.tgz`; the pinned SHA-512 is still enforced. No arbitrary local archive is trusted.

## Validation and deployment

- `node tests/run-tests.js`
- `node tests/qr-installer-tests.js`
- `python tools/verify-qr-vendor.py`
- `python tools/build-release-manifest.py` (after installing library locally)
- `python tools/verify-release-manifest.py`

The v12.2.1 *source* ZIP contains the installer but **does not bundle third-party jsQR bytes** because this execution environment cannot retrieve the npm tarball. Functional local-jsQR decoding can be verified only after running the installer on a networked computer. Do not present decoder support as confirmed before that.

## Limitations

One QR symbol per image is returned in the jsQR fallback. It is still a static inspector and cannot prove that a decoded destination is malicious or safe. Images from emails are rasterized in memory and their contents are not sent to third parties. The Content Security Policy continues to block outbound connections during normal use.
