# Cybersteps v7.0 — Split-Safe Benchmarking and QR Resilience

## Authoritative baseline

Built on `Cybersteps_Team_Final_Advanced_Security_v6.0.zip`, which itself was carefully merged over the team's final `Phishing-Email-Analyser-main.zip`. The original team's 104 regressions and all prior security modules are preserved.

## New or enhanced source

- **`tools/benchmark-v7.js` (new)**: strict separate validation/test evaluation, campaign and exact-input leakage rejection, conflicting-label refusal, validation-only threshold selection with Wilson false-positive upper-bound and minimum recall constraints, optional validation-fit monotonic PAVA reliability estimates, held-out reliability measures (Brier/ECE), per-language held-out metrics and provenance requirements. No raw email/URL content in exported reports. Synthetic corpora cannot calibrate.
- **`js/qr-security.js` (enhanced)**: `createImageBitmap` alternative using local `FileReader`/`Image`, two decoder paths (browser `BarcodeDetector` or pinned offline jsQR), pixel/byte caps, and incomplete-coverage reporting. No URL navigation or uploads.
- **`js/app.js` (small targeted update)**: QR scanning unsupported/limited statuses become explicit incomplete-coverage messages in the actual risk report; analyses from the team's email input/EML parser continue to work unchanged.
- **`tools/vendor-qr-decoder.py` (enhanced)**: checked SHA-256 installation from either release-pinned HTTPS or developer-supplied offline files, same-version license verification, lock manifest.
- **`tools/verify-qr-vendor.py` (new)**: CI gate for included local vendor files. Missing optional decoder is reported as optional, never falsely asserted present.
- **`tests/v7-evaluation-tests.js` (new)**: 14 checks covering split leakage, conflicting labels, invalid labels, metadata requirements, synthetic calibration refusal, independent held-out evaluation behavior, QR image fallback and bounds.
- **`tests/merge-review-tests.js` (one assertion update)**: tests actual pinned hash verification algorithm rather than the old installer's specific variable names.
- **`.github/workflows/security-tests.yml`**: adds new evaluation, vendor integrity, and optional decoder gates.
- **`docs/V7_EVALUATION_SECURITY.md` and README**: reproducibility, supply chain, operational caveats.

## Verification

- Existing team suite: 104/104
- Existing security suites: 1,239/1,239 (as in v6, total baseline 1,343)
- New v7 research and QR suite: 14/14
- **Combined 1,357 tests passed, 0 failed** when run in the build environment.
- Browser smoke harness: Chromium passed (OAuth report, dashboard retained, explicit unsupported-QR coverage; no page exceptions). This is a local inline-assets harness, not hosted CSP validation.
- Manifest: see `RELEASE_MANIFEST.json`; re-run the verifier in CI and after extraction.

## Explicit limitations

- **There is no independently downloaded and verified external email corpus in this release. No external accuracy, measured FPR, or probability calibration claim is made.** An external benchmark requires an authorized, labeled corpus, with source and usage rights verified independently.
- The tiny synthetic sample is an evaluation smoke test only. Its 5/5 held-out phishing detections do not estimate real-world recall.
- Calibrator output is exploratory; **browser scoring stays heuristic and unchanged** until externally supported calibration is independently assessed and approved.
- **Verified jsQR decoder bytes could not be retrieved in this environment**. Native browser QR support may work; cross-browser fallback remains optional until installed and locked. The v7 FileReader/Image improvement alone does not solve missing decoder implementations.
- Passing regression tests is not a guarantee against novel phishing attacks. This release is an educational cybersecurity tool, not a production SOC gateway.
- Remote GitHub Actions has not yet executed on the user's actual repository. A protected branch policy must be configured separately.

## Commands

```sh
cd phishing-email-analyser
node tests/run-tests.js
node tests/v7-evaluation-tests.js
node tools/benchmark-v7.js --input tests/fixtures/SYNTHETIC_SPLIT_RESEARCH.csv --dataset-kind synthetic --output docs/v7-synthetic-split-smoke.json
python3 tools/verify-qr-vendor.py
python3 tools/verify-release-manifest.py
```
