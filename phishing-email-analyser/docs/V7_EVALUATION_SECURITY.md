# Cybersteps v7.0 — Evaluation reliability and QR capability hardening

## Scope, provenance, and credit

v7 extends **your team's authoritative final release + v6**, without replacing any of the team's original training, dashboard, email parser, German language rules, or detection output. The contribution consists of the split-safe research benchmark, exploratory validation-only monotonic calibration analysis, QR rasterization fallback, coverage propagation, dependency integrity tooling, tests, and CI.

## Threat model and why these controls matter

1. **False detection claims**: 1,000 passing tests do not prove 99% detection accuracy. Synthetic examples reflect how the developer expects the code to behave and may share patterns with implementation rules.
2. **Train/test leakage**: A campaign repeated in test and validation can inflate performance. `group` must represent shared infrastructure or campaign identity; splits sharing a group, exact duplicate input, or conflicting labels cause a *hard failure*.
3. **Optimistic tuning**: A threshold chosen using the held-out test set is not independently evaluated. `tools/benchmark-v7.js` uses validation ONLY to select a threshold, and applies that selected threshold once to the held-out test set. Diagnostic synthetic data can never select a threshold.
4. **False positive cost**: Validation selection requires both a configured minimum observed recall and that the Wilson **upper bound** on false-positive rate not exceed `--max-fpr` (default 0.05). If none qualifies, it retains the original threshold 45, and refuses to calibrate.
5. **Calibration uncertainty**: A monotonic PAVA reliability mapping is fit on validation, with smoothing and a second monotonic pass. Held-out Brier score, 10-bin expected calibration error, and reliability bin counts are reported only when there are at least 100 samples *of each class* in **both** validation and test by default (`--min-class`). The output is exploratory and NEVER changes the browser's risk score or claims clinical/operational probabilistic trustworthiness.
6. **Privacy**: No fetched content, sample text, email addresses, URLs, or raw examples are exported in the benchmark JSON. Reports identify only source metadata, dataset SHA-256, sample counts, thresholds, group-overlap counts, and aggregate test results. The dataset is not committed.
7. **Unsupported QR decoding**: Some browsers have no native BarcodeDetector. The v7 module can rasterize a locally selected image via browser Image+FileReader when createImageBitmap is absent. It reports missing support, decoding failures, scan limits, and incomplete coverage explicitly, rather than marking an unscanned email safe.
8. **Supply chain**: jsQR is Apache-2.0 licensed and optional. A version-matched JS/License bundle is installed *only* when both artifacts match independently verified SHA-256 pins. `tools/verify-qr-vendor.py` checks bundled hashes and corresponding `index.html` script references. No dynamic CDN scripts or runtime requests are allowed.

## Reproducible evaluation

Required CSV fields: `label,text,split,group` (optional `language`).
- Labels must be manually verified **phishing/legitimate**, not merely spam/ham. Do not map unvalidated training labels to phishing.
- Split by campaign and registrable domain **before** threshold selection. Cross-split near duplicates can remain even with exact/group checks; manually investigate content clustering and temporal overlap.
- Never add externally downloaded corpora to the repository unless their license/privacy terms explicitly permit redistribution.
- For external data, record source DOI/URL, collection/access date, labeling procedure, sampling strategy, license and permitted use, class balance, geographic/language coverage, duplicates, and possible stale campaigns.

Commands:

```sh
cd phishing-email-analyser
node tools/benchmark-v7.js --dataset-kind synthetic \
 --input tests/fixtures/SYNTHETIC_SPLIT_RESEARCH.csv \
 --output docs/v7-synthetic-split-smoke.json
node tests/v7-evaluation-tests.js
python3 tools/verify-qr-vendor.py
python3 tools/verify-release-manifest.py
```

External study (on user's machine, once an appropriately labeled and permitted dataset is obtained):

```sh
node tools/benchmark-v7.js --dataset-kind external-labelled \
 --input /private/labelled-emails.csv --source 'verified DOI/URL' \
 --license 'verified license string' --collected 2026-10-13 \
 --output /private/cybersteps-real-world-results.json
```

Recommended public dataset starting points **for human verification**, not fetched or distributed here:
- [Zenodo: Phishing validation emails (Miltchev et al.)](https://doi.org/10.5281/zenodo.13474746), 2000 messages, mixture of real and generated; establish permitted terms and revalidate labels before use.
- [Zenodo: MeAJOR email assets](https://doi.org/10.5281/zenodo.18471483), preprocessed multi-source corpus; inspect which features/messages are actually present and licensing before converting to raw text.
- [PhishTank developer feed](https://phishtank.org/developer_info.php): verified phishing URLs, **positive examples only**; not enough alone to benchmark phishing-vs-legitimate emails.

### What the v7 synthetic smoke test means

The 20-case split smoke fixture includes 10 held-out examples and cannot establish 100% detection quality despite passing its simplistic cases. Its Wilson confidence bounds are very wide and are explicitly included. Calibration is refused. Actual real-world accuracy, improved false-positive rate, and multilingual generalization remain **unmeasured**.

## QR capability status

- Both decoding paths are local; no QR target URL is opened.
- Browser-native `BarcodeDetector` may scan multiple codes. The optional jsQR 1.4.0 fallback decodes at most **one** code in an image; GIF animation frames are not fully scanned.
- A compatible decoder is still required. The jsQR JS/library files are **not included in this release** because they could not be independently downloaded and authenticated in this execution environment. This limitation is intentional and must not be portrayed as universal cross-browser QR support.
- Installer accepts pinned internet artifacts **or** developer-provided local files (offline, paired with independently verified SHA-256 values). After installation, commit the decoder, Apache-2.0 license, JSON lock, HTML script tag and regenerated release manifest together.
- Some malformed/image-bomb data is rejected via a 3 MB source limit and 4096x4096 decoded-image limit; native decoder hangs are not fully preventable in synchronous browser APIs. Always test in target browsers.

## Release gates and remaining work

- Rerun original team and security suites; never delete old cases to make new cases pass.
- Validate release manifest from a freshly extracted final ZIP.
- Confirm GitHub Actions passes in the actual repository. Locally passing checks do **not** mean branch protection is active.
- Acquire an independently labeled dataset and report true positives/false positives, per-language precision/recall, confidence bounds, false-positive causes, and limitations.
- Independently verify and bundle the jsQR files if cross-browser no-network QR scanning is a course requirement.
