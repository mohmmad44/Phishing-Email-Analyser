# Cybersteps v6.0 — Advanced Identity-Phishing Investigation

## Baseline and compatibility

This release starts from **the previously integrated team's v5.1 final ZIP**, not from the old student prototype. 48 existing files remain byte-for-byte unchanged; intentionally changed files and new files are listed with hashes in `V6_FILE_PROVENANCE.json`. All 104 team tests still pass, as do the previously integrated specialist suites.

## Fully implemented in v6

- `js/oauth-security.js`: contextual OAuth/device-code lures, application-consent permission requests and unexpected MFA approval requests with benign-message suppression.
- `js/threat-feed.js`: bounded, opt-in, browser-local IOC JSON import and **exact match** with expiration and provenance warnings; **not a live reputation service**.
- `js/investigation-report.js`: bounded, structured JSON investigation export; it labels the existing risk score a heuristic and does not export the original message body.
- `tools/benchmark-audit.js`: a reproducible audit for genuinely labeled `phishing`/`legitimate` corpora. Precision/recall/F1/FPR, per-language slices, confidence bounds, threshold sensitivity and explicit train/test group overlap diagnostics.
- `tests/v6-security-tests.js`: 63 verification cases, including legitimate examples, attack cues, imported-feed validation, and controlled mutations.
- GitHub Actions CI includes the new tests and dataset audit. No additional runtime networking or secrets required.

## Evaluated scenarios

See `v6-synthetic-comparison.json` and `v6-synthetic-audit.json`. The 20-case synthetic fixture produces TP=9, TN=10, FP=0, FN=1 at the original 45-point threshold; **it is not an external phishing corpus**, and no real-world performance claim follows. The illustrative v5.1→v6.0 comparison shows an OAuth device-code scenario moving from score 12 to 41 and a benign description remaining at 10. These are handcrafted, nonrepresentative examples.

## Outstanding items and hard limitations

1. **Real-world validation**: A public dataset could not be downloaded/verified in this execution environment. Do not claim improvements to recall or false-positive rate until independently sourced, labeled and licensed data is used; avoid selecting thresholds on the test data.
2. **Calibration**: It is impossible to calibrate probabilities without representative labeled data. This release preserves the existing **heuristic index** and makes its interpretation explicit. The threshold sweep is for diagnostics only.
3. **Offline QR fallback**: Native QR scanning works only in supported browsers. The jsQR vendor script requires independently verified SHA-256 pins; a verified library was not available for bundling. The app reports unsupported functionality transparently.
4. **Live intelligence**: No Safe Browsing/PhishTank/API lookups, since those require opt-in, accepted provider terms, privacy design and possibly secrets or a server intermediary. Only local feed enrichment is implemented.
5. **Static attachment/MIME parsing**: The team's existing safeguards are unchanged. This app does not execute or sandbox attachments.
6. **DevSecOps**: CI configuration is local and unverified on an actual GitHub pull request; configure required status checks and verify host security headers after deployment.

## Recommended reproducible commands

```bash
cd phishing-email-analyser
node tests/run-tests.js
node tests/v6-security-tests.js
node tests/deployment-policy-tests.js
node tools/benchmark-audit.js --input tests/fixtures/SYNTHETIC_LABELLED_URLS.csv --dataset-kind synthetic
python3 tools/verify-release-manifest.py
```

The browser smoke test uses a controlled Chromium harness that loads only local assets and checks the new feature flow. It is **not** a remote deployment or a penetration test.

## References

- [Microsoft (April 2026): AI-enabled device-code phishing](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/)
- [Microsoft (September 2026): EvilTokens device-code phishing analysis](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)
- [Google Safe Browsing v5 documentation](https://developers.google.com/safe-browsing/reference)
