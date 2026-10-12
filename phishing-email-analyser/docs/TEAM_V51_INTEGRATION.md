# v5.1 integration into the final team release

## Source of truth and preservation

The user-supplied `Phishing-Email-Analyser-main.zip` is **the authoritative final team project**, not the earlier `Phishing-Email-Analyzer-Cybersteps-main.zip` used when v5.1 was originally assembled. A file-level SHA-256 record for all **17** team files is shipped in `TEAM_BASELINE_PROVENANCE.json`.

The team's final version already added important features not present in the earlier baseline: **104 tests rather than 94**, German-language rules with explicit `-de` IDs, mixed-script detection, and a multipart MIME parser retaining **both text/plain and text/html** content. A wholesale v5.1 overwrite would have silently removed some of this work; this release deliberately does not do that.

## Exactly what was merged

The team files were copied first. Only the following shared application files were integrated with v5.1 enhancements: `index.html`, `js/analyser.js`, `js/app.js`, `js/core.js`, `js/dashboard.js`, `js/eml.js`, `js/rules.js`, plus the test-runner's security-module imports. The original team user guide in `phishing-email-analyser/README.md` is retained and appended with an integration note; the short root README is repaired and expanded. All other team-authored files remain byte-for-byte unchanged.

**Team-specific compatibility fixes:**

- The original 104-case `tests/run-tests.js` is used (with only the module imports added), instead of v5.1's older 94-case test runner.
- `parseEml()` retains content from both plain and HTML MIME parts, and also returns original HTML source for static security analysis.
- Original team German-specific `-de` rule IDs and explanations remain. Where the enhanced cross-language rules score the same signal, the `-de` compatibility findings have zero additional scoring weight to avoid double-counting. The German generic greeting retains its standalone score.
- The original `sender-mixed-script` finding ID remains available as informational evidence, with risk weight assigned by the enhanced `sender-unicode-mixed-script` detection.
- Original site CSP and deployment `_headers` remain; v5.1 adds modules/scripts without enabling remote calls.

## Added v5.1 security components

Domain impersonation, Unicode/IDN decoding and confusable checks, bundled Public Suffix List snapshot, nested redirect parameter analysis, static HTML link/form analysis, optional local QR scan with MIME image extraction, defensive input limits, MIME-paste decoding, English/German negation-aware heuristics, release-manifest hashing, GitHub Actions, deterministic fuzz/property checks, and a synthetic benchmark harness.

### Security limits

- A domain resemblance is an **investigation clue**, not verified maliciousness. The Unicode confusable mapping is partial and is not complete UTS #39 conformance.
- Embedded redirect destinations are decoded statically; servers are not contacted and the analyzer does not prove a redirect will execute.
- QR scanning requires browser `BarcodeDetector` or an independently vetted, locally installed decoder. The optional installer fails closed without explicitly supplied trusted digests.
- SPF/DKIM/DMARC are **claims extracted from supplied headers**, not independently cryptographically verified.
- The synthetic 20-sample benchmark tests evaluation plumbing. It is not a representative phishing accuracy evaluation.
- The `_headers` file's `frame-ancestors 'none'` works only with hosts that send those HTTP response headers. GitHub Pages ignores `_headers`.

## How to validate the merged contribution

From the repository root:

```sh
cd phishing-email-analyser
node tests/run-tests.js
node tests/domain-security-tests.js
node tests/url-security-tests.js
node tests/advanced-security-tests.js
node tests/release-hardening-tests.js
node tests/secure-property-tests.js
node tests/adversarial-tests.js
node tests/deployment-policy-tests.js
node tests/merge-review-tests.js
node tools/benchmark.js --input tests/fixtures/SYNTHETIC_LABELLED_URLS.csv --output docs/synthetic-benchmark-result.json --dataset-kind synthetic
python3 tools/verify-release-manifest.py
```

The 104 original team tests remain critical merge criteria; do not replace this test file with the 94-case v5.1 one. After modifying any tracked file, run `python3 phishing-email-analyser/tools/build-release-manifest.py` from the repository root (or invoke using its absolute path), then verify and commit the new manifest. Run CI on GitHub before merging; a local test run does not verify the remote workflow.

## Git and ownership

Use this ZIP's **contents**, including `.github/`, `.gitattributes`, and `.gitignore`, at the repository root, without replacing the repository's own `.git` directory. Review `git diff` before committing. Do not include the project or generated `docs/browser-preview.png` in a separate user-supplied baseline revision without discussion; it is a test artifact from a controlled browser harness, not proof of production deployment.

## SHA-256 preservation audit

The files listed below are byte-for-byte unchanged from the final team ZIP:

- `phishing-email-analyser/_headers`
- `phishing-email-analyser/css/styles.css`
- `phishing-email-analyser/js/content.js`
- `phishing-email-analyser/js/guidance.js`
- `phishing-email-analyser/js/learn.js`
- `phishing-email-analyser/tools/build-preview.py`
- `test-phishing-sample.eml`

The following team files intentionally differ because the v5.1 integration adds behavior or corrects documentation:

- `README.md`
- `phishing-email-analyser/README.md`
- `phishing-email-analyser/index.html`
- `phishing-email-analyser/js/analyser.js`
- `phishing-email-analyser/js/app.js`
- `phishing-email-analyser/js/core.js`
- `phishing-email-analyser/js/dashboard.js`
- `phishing-email-analyser/js/eml.js`
- `phishing-email-analyser/js/rules.js`
- `phishing-email-analyser/tests/run-tests.js`
