# Cybersteps v10 — External Corpus Quality Evaluation

## What this phase does (and does not do)

This phase introduces a **repeatable, fixed-policy external-corpus evaluation** for the v9 detector. It measures false positives (legitimate messages incorrectly labeled High/Critical), phishing recall, precision, triage workload, and the effect of repeated message templates. It produces a privacy-aware JSON report and a human-readable Markdown summary.

**No independent corpus was downloaded in the build environment. No new real-world accuracy results are claimed.** No live detection rules, calibration, or deployed score thresholds have been changed. This is intentional: tuning on a validation/evaluation corpus without a separate holdout produces misleading improvements.

### Recommended public source (mixed origin)

[Miltchev, Rangelov & Genchev, *Phishing validation emails dataset* (2024), Zenodo DOI 10.5281/zenodo.13474746](https://zenodo.org/records/13474746)

- Original file: `Phishing_validation_emails.csv`, approximately 203 KB, 2,000 rows as described by the publishers.
- Expected publisher-listed MD5 checksum: `1bf8ec0fe3f67e12dd275ce5b2b91b69`. The CLI rejects mismatched files; it also records SHA-256 for repeatability. **MD5 here is a published file fingerprint, not a modern signature or authenticity proof.** Independently confirm the source and applicable use/redistribution terms.
- Labels are `Safe Email` and `Phishing Email`; input columns are `Email Text` and `Email Type`.
- **Dataset mixes real-world and AI/generated emails.** Individual example origin is not supplied. It is not suitable for claiming real-world email accuracy. Short templated messages often omit headers, links, sender information, and evidence needed by a forensic detector.
- The project does not redistribute this dataset. Download it using a browser on your own system after reviewing the source and any terms.

### Run the evaluation

Save the downloaded CSV outside Git, e.g. inside a new `evaluation_data/` directory (ignored by `.gitignore`). From `phishing-email-analyser/`:

```bash
node tools/public-corpus-evaluation.js \
  --input evaluation_data/Phishing_validation_emails.csv \
  --output evaluation_data/zenodo-v10-results.json

node tools/render-public-evaluation.js \
  --input evaluation_data/zenodo-v10-results.json \
  --output evaluation_data/zenodo-v10-summary.md
```

The default source identifier `zenodo-13474746` verifies the exact published MD5 fingerprint. If using a *different independently labeled email corpus*, specify `--source other` and preferably an independently checked `--expected-md5 <32-hex>`. Document its origin, date, consent/license, annotation methods and class definitions separately. **Do not map generic spam directly to phishing.**

### Report interpretation

The report contains:

- **Confusion matrix**: TP, FP, TN, FN at the already-deployed High/Critical threshold, 45/100.
- **Precision, recall, F1, specificity, false-positive rate** plus 95% Wilson bounds (which assume independent samples, an assumption often violated by templates).
- **Fixed threshold sweep** (20, 30, 40, 45, 50, 60, 70, 80) to show tradeoffs, **not** automatically choose a new production threshold.
- **Triage workload**: High/Critical, manual-review range (20–44), Low (below 20); Low is not a safety clearance.
- **Evidence-availability slices**: texts with visible URLs, full-header-looking messages, and text without visible URLs. The engine cannot infer what the source omitted.
- **Duplicate/template diagnostics**: normalized duplicate removal, conflicting-label exclusion, approximate template-family concentration and a template-median sensitivity comparison. Family grouping is approximate; it is not campaign attribution.
- **Privacy-limited error inspection**: rule IDs and SHA-256 identifiers (never raw message text or clickable URLs in exported reports). Even stable hashes can disclose low-entropy data; treat reports as restricted research artifacts.

### Independent external-study acceptance criteria

Before asserting an improvement in operational detection, obtain **separately sourced and independently labeled** evaluation data with sufficient benign corporate email and current phishing campaigns. Prefer separate studies for English, German, French and Spanish. Include invoices, routine IT notices, delivery updates, bank alerts and password reset notices in legitimate examples. Review label disagreements with qualified human annotators; avoid data leakage and campaign overlap.

Record version and time of the corpus, sampling methodology, prevalence assumptions, per-language confusion matrices, false-positive examples, coverage deficiencies, and false-negative attack classes. Pre-register thresholds on validation and evaluate final choices on a held-out test set. A high-performing result on the Zenodo mixed/template-heavy corpus is **not** evidence of production readiness.

### Verified locally

The new CLI and Markdown renderer are covered by `tests/v10-public-evaluation-tests.js`, including multiline CSV parsing, duplicate/conflict handling, corrupt-checksum refusal, non-export of raw message contents, and refusal to emit calibrated-probability claims. They are run in GitHub Actions along with all inherited team tests.
