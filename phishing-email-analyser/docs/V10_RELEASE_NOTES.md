# Cybersteps v10.0 — Evaluation readiness and auditability

## Objective

Advance the *quality* of the evidence supporting Cybersteps: quantify genuine phishing recall and legitimate-email false positives using externally sourced corpora, and make the analysis transparent without claiming synthetic regression counts equal operational accuracy.

## Implemented

1. **External CSV evaluator** (`tools/public-corpus-evaluation.js`). Supports the published schema and original-file checksum of the 2024 Zenodo Phishing Validation Emails collection, plus user-supplied labels with the verified `--source other` option. Performs no network requests.
2. **Honest evaluation policy**: fixes the detector's original High/Critical threshold at 45 rather than tuning it on the evaluation set. Provides a descriptive threshold sweep, explicit manual-review workload and false-positive/false-negative counts. It **does not** emit calibrated phishing probabilities.
3. **Quality-of-data diagnostics**: exact/normalized duplicate removal, conflicting-label exclusion, approximate template-family overlap, family-balanced sensitivity reporting, and evidence-availability slices; the original corpus may be a small set of repeated templates.
4. **Error attribution**: aggregated rule IDs associated with misclassifications and SHA-256 identifiers for a bounded number of cases. No raw message text, clickable URLs or attachments are written into result files by default.
5. **Evaluation summaries** (`tools/render-public-evaluation.js`): produces a reader-friendly Markdown report with uncertainty ranges, a confusion matrix, failure patterns and the conditions needed before making any deployment claim.
6. **Reproducible security checks**: 10 new tests, CI checks for the evaluator and Markdown renderer, and a verification guide. All inherited team functionality and static/offline browser protections remain unchanged.

## Not implemented or verified

- The 2,000-email external CSV is **not bundled and was not analyzed**, because downloading the source file into the execution environment was not possible. No new real-world precision, recall or false-positive rate is reported.
- The referenced Zenodo corpus contains a mixture of authentic and generated texts with unknown origin per item. Even after you run it, those results must be labeled *mixed-origin dataset findings*, not real-world operational accuracy.
- There are no new trained models, deployed calibration changes, domain live lookups, account integrations or production detection-rule changes. Using the independent evaluation data to optimize thresholds would invalidate an independent test; first obtain a separate validation set.
- QR decoding remains dependent on native browser support or locally verified decoder availability. No new claim of universal QR support.

## Validation and integration

`node tests/v10-public-evaluation-tests.js` checks parsing, checksum mismatch rejection, conflicting labels, approximate template duplicates and non-disclosure of raw email content. The inherited regression suites are still executed. `tools/build-release-manifest.py` and `tools/verify-release-manifest.py` enforce source integrity on the ZIP release.

For datasets and exact commands, read `docs/V10_EXTERNAL_QUALITY_EVALUATION.md`.
