# Cybersteps v11.0 — decision-quality and abstention study

## Scope and non-claims

This release extends the *team final v10.0* without overwriting its scoring policy, threshold, language rules, document parsing, or originally authored tests. It addresses a specific research problem: **a phishing lure can demand a risky action while providing no checkable technical evidence**. Many short text-only emails do not contain a sender, full URL or headers. Marking them as definitely phishing is not justified; marking them "safe" on a Low score is equally misleading.

### Three distinct outputs

1. **Risk level** (`Low`, `Medium`, `High`, `Critical`): existing rule-weighted heuristic at existing threshold 45. Unchanged in v11, not a calibrated probability.
2. **Independent verification recommended**: an action request was identified in a limited-context email. **Not** a new positive phishing prediction; no score is added.
3. **Coverage/evidence**: original static-artifact checks, trusted/untrusted claims, and incomplete processing are still reported separately.

This is a *selective/abstaining* decision-support approach rather than a new classification model. It is designed to reduce false reassurance, not to boost an accuracy figure by relabeling review cases as attacks. No result indicates live link reputation, sender signature validation, or malware execution.

## New cues and safeguards

`js/verification-context.js` performs **bounded, offline, deterministic, context-plus-action detection** on six cases: account-security verification instructions, declined-payment billing updates, parcel personal-data requests, account-setting updates to avert interruption, bank "secure message" click-throughs and subscription renewal prompts. It uses short clause windows and ignores plainly negated/training instructions or independently verified official-app navigation guidance. All extracted cues are advisory and **zero weight**.

The user-visible report has a separate actionable triage statement and recommends contacting the sender by an independently obtained number, known app, or manually entered domain. It does not say the company or request is fraudulent without supporting evidence. `js/investigation-report.js` includes the decision, cue IDs and uncertainty in a JSON export.

The corpus evaluator `tools/public-corpus-evaluation.js` retains its **fixed, pre-existing 45-point threshold** and separately reports the coverage and benign-message review burden of the verification queue. Neither the evaluation nor new cues optimize the model threshold. Queue capture must **not** be reported as phishing precision or classifier recall.

## Qualitative case study — NOT independent accuracy evidence

Examples excerpted/closely modeled from published short-message validation scenarios may contain no sender, URL destination or attachment. The old detector can assign Low risk to "Payment declined; update billing" or "delivery pending; provide personal details" without access to the actual destination. Under v11 these scenarios can produce `independent-verification-recommended`, while their risk scores remain unchanged. Conversely, receipts, payment statements with no requested data collection, regular project reports, legitimate security warnings and explicit security-awareness instructions do not trigger these *specific action cues* in the tested cases. A non-trigger does not establish safety.

19 targeted engineering tests include six action cues, eight benign/educational negatives, voice-mode isolation, unchanged numerical scores, export consistency, bounded inputs, a UI message, and a synthetic evaluator/renderer smoke test. The inherited team's original 104 tests are also retained.

**No independent labeled real-world corpus was run here.** The published Zenodo 13474746 dataset is openly described as a mix of real and generated messages (unknown per-record origin), and exhibits repeated short-text templates. Its published CSV could not be downloaded by the build environment. Consequently, this release offers no new operational precision, false-positive-rate, phishing-recall, or probability-calibration claim.

## Operational evaluation protocol

1. Freeze v10 (baseline) and v11 in separate version-controlled checkouts. Do not modify the detection threshold between evaluations.
2. Obtain independently sourced and *licensed* benign operational emails and real phishing messages, preferably as complete `.eml` files with headers. Obtain independent human labels, class definitions and timestamps. Filter private information before publication.
3. Isolate phishing campaigns, message templates, sender domains and time periods between development and held-out evaluation. Record duplicates and class provenance.
4. Run the unmodified v10 and v11 detectors on exactly the same held-out messages. Report **High/Critical classifier** precision, recall and benign false-positive rate separately from **manual-review queue capture and queue burden**.
5. Include missing URL/header/attachment coverage, language-specific strata (German/English and others), PDF/image attachments, authorization phishing, and business invoice/IT security negative controls.
6. Evaluate useful operational burden: at 1,000 legitimate emails, how many are escalated to High and how many merely require manual verification? Estimate this on real data, never infer from a balanced or synthetic set.
7. Audit samples where classification and verification disagree. Publish aggregate metrics with uncertainty intervals, provenance and selection biases. Never infer individual maliciousness from prevalence estimates or phishing-like phrases alone.

## Reproducible evaluation (published mixed-origin dataset)

The v10 workflow supports `Phishing_validation_emails.csv` from <https://zenodo.org/records/13474746>. The source file must be downloaded independently into the gitignored `evaluation_data` directory; the source MD5 is verified against the publisher listing (as a file fingerprint, **not** as an authenticity signature). From `phishing-email-analyser/`:

```sh
node tools/public-corpus-evaluation.js --input evaluation_data/Phishing_validation_emails.csv --output evaluation_data/v11-zenodo-results.json
node tools/render-public-evaluation.js --input evaluation_data/v11-zenodo-results.json --output evaluation_data/v11-zenodo-report.md
```

For any different user-provided dataset, use `--source other --expected-sha256 <independently-verified-64-hex-hash>`, verify its provenance, and confirm its labels mean phishing rather than generic spam. The optional SHA-256 pin is only a fingerprint match, not source authenticity proof. This mixed-origin dataset is **not a substitute** for a real-world field study.

## Remaining limitations

- Contextual detection is English-forward with a small selection of German phrases; no exhaustive language model or discourse analysis.
- Clause/window heuristics can miss obfuscated, indirect, quoted or multi-step social engineering. They can also recommend verification for a perfectly legitimate account alert; this is intended *review burden*, not a false positive malicious verdict.
- The exact malicious destination behind "click here" cannot be established without an actual link. No web requests occur.
- The published short-message corpus is templated and may lack the artifacts this detector specializes in; absolute metrics will be biased by missing evidence.
- Real-world probability calibration, independent external dataset study, and verified cross-browser QR dependency remain future work.
