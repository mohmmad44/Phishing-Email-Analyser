# Cybersteps v11.0 — Evidence-Calibrated Decision Support (not probability calibration)

**Base:** The team's merged v10.0 application. Existing risk-scoring weights and High/Critical threshold remain unchanged.

## New

- `js/verification-context.js`: six bounded context/action cues for under-evidenced requests; **zero risk-weight contribution**.
- `js/analyser.js`: `assessment.triageDecision`, `assessment.actionCues` and `assessment.recommendedAction`.
- `js/app.js`: visible independent-verification outcome; no misleading "No warning signs" headline when a low-scoring message has actionable cues.
- `js/investigation-report.js`: structured export separates review routing from evidence-backed phishing findings.
- `tools/public-corpus-evaluation.js`: optional independently sourced SHA-256 input-file pinning (in addition to the existing publisher MD5 fingerprint).
- `tools/public-corpus-evaluation.js` and `tools/render-public-evaluation.js`: human-review workload and capture metrics displayed **separately** from the classifier's confusion matrix/false-positive rate.
- `tests/v11-verification-quality-tests.js`: targeted positive/negative tests and non-regression checks, included in GitHub Actions.

## Evidence limitations

No full independent real-world dataset was downloaded, validated or measured during this build. The scoring engine has **not** been calibrated against phishing probabilities, and the review queue is not a phishing verdict. All operational accuracy claims must await a held-out labeled corpus. Read `docs/V11_DECISION_QUALITY_STUDY.md`.

## How to run

Open `index.html` locally. The new triage text appears under **Evidence & uncertainty** when an action request warrants verification. Execute `node tests/v11-verification-quality-tests.js` and the inherited suites. The project remains offline at runtime.
