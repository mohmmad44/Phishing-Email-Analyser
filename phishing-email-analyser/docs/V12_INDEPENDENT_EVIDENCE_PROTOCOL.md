# Cybersteps v12 — Evidence-first external evaluation protocol

## Objective and scope

This phase follows v11 rather than replacing its rule engine. It delivers **repeatable evidence collection** for (1) how many labeled phishing messages the application rates High/Critical, (2) how many legitimate messages are incorrectly rated High/Critical, and (3) *which exact cases* deserve a private investigator review. A heuristic `0–100` risk index is **not** a probability that an email is phishing, and no threshold, weights, or browser behavior are changed by these research tools.

**As of this release no external corpus has actually been executed in this environment.** Direct HTTPS retrieval of the 2024 Zenodo dataset failed with a network/DNS error. The included release contains the evaluator, download/verification helper, documentation, and synthetic unit tests—not invented precision, recall, or false-positive figures. The previous 60-message synthetic study remains development evidence only.

## Dataset source and restrictions

Suggested initial audit: [Miltchev, Rangelov and Genchev, *Phishing validation emails dataset* (2024), Zenodo DOI 10.5281/zenodo.13474746](https://zenodo.org/records/13474746). The published CSV is about 203 kB and has 2,000 messages with `Email Text` and `Email Type` fields. Published MD5 is `1bf8ec0fe3f67e12dd275ce5b2b91b69`. The authors say the messages are a **mixture of real and artificially generated emails** without a trustworthy, per-message provenance field. It cannot establish purely real-world, current operational performance, even if all rows are scored. Investigate its redistribution/license terms before sharing any bytes, and do not distribute this CSV inside the repository.

From a computer with access:

```bash
cd phishing-email-analyser
python3 tools/fetch-zenodo-validation.py
# If download fails, download the original CSV in a browser directly from Zenodo,
# save at evaluation_data/Phishing_validation_emails.csv and check the MD5.
node tools/public-corpus-evaluation.js \
  --input evaluation_data/Phishing_validation_emails.csv \
  --source zenodo-13474746 \
  --output evaluation_data/zenodo-exploratory.json
node tools/render-public-evaluation.js \
  --input evaluation_data/zenodo-exploratory.json \
  --output evaluation_data/zenodo-exploratory.md
```

These commands produce a **mixed-provenance exploratory benchmark only**, not a test of current real-world deployment accuracy.

## Independent validation and test process

Use two **separately sourced**, legally usable, independently reviewed phishing-vs-legitimate datasets, ideally including real recent phishing and genuine operational mail. Do not relabel ordinary spam as phishing. Each source may be a mixture of verified phishing and verified legitimate messages, but **validation and test should not share campaigns, templates, organizations, or original message bodies**. Keep data collection and labeling provenance, date, locale, category and analyst verification in an internal study log. For email security, realistic false positives require real *ham* such as security notices, receipts, invoices and legitimate links. Enron/SpamAssassin historical ham is useful for limited comparisons but should not be presented as current German corporate mail.

The scripts accept UTF-8 CSV with `text,label,group,language` (or `Email Text,Email Type`). `label` must be explicitly `phishing` or `legitimate` (or the original Zenodo labels); `group` should be a consistent campaign identifier when available; missing `group` falls back to conservative near-template fingerprinting. `language` is optional. Use a unique label such as `validation-research-2026` to describe your verified source collection, **not** a placeholder named `real-world` without evidence.

**Stage 1 — validation only** (fix a research threshold, without looking at test labels):

```bash
node tools/v12-evidence-study.js \
  --stage validation \
  --input evaluation_data/independently_reviewed_validation.csv \
  --source validated-research-corpus-A \
  --license 'verified permitted research use' \
  --collected 2026-10-13 \
  --dataset-kind externally-labeled --labels-reviewed yes \
  --max-fpr 0.05 --min-recall 0.60 --min-class 100 \
  --policy evaluation_data/v12-private-frozen-policy.json \
  --output evaluation_data/v12-validation-results.json \
  --private-review evaluation_data/v12-validation-errors.private.json
```

If either label has fewer than 100 examples, the policy stays at **45**; the minimum class size is a guardrail, **not proof of representativeness**. Otherwise candidate thresholds must satisfy the **95% Wilson upper bound** on the validation false-positive rate and the minimum recall target. This is exploratory; it is not a validated operational model. Check the threshold choice before proceeding. Keep the policy JSON private: it includes a secret used for HMAC duplicate and template-overlap checks.

**Stage 2 — lock threshold, test separately** (requires a different declared dataset source):

```bash
node tools/v12-evidence-study.js \
  --stage test \
  --input evaluation_data/independently_reviewed_test.csv \
  --source independently-reviewed-corpus-B \
  --license 'verified permitted research use' \
  --collected 2026-10-13 \
  --dataset-kind externally-labeled --labels-reviewed yes \
  --policy evaluation_data/v12-private-frozen-policy.json \
  --output evaluation_data/v12-test-results.json \
  --private-review evaluation_data/v12-test-errors.private.json
node tools/v12-render-study.js \
  --input evaluation_data/v12-test-results.json \
  --output evaluation_data/v12-test-report.md
```

These second-stage commands **reject** exact text overlap, conservative approximate-template overlap, and any identical declared campaign ID across the two sources. Review the source/label rules if legitimate boilerplate causes an overlap. Do not relax overlap controls solely to improve measured metrics. If evaluation reveals a flaw, correct it using the *validation* source; then gather a new, previously untouched test source to remeasure the candidate. Repeated optimization on the same test corpus turns it into development data.

## What the confusion matrix means

| Actual label | Predicted High/Critical | Below High threshold |
|---|---|---|
| Phishing | **TP** — detected | **FN** — missed by High-risk verdict |
| Legitimate | **FP** — false alarm | **TN** — correctly below High |

- **Recall** = TP / (TP+FN), sensitivity to labeled phishing.
- **False-positive rate** = FP / (FP+TN), how often legitimate messages are unnecessarily flagged High/Critical.
- **Precision** = TP / (TP+FP), heavily affected by phishing prevalence, dataset composition and label quality.
- Wilson 95% intervals communicate sampling uncertainty **but assume independent cases**; correlated attacks/campaigns effectively reduce sample size.
- **Independent verification queue** is reported separately and never counted as an automatic phishing verdict.
- Report per-language and per-category metrics only where independently labeled fields are available, with sample counts.

## Private error investigation

The `--private-review` file contains up to 25 example false positives and false negatives with approximate defanged excerpts, scores and active rule IDs. It has restrictive local file permissions and goes under `evaluation_data/`, which `.gitignore` excludes. **This file still contains sensitive email text; keep it private, manually redact before sharing, and never commit it.** Use it to classify underlying failure modes such as benign security-awareness language, missing original URLs, generic parcel requests, malicious-looking yet legitimate subdomains, excessive weight accumulation, spoofed sender identifiers, or truncated/redacted context. Fix rules only using development/validation evidence; leave the held-out test untouched.

## Data-integrity and security conditions

- The downloader uses HTTPS and verifies the **published MD5**. MD5 here is a release fingerprint supplied by Zenodo, **not** a tamper-proof source signature. When available, pin an independently recorded SHA-256 as well.
- The tool uses the existing offline JavaScript analyzer; it **does not visit** embedded links or contact reputation services.
- All examples remain local. Aggregate reports exclude email bodies and individual message hashes.
- Both corpus loaders reject malformed CSV and contradictory duplicate labels and enforce file/row/message size bounds.
- Source names, license strings and `--labels-reviewed yes` are **user declarations, not cryptographic attestations or independent proof**.
- A selected threshold is output to the **private research policy only**; it does not modify `js/analyser.js` or any deployed application behavior.
- CI runs only synthetic behavior tests, **never** licensed external data or private policy artifacts.

## Current status and next requirement

| Milestone | Status |
|---|---|
| v11 runtime scoring and original team behavior preserved | Implemented; verify with inherited suites |
| Real corpus acquisition helper with published file fingerprint | Implemented, but download not executed here |
| Exploratory published mixed-real/generated benchmark | Runnable; **not run on full original CSV here** |
| Independent validation vs held-out test with overlap rejection | Implemented; verified on synthetic fixtures |
| Confusion matrix, precision/recall/FPR/Wilson intervals | Implemented; real values still pending |
| Local-only false positive/negative case review | Implemented; real cases still pending |
| New production score calibration | **Not authorized** pending valid, independent evidence |

Success means a documented, reproducible comparison on *authentic* independently labeled data, with the operational cost of false positives and the uncertainty of every claim made clear. A large test count is a regression signal, not phishing-detection accuracy.
