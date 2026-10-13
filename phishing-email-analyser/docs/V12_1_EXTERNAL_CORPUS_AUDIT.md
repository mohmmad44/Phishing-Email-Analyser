# Cybersteps v12.1 — Exploratory External Corpus Audit

**Evaluation date:** 13 October 2026  
**Source:** [Miltchev, Rangelov & Genchev, *Phishing validation emails dataset*, Zenodo (2024)](https://zenodo.org/records/13474746), DOI `10.5281/zenodo.13474746`.  
**Input file:** `Phishing_validation_emails.csv` (provided separately by the project user). Original dataset MD5 `1bf8ec0fe3f67e12dd275ce5b2b91b69` and SHA-256 `ad15f63cb8db2caaee33c442f1ff4488b9444530a4c42ab63bb580016b160bd3` match the expected/source record fingerprint. **Dataset bytes are excluded** from this project package.

## Executive conclusion

Cybersteps v12 was run with its **existing** static email analyzer and **unchanged High/Critical threshold 45/100**, without training or threshold selection on this dataset. At the distinct-message level, the analyzer classified **5 of 23 phishing-labeled messages as High/Critical** while flagging **0 of 77 safe-labeled messages** as High/Critical. These figures are **not real-world accuracy estimates** because the provided dataset has heavy duplication, uncertain real-versus-generated provenance, limited technical evidence, and unreviewed label quality.

## Dataset quality and provenance

| Diagnostic | Finding |
|---|---:|
| Raw dataset rows | **2,000** |
| Raw phishing-labeled / safe-labeled rows | 1,000 / 1,000 |
| Canonical exact duplicate rows removed | **1,900** |
| Distinct messages evaluated | **100** |
| Distinct phishing-labeled / safe-labeled | **23 / 77** |
| Approximate repeated template families | **21** |
| Fraction of distinct messages in ten largest families | **89.0%** |
| Distinct messages with actual web URLs | **0 / 100** |
| Full mail headers or attached binary files | **Not supplied** |

Names and currency amounts change within repeated templates. Large numbers of copies of the same email do not constitute independent confirmation of detection performance. The source notes that its emails mix real and artificially generated texts; there is no per-record provenance field. Some supposedly phishing-labeled samples are generic account/billing notices which cannot be independently classified as malicious from the supplied text alone.

## Fixed-threshold confusion matrix: score ≥ 45 = High/Critical

| Actual dataset label | Cybersteps High/Critical | Below High | Total |
|---|---:|---:|---:|
| Phishing | **5** TP | **18** FN | 23 |
| Safe | **0** FP | **77** TN | 77 |

- **Dataset-labeled phishing recall:** 21.7% (5/23); approximate Wilson 95% interval **9.7–41.9%**.
- **Observed legitimate-message false-positive rate:** 0.0% (0/77); approximate Wilson 95% upper bound **4.8%**.
- **Observed precision:** 100.0% (5/5); approximate Wilson 95% interval **56.6–100%**. Five High-risk positives cannot establish robust precision.
- **F1 score:** 0.357. F1 and precision depend on corpus composition.

**Sampling caveat:** Even after exact deduplication, repeated templates remain and labels have not been independently audited. The quoted Wilson intervals assume independent observations and can overstate certainty.

## Error review: reasons behind missed labels

The 18 phishing-labeled examples rated below 45 fall into four observable categories (counts of distinct texts, not raw rows):

| Missed pattern | Count | Typical score | Interpretive limitation |
|---|---:|---:|---|
| Near-identical account-compromise/reset instructions with different greetings | **10** | 20 | Urgency is recognized, but there is no real link or sender to establish impersonation |
| Generic parcel, billing, subscription or account-settings instructions | **4** | 0 | Such text may be legitimate; external context is absent |
| Unusual-login/activity alerts or overdue-invoice warning | **3** | 24 | Threat cues are detected but not sufficient on their own for High |
| Secure bank-message “click here” lure | **1** | 14 | A generic click instruction is detected without a destination to verify |
| **Total** | **18** | | |

There were **no false-positive High/Critical verdicts among the 77 distinct safe-labeled texts**. This is a narrow observation and should not be generalized to normal IT notices, authentic invoices, or German business email without representative additional samples.

## Separate independent-verification queue

Cybersteps v11/v12 can recommend independent verification without assigning a High-risk phishing verdict. On these distinct messages, **6** phishing-labeled texts triggered this separate advice. Combined with the five High/Critical results, **11/23** phishing-labeled texts were sent to either High/Critical or explicit independent verification; **0/77** safe-labeled texts met either of these two criteria. This is a *manual-review routing statistic*, **not** phishing classification recall or confirmed maliciousness.

Separately, **13** of the 18 missed High/Critical phishing-labeled examples received Medium scores (20–44). Including every Medium case in a general review queue is a separate, broader triage policy with different workload implications.

## Why this evaluation does not justify changing the production threshold

The bundled evaluator shows that lowering the cutoff on this corpus would change which short messages are classified as High, but the corpus contains no real URLs or sender metadata and has just 21 approximate text families. Changing policy based on this same corpus would train on the evaluation set. In particular, **do not lower the threshold to 20 solely because it detects more repeated password-reset templates**: the system could then flag authentic IT/security notices in real use.

This was an **external exploratory audit**, not an independent validation-plus-test experiment. Production risk scoring, model probability claims, QR/Office coverage, and the GitHub Actions workflow remain unchanged.

## Reproduce using the original dataset (kept outside Git)

From the `phishing-email-analyser` directory:

```bash
node tools/public-corpus-evaluation.js \
  --input evaluation_data/Phishing_validation_emails.csv \
  --source zenodo-13474746 \
  --output evaluation_data/zenodo_audit.json
node tools/render-public-evaluation.js \
  --input evaluation_data/zenodo_audit.json \
  --output evaluation_data/zenodo_audit.md
```

The tool verifies the source MD5 and outputs aggregated findings without raw email content. Private error-review files from `v12-evidence-study.js` must remain uncommitted and access-restricted. The source CSV is intentionally **not packaged** into this release.

## Next defensible scientific milestone

1. Curate diverse, fully formed **phishing** messages and genuine **legitimate** emails (including German invoices, notifications, IT security mail, and business correspondence), with source, label, date, language and attack-category provenance.
2. Independently adjudicate ambiguous examples, including screenshots / redacted headers when needed; exclude ordinary spam that lacks phishing behavior.
3. Select any candidate detection changes on a designated validation corpus only. Lock the scoring policy, then evaluate it **once** on a **different, held-out corpus** with campaign/template separation.
4. Report per-language recall, precision, false-positive rate, human-review volume, confidence intervals, and error taxonomy; show which evidence was absent in each case.

**Bottom line:** This dataset reveals a measurable gap between a High-risk verdict and merely suggestive, short phishing-labeled text. It does *not* show that Cybersteps would miss 78% of actual phishing emails in normal operation. A more representative evaluation is needed before reporting that kind of claim.
