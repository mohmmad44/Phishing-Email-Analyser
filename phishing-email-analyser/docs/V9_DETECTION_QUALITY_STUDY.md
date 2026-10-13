# Cybersteps v9.0 — Detection quality and evidence-based investigation

## Scope, integrity, and objectives

This release builds on the team's v8.0 project and deliberately shifts the priority from test quantity to **missed malicious requests, nuisance false positives, and transparent evidence**. The team detection modules, offline CSP, phishing training, and original 104 tests are retained. The existing raw heuristic scoring formula is retained, except for a narrow safeguard: generic-only evidence without a high-specificity indicator cannot exceed Medium (44). This is **not probability calibration**.

## Why this matters

An email about password security can mention “share your PIN” without requesting a PIN. Previously, a blanket regex often failed to separate quoted policy advice from direct instructions. A phrase such as “macros” or “remote desktop” was also sufficient to produce a high-risk warning when it appeared in a benign glossary.

The upgrade separates **observations** (words, addresses, parsed hyperlinks) from **inferences** (the message probably attempts to deceive). It does not silently discard URL evidence, nor does it claim that metadata or sender authentication was independently checked.

## Changes

1. **Defensive-context and quotation handling.** English, German, French, and Spanish action requests have a local negation/educational-context gate. Prohibitions (“do not share”), conditional warnings (“if anyone asks ...”), and explicitly quoted training instructions are not treated as actionable requests. A subsequent direct instruction in another clause remains detectable. Such suppression is documented as contextualized evidence, not erased from the original input.
2. **Avoid scoring mere terminology as attacker action.** A bare mention of `macros`, `AnyDesk`, or `remote desktop` no longer triggers the same severity as instructions to enable macros or install remote-access software.
3. **Additional French/Spanish indicators.** Narrow, action-oriented detection for credential confirmation, account-lock threats, and urgent deadlines; avoid bare keywords wherever possible. They are heuristic rules, not complete French/Spanish language coverage.
4. **Payment rerouting combination.** An explicit transfer instruction together with changed banking details is distinct from a benign notice of changed invoice details. The rule still says verify independently, not confirmed fraud.
5. **Weak-only score cap.** When **no high-specificity evidence** is present, the displayed risk index is capped at 44 to prevent an accumulation of vague marketing/brand/urgency keywords from being labelled High. All original findings remain available and `scoreUncapped` is recorded. A direct secret request or a technically suspicious hostname overrides this safeguard. Note that high-specificity observations are still not verification of an attacker.
6. **Evidence-first UI and export.** The report explains whether it contains corroborated indicators, a specific indicator, or only weak indicators; which rule IDs support the concern; which apparent matches were contextualized; and what was not independently tested. Exports distinguish language heuristics, static artifacts, user-imported indicators, and untrusted header claims. All reported findings explicitly say `verified_malicious: false`.

## Controlled before/after comparison — not a real-world result

The `tests/fixtures/QUALITY_CHALLENGE_SYNTHETIC.json` development set contains **60 author-written examples** (30 legitimate, 30 phishing). Its contents influenced the changes. Therefore it is **not an independent test** and MUST NOT be used as proof of accuracy on real user emails. Comparisons use identical text and the same 45/100 High threshold in the original v8.0 engine and the modified v9.0 engine.

| Outcome | v8.0 | v9.0 |
|:--|--:|--:|
| True positives (phishing rated High/Critical) | 23 | 27 |
| False negatives (phishing rated Low/Medium) | 7 | 3 |
| False positives (legitimate rated High/Critical) | 5 | 0 |
| True negatives (legitimate rated Low/Medium) | 25 | 30 |
| Recall on challenge | 76.7% | 90.0% |
| False-positive rate on challenge | 16.7% | 0% |

**Observed 0/30 false positives is not a zero false-positive guarantee.** For independent Bernoulli samples, a two-sided Wilson 95% interval for the challenge false-positive rate extends to roughly 11.4%, even before accounting for synthetic author bias or campaign correlation. These figures are useful for regression diagnosis only.

Three intentionally difficult phishing scenarios still fall into Medium at threshold 45: `phish-otp` (direct code request without other evidence), `phish-callback` (telephone callback lure) and `phish-oauth` (device-code authorization lure). Their findings **are detected and shown for investigation**; the numerical threshold should not be misread as a safety clearance. Raising risk in the absence of corroborating evidence could raise false positives, so this remains a research tradeoff.

To reproduce (no network needed):

```sh
node tools/quality-audit.js --baseline docs/V9_V8_BASELINE_CASE_SCORES.json --output docs/V9_QUALITY_DEVELOPMENT_COMPARISON.json
node tests/v9-quality-tests.js
```

The original v8.0 case scores are included only to make changes auditable; no personal email content is included in that baseline file.

## How to establish genuine real-world detection reliability

**No independent, sufficiently representative labeled dataset was available for this build. Do not claim a measured real-world recall, precision, calibration or false-positive rate.** This release does not tune the production threshold on synthetic development examples.

1. Obtain properly licensed, independently labeled phishing and legitimate messages, record source and collection date, and check whether labels actually distinguish phishing from ordinary spam. Consider the [2024 Zenodo validation dataset](https://zenodo.org/records/13474746), noting it mixes real and synthetic messages, and [MeAJOR](https://zenodo.org/records/18471483), noting its anonymization may hide the exact URL/domain cues this analyzer needs.
2. Build **source/campaign-separated** validation and test cohorts with no duplicate or near-duplicate families across partitions. Record language, threat type, time period and proportion of legitimate messages.
3. Lock the detector version, rule weights and threshold before the held-out test. Run `tools/benchmark-v7.js` on an appropriately labeled CSV (`label,text,split,group,language`) and preserve the resulting source SHA-256; use a non-optimized holdout to report accuracy.
4. Report TP/FP/TN/FN, phishing recall, **false-positive rate with interval**, precision and the false discovery burden. Stratify by language and hard benign categories (legitimate invoices, helpdesk notices, training, banks). For sparse slices, mark insufficient sample size.
5. Have analysts manually review ALL test false positives and false negatives and classify reasons (benign urgency, quoted attack example, obfuscated URL, text-only phishing, damaged MIME, unknown language, document scan gaps). Report representative **redacted** evidence, not full personal messages.
6. Treat probabilities as unsupported until calibration is evaluated on enough independent labeled samples; the 0–100 UI index is heuristic. A non-match in an imported threat feed is NOT a clearance.

### Design cautions

- The defensive-context gate is a heuristic and could be exploited by an attacker who includes safety advice around a malicious request. Technical URL/link/attachment findings remain inspectable; the user must verify independently.
- Severity caps can cause missed attacks with weak or novel signals. The system returns an explicit investigation status and does not say “safe”.
- Supplied SPF/DKIM/DMARC headers are untrusted; there is no independent crypto validation.
- Static PDFs, Office archives, HTML and QR scans can be partial or unsupported. Incomplete coverage changes the report status to `incomplete`, not “Low risk is safe”.
- The qualitative explanation is not a causal proof or fully faithful attribution for every regex pattern; it reports known rule IDs and observable evidence.
- The URL decoder never navigates to links. A malformed URL or a newly invented phishing technique can evade these rules.

## Version notes

- Original 104 team regression checks remain unmodified.
- Added `tests/v9-quality-tests.js`, synthetic 60-case scenario fixture, and repeatable `tools/quality-audit.js`.
- No ML model, live APIs, surveillance, or extra runtime libraries were added.
- The build's SHA-256 release manifest must be regenerated after any source modification.
