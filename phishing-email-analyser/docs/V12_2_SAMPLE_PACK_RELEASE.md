# v12.2 — Synthetic Email Demonstration and Validation Pack

This release adds **48 sample `.eml` files** on top of Cybersteps v12.1, plus an automated fixture verifier and aggregate per-case report. The existing production analyzer, browser UI, phishing risk thresholds, and 104 original team tests are unchanged.

## Why these fixtures exist

The separately measured v12.1 public-corpus study contained only **100 unique messages** from 2,000 repeated CSV rows and lacked complete sender and destination context. That empirical finding must not be conflated with these richer educational MIME scenarios. This v12.2 pack supplies complete fictional messages to test difficult MIME and security-analysis paths, including legitimate security notices. It is **synthetic test engineering, not another real-world benchmark**.

## Implemented content

- 24 phishing-themed scenarios (EN, DE, FR, ES), including account and bank spoofing, Unicode/Punycode-style spoofing, HTML link mismatches, multi-hop redirect strings, base64/quoted-printable, CEO fraud, OAuth and MFA prompts, an inline QR attachment, and static PDF/DOCX links.
- 18 legitimate business/security examples covering billing, receipts, anti-phishing guidance, training, office notices, and real MIME attachments, including a benign QR image.
- 6 **ambiguous** messages that warrant independently verifying claims, but are not labeled malicious.
- `cases.json` with individual SHA-256 hashes, expected MIME source, expected attachment counts, expected selected technical findings, and explanatory labels.
- `tools/generate-example-emls.py` for deterministic offline fixture creation and `tools/evaluate-example-emls.js` + `tests/example-eml-validation-tests.js` to parse, run and inspect results.
- `examples/eml/VALIDATION_RESULTS.md` and `docs/V12_2_EML_SYNTHETIC_VALIDATION.json`, which record **observed results** with clearly labeled shortcomings.

## Frozen baseline observations

At High-risk threshold 45/100 on the **author-created synthetic pack**:

- 20 of 24 fictional phishing cases produce a High/Critical score.
- 0 of 18 fictional legitimate cases produce a High/Critical score.
- 6 of 6 review-only cases have an independent-verification cue.
- `P04`, `P18`, `P23` and `P24` are below High. These are visible gaps, not recoded as successful phishing detections.

These are small, intentionally chosen development examples. **Do not quote the ratios as real-world precision, recall or false-positive rates.** Repeated testing and manual selection make them unsuitable for independent evaluation. Some detections require browser QR capabilities; the Node fixture verifier does not raster-decode QR images.

## Automated verification

Run `node tests/example-eml-validation-tests.js` from the application directory. CI now includes that command, in addition to all inherited tests. The release manifest includes every new example's content fingerprint, so missing or line-ending-corrupted samples fail verification.

## Safety and privacy

All messages use fictitious people, addresses, links and account actions. No external URLs are fetched, QR links are not opened, and attachments are parsed statically. The original real validation CSV and its private case-review material are excluded from the release.
