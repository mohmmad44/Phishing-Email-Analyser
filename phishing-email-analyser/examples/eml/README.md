# Cybersteps — 48 example `.eml` messages for validation

All 48 messages are **fictional, explicitly constructed educational examples**, not collected from anyone's inbox. They do **not** establish real-world phishing accuracy or legitimate-email false-positive rates. They are suitable for demonstrations, exploratory regression testing, and exercises comparing a rule's observed output with its intended behavior. All spoofed destinations use reserved `.example` documentation domains or invented code values; no provided link should be opened. Some trusted domains appear solely as reference text, not as phishing endpoints.

## Directory structure

| Folder | Count | Meaning |
| --- | ---: | --- |
| `01_phishing/` | 24 | Simulated attacks: impersonation, German/French/Spanish lures, Unicode homoglyphs, redirects, HTML deception, QR, PDF/Office links, OAuth/MFA, and payment diversion. |
| `02_legitimate/` | 18 | Everyday mail: invoices, receipts, internal IT announcements, anti-phishing warnings, newsletters, normal attachments, and event QR codes. |
| `03_manual_review/` | 6 | Incomplete, ambiguous account/payment/parcel notices; intended for independent verification, **not** presumed phishing. |

`cases.json` contains the intended fictional scenario labels, a short objective, languages, SHA-256 checksums, expected MIME capabilities, and a small set of regression identifiers. **The detector never receives these ground-truth labels.**

`VALIDATION_RESULTS.md` records the **actual**, reproducible scores from the current packaged analyzer at the fixed High/Critical threshold of 45/100. It also identifies simulated phishing misses. The corresponding machine-readable output is `../../docs/V12_2_EML_SYNTHETIC_VALIDATION.json`.

## Try the examples manually

1. Start the application by opening `index.html`.
2. Open **Analyse** and drop one `.eml` file onto the email drop zone.
3. Compare the risk score, findings, manual verification advice, and scan-coverage warnings with the scenario name.
4. Try a phishing and a legitimate example from the same topic (e.g. `P03` versus `L10`, or `P16` versus `L18`).
5. When displaying the labels to classmates, say they are authored demonstrations and **not independently reviewed real emails**.

Some examples contain UTF-8 Cyrillic characters and zero-width formatting characters. Open them as raw `.eml` files, not through editors that silently normalize them or rewrite line endings. The files use CRLF line endings and genuine MIME body encodings.

## Validating automatically (no external services)

From `phishing-email-analyser/`:

```bash
node tests/example-eml-validation-tests.js
node tools/evaluate-example-emls.js --write
```

The first command verifies all 48 immutable SHA-256 hashes, MIME decoding, expected attachment extraction, select rule IDs, and that the examples pass safely through the real detector. The second regenerates the synthetic baseline table, without any internet requests. **Neither command validates the quality of the underlying fictional labels or estimates deployment performance.**

## QR and document coverage

The `P18` and `L15` files contain real synthetic PNG QR codes embedded in MIME messages. The parser extracts their bytes, but actual QR recognition requires browser `BarcodeDetector` or the separately verified, installed local decoder. A QR scan reported as unsupported or incomplete is **not** a negative QR finding. `P19`/`L16` include real synthetic PDFs, while `P20`/`L17` include OOXML-shaped DOCX attachments with external-link relationship examples. The static document scanner is not a malware sandbox and does not execute attachment content.

## Representative known limitations

At the present 45/100 High/Critical threshold, `P04`, `P18`, `P23`, and `P24` are below High in the Node run. In particular, `P18` requires an actual QR decoder to read its destination, and document and HTML form analysis provides static but incomplete evidence. These are **expected gaps to discuss during a course presentation**, not defects in the fixture pack. The six review examples are designed to elicit explicit independent-verification cues without promoting weak evidence into a confident malicious label.

## Deterministic regeneration

The checked-in `.eml` files work without extra dependencies. To regenerate from `tools/generate-example-emls.py` (which creates synthetic PDFs and PNG QR codes), Python packages `qrcode[pil]` and `reportlab` are needed in your *development environment only*. After regeneration, run the validation script and update the release manifest; inspect any SHA-256 changes before merging. Never commit personal email exports, public-corpus copies, or real personal identifiers to this folder.
