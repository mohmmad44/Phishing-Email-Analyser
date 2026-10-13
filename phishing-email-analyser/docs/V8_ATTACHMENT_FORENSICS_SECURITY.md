# Cybersteps v8.0 — local attachment forensics: design, threat model and validation

**Purpose.** Extend the team's final v7 browser-only email analyzer with a bounded, non-executing **attachment triage** layer. This is **not antivirus, sandboxing, a complete PDF/OOXML reader, or a claim that a document is safe**.

## Trust boundaries and operations

1. The user explicitly selects a local PDF/Office file, or an `.eml` with a Base64 PDF/OOXML attachment. No URLs are visited. The browser CSP still sets `connect-src 'none'`.
2. MIME decoding is local and bounded (25 MiB email, at most four document candidates, at most 8 MiB each). The original team's 104 tests and dual plain/HTML text handling are preserved.
3. The new `js/attachment-security.js` classifies by **magic signature**, not merely extension. Suspicious mismatches are documented; unsupported files return `incomplete` rather than a false "clean" verdict.
4. PDF: static visible-object inspection covers URI actions, OpenAction, Launch, JavaScript and embedded-file indicators. Some uncompressed JPEG/DCT streams can be extracted as QR candidates. No PDF rendering/decryption, full object-graph parsing, xref resolution, or decompression of PDF content streams occurs.
5. OOXML: ZIP central directory is validated with strict entry/expansion/path limits, method allowlisting, local/central consistency, size and CRC checks. Decompression uses the browser's local `DecompressionStream('deflate-raw')` when available. XML and `.rels` bytes are parsed as **text only**; external destinations are **not loaded**. VBA, ActiveX, embeddings, workbook links are reported as *presence indicators*, not confirmed threats. Supported PNG/JPEG package images are forwarded to the existing QR inspection path.
6. Extracted HTTP(S) URLs are passed through the **existing v7 domain, Unicode/IDN and redirect detector**. The v8 integration reuses weighted findings and marks origins as `document`; it does not silently increase all file scores.
7. Reports contain a distinct "Local document forensics" section and export only bounded findings, source names and coverage metadata. Document bytes and body content are *not* placed in JSON exports or history.

## Security limits (defense-in-depth)

| Control | Bound |
|---|---:|
| Single document | 8 MiB |
| ZIP central directory entries | 160 |
| Cumulative declared uncompressed ZIP size | 12 MiB |
| One compressed or uncompressed ZIP part | 2 MiB |
| Declared ZIP inflation ratio | 100:1 |
| Extracted document URLs | 40 per document |
| Extracted supported QR candidate images | 4 per document |
| MIME document candidates | 4 |
| MIME whole message | 25 MiB |

These are application-level controls rather than a formal guarantee of time- or memory-bounded execution on every browser and every input. ZIP entries are decoded incrementally and independently, with checks before storing expanded bytes; the local PDF dictionary parser does not execute or render content.

## Expected attack coverage

- Explicit malicious or deceptive document hyperlinks, including Unicode domain impersonation, if visible in inspected document structures.
- Some PDF action indicators (`/Launch`, `/JavaScript`, `/OpenAction`, `/EmbeddedFile`). Presence is not proof of execution, and lexical scanning may yield false positives.
- OOXML `.rels` links and non-web external relationship schemes; macro, ActiveX, embedded object and external workbook-link presence.
- Some inline JPEG/DCT PDF images and standard PNG/JPEG OOXML media candidates, **only if a QR decoder is available**. No full PDF QR promise.
- MIME `.eml` document extraction and contextual evidence export.

## Intentionally unsupported / known coverage gaps

- PDF object streams, cross-reference streams, compressed text, many filters, encryption, complex encoding, OCR, attachments nested inside PDFs, or full PDF/Office rendering.
- ZIP64, encrypted ZIP/Office packages, encrypted PDFs, archives with unsupported methods or excessive inflation.
- OOXML external references hidden in unusual nonstandard formats, binary metadata, OLE files (`.doc`, `.xls`), and macro disassembly.
- QR decoding without the browser's native BarcodeDetector or independently authenticated local jsQR bundle. The optional bundle is **not included**; no network lookup occurs at runtime.
- Live URL reputation, signature verification of SPF/DKIM, and malware behavior. A static match is an investigation clue, not a proven compromise.
- A real-world estimate of precision/recall/false-positive rate. The synthetic fixtures and 1,000+ prior regression/property tests are **not a representative threat dataset**.

## Security and standards references

- OWASP File Upload Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- OWASP Input Validation Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- Open Packaging Conventions (OPC) external relationships and TargetMode: https://wiki.openoffice.org/wiki/OOXML/Open_Packaging_Conventions_(OPC)
- GitHub CodeQL default setup documentation: https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configure-code-scanning

## How to demonstrate the contribution

1. Run `node tests/v8-attachment-security-tests.js`, including a compressed OOXML external relationship, macro indicator, malformed ZIP/CRC/path defenses, EML extraction and safe benign examples.
2. Run `python3 tools/v8-browser-smoke.py` in an environment with Python Playwright + local Chromium. It tests both local document selection and `.eml` document import.
3. Load a demonstrative PDF containing `/Launch` and a visible URI: the output explains the evidence and marks coverage incomplete.
4. Load a benign Office document with only an ordinary external link: the link is listed without being automatically called malicious.
5. Export JSON; show the document metadata, coverage limitations and bounded findings without any original file bytes.
6. Run the inherited original and v7 suites from the GitHub Actions workflow.

**Future empirical study:** Source licensed, independently labeled *phishing vs legitimate* complete email/document samples; group by campaign/domain/sender and time; evaluate on a held-out set, reporting per-language precision/recall/FPR and confidence intervals. Never train/select thresholds on the held-out test set or treat spam as equivalent to phishing.
