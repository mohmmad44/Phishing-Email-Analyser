# Phishing Email Analyser

A free, private phishing and social-engineering analyser that runs **entirely in your web browser**.
Paste a suspicious email or a phone-call transcript and get a risk score, a clear explanation, an attack-path simulation mapped to MITRE ATT&CK, incident-response guidance and IOCs. It also includes an awareness challenge, personalised training and a team dashboard.

No server, no database, no accounts, no AI APIs, no tracking.

---

## Run it on your computer (30 seconds)

1. Unzip the folder.
2. Double-click `index.html`. It opens in your browser and works offline.

## Put it on the internet for free

All three options are free for static sites like this one.

**Option A: Netlify Drop (easiest, no account needed to try)**
1. Go to <https://app.netlify.com/drop>.
2. Drag the whole `phishing-email-analyser` folder onto the page.
3. You get a public link straight away. Create a free account to keep it permanently.

**Option B: GitHub Pages (good for your portfolio)**
1. Create a free GitHub account and a new **public** repository, e.g. `phishing-email-analyser`.
2. Click **Add file → Upload files**, drag in everything from this folder (keep the `css` and `js` folders), then **Commit**.
3. Go to **Settings → Pages**, set *Source* to **Deploy from a branch**, choose `main` and `/ (root)`, then **Save**.
4. After a minute your site is live at `https://YOUR-USERNAME.github.io/phishing-email-analyser/`.

**Option C: Cloudflare Pages**: create a project, choose *Direct Upload*, and upload the folder.

> Optional hardening for hosts that support headers (Netlify, Cloudflare): the included `_headers` file adds the same privacy policy as an HTTP header, plus `frame-ancestors 'none'` so other sites cannot embed yours.

---

## What is in the folder

| File | What it does (plain English) |
|---|---|
| `index.html` | The page layout: tabs, text box and buttons. Contains the privacy lock (see below). |
| `css/styles.css` | Colours, spacing and layout, including dark mode and phone layout. |
| `js/rules.js` | The **knowledge base**: every warning sign, its weight and its explanation. Edit this to add your own rules. |
| `js/analyser.js` | The **detection engine**: reads the text, checks links, attachments and headers, calculates the score and extracts IOCs. |
| `js/guidance.js` | Turns findings into "what happens if…", the attack path and incident-response steps. |
| `js/content.js` | Example emails, the 12 challenge messages and the training lessons. |
| `js/eml.js` | Hand-written `.eml` reader: unwraps MIME parts, base64 / quoted-printable and encoded headers into plain text for the analyser. |
| `js/core.js` | Shared helpers: safe storage, safe display of text, awareness-score formula. |
| `js/app.js` | Connects the Analyse page buttons (including `.eml` drag-and-drop, read locally with `FileReader`) to the engine and draws the report. |
| `js/learn.js` | The Challenge and Training pages. |
| `js/dashboard.js` | Personal and team dashboards. |
| `tests/run-tests.js` | 104 automated checks for the detection engine (`node tests/run-tests.js`). |
| `tools/build-preview.py` | Makes a single-file copy (`dist/preview.html`) for previews. Not needed for hosting. |

---

## Key decisions, explained

**Why plain HTML, CSS and JavaScript?** Browsers understand these three languages natively. There is nothing to install or build and nothing to break when a framework updates. It is also the easiest code to learn from.

**How is privacy guaranteed?** The page has a *Content Security Policy* (CSP), a line in `index.html` that the browser enforces. `connect-src 'none'` means the page is forbidden from sending data to any server. Even if someone added a bad line of code, the browser would block the upload. Try it: open DevTools (F12) → **Network**, click Analyse, and you'll see no new requests.

**Why no Google Fonts?** Loading a font from Google tells Google that someone visited. The app uses fonts already on your device.

**Why no automatic voice transcription?** The speech recognition built into browsers (Web Speech API) sends audio to Google or Apple servers. That would break the privacy rule, so you load a recording to *play locally* and type what was said.

**How are emails displayed safely?** Email text is untrusted. If we inserted it into the page as HTML, a malicious email could run code (an attack called **XSS, Cross-Site Scripting**). The app only ever inserts text as plain characters (`textContent`), so `<script>` in an email is just shown, never run. Links are read as text and **never visited**.

**What is stored?** Only small summaries (score and warning-sign names, never the message), challenge answers and training progress, in your browser's `localStorage`. "Privacy & how it works → Delete all data" wipes it.

**How does the team dashboard work without a database?** Each person exports a small JSON file of scores. A manager imports those files, and the combining happens in the manager's browser.

**How is the risk score calculated?** Each warning sign has a weight (a password request = 25, a generic greeting = 6). Dangerous combinations add a bonus. The total is squashed onto 0–100 with `100 × (1 − e^(−total/55))`, so it rises quickly at first and never exceeds 100. Bands: Low 0–19, Medium 20–44, High 45–69, Critical 70–100.

---

## Ideas to extend it (great practice)

1. **Add a rule.** Open `js/rules.js`, copy an existing rule, change the `id`, `title`, `patterns` and `explain`. Re-run the tests.
2. **Add a brand.** Add it to `BRANDS` in `rules.js` with its real domains so look-alikes get caught.
3. **Add challenge messages.** Add entries to `CHALLENGE` in `js/content.js`.
4. **Parse `.eml` files.** Let users drop an exported email file onto the page (use `FileReader`, like the dashboard import).
5. **QR-code phishing ("quishing").** Decode QR images locally with a small library and analyse the URL.

## Limits

This is a rule-based teaching tool. It can miss carefully written attacks and can flag genuine messages. A low score does not prove a message is safe. Always verify through a trusted channel and report suspicious messages to your security team.

## Security extension integrated from v5.1

The original team application and its 104 regression tests are preserved. The integration adds optional local Unicode/IDN domain inspection, Public Suffix List-backed parsing, nested URL parameter inspection, HTML-source investigation, and QR-code analysis where a local browser decoder is available. Pasted MIME uses the existing email parser. For detailed merge decisions, testing and limitations see [the integration report](docs/TEAM_V51_INTEGRATION.md).

Neither extracted URLs nor attachments are executed or visited. Optional QR decoder support is not bundled automatically, and test/synthetic benchmark results do **not** establish real-world detection accuracy.


## v6 — additional security investigation (your individual contribution)

- **Contextual OAuth/device-code lure detection** (`js/oauth-security.js`): requests to enter device codes at real authentication portals, suspicious third-party OAuth permission grants, and instructions to approve unexpected authentication prompts. A valid authentication URL is **not itself evidence of phishing**. These are heuristic investigation indicators, not validated exploitation.
- **User-supplied local indicator feeds** (`js/threat-feed.js`): optional JSON import through the Analyse tab. The app checks exact URL or hostname indicators **only in the browser**; no query leaves the device and the feed is not stored. These lists are **unverified third-party claims**, not confirmed compromise. Expired feeds are ignored. No automatic URL reputation lookups are made.
- **Benchmark audit** (`tools/benchmark-audit.js`): accept independently sourced *phishing vs legitimate* labels, output confusion matrix, precision/recall/F1/FPR, Wilson uncertainty, language slices, threshold sensitivity, group overlap and data-quality warnings. **Do not optimize a threshold on the evaluation/test set.** Train/validation/test and group/source splits are separate concerns. The bundled examples are entirely synthetic.
- **v6 regression suite** (`tests/v6-security-tests.js`): authentication lure positives, legitimate notices, Unicode regression, imported-feed parsing/matching/expiry and deterministic whitespace perturbations.

Run the new tests:

```bash
node tests/v6-security-tests.js
node tools/benchmark-audit.js --input tests/fixtures/SYNTHETIC_LABELLED_URLS.csv --dataset-kind synthetic
```

To evaluate a real, independently sourced corpus, create a *licensed, reviewed*, CSV with `label,text` (or `label,url`) columns and optional `language,group,split` columns; labels must be exactly `phishing` and `legitimate`. **Spam != phishing**. The tool does not automatically download or inspect external data. It emits no original email content in its result. Full instructions: [`docs/V6_THREAT_MODEL_EVALUATION.md`](docs/V6_THREAT_MODEL_EVALUATION.md).

To try the **optional local indicator feed**, import a JSON file with shape:

```json
{
  "source":"Training fixture / user-supplied feed",
  "asOf":"2026-10-01T00:00:00Z",
  "expiresAt":"2026-12-01T00:00:00Z",
  "entries":[
    {"kind":"domain","indicator":"example.invalid","threat":"phishing"},
    {"kind":"url","indicator":"https://example.invalid/login","threat":"suspicious"}
  ]
}
```

This is an **illustrative, non-operational** sample; listing a domain in your own JSON does not make it malicious. Domain matching is exact and does not include subdomains. Lists are capped at 1 MiB / 5,000 records; URL indicators are capped at 2,048 characters. The browser never downloads, follows or contacts an indicator.

**QR caveat:** `BarcodeDetector` varies between browsers; an optional, SHA-256-verified local `jsQR` installation is supported but the library could not be fetched and authenticated in this release environment. Consequently cross-browser QR decoding is **not** claimed as completed. No runtime QR network requests are made.

**Deployment caveat:** `_headers` is honored by compatible hosts (such as Netlify and Cloudflare Pages) but not by GitHub Pages; clickjacking protection (`frame-ancestors 'none'`) requires correct HTTP header deployment, because it is ignored in `<meta>` CSP. Verify in browser network response headers on the deployed site.


## v7: research-grade evaluation workflow (new individual contribution)

`tools/benchmark-v7.js` accepts a CSV with **label,text,split,group,language** columns.
`label` must be `phishing`/`legitimate`, `split` must be `validation`/`test`,
`group` must identify a campaign or registrable domain consistently across rows.
Do not provide only spam/ham labels: spam is not necessarily phishing.
The benchmark rejects duplicate inputs/contradictory labels and cross-split
campaign leakage. It NEVER exports raw email messages into the metrics JSON.

```sh
# Offline smoke test: synthetic examples are NOT allowed to change thresholds.
node tools/benchmark-v7.js --input tests/fixtures/SYNTHETIC_SPLIT_RESEARCH.csv \
  --dataset-kind synthetic --output docs/v7-synthetic-split-smoke.json

# After downloading and documenting a real labelled corpus on your own machine:
node tools/benchmark-v7.js --input /private/data/labelled-corpus.csv \
  --dataset-kind external-labelled --source 'DOI or original corpus identifier' \
  --license 'verified dataset license' --collected 2026-10-13 \
  --max-fpr 0.05 --min-recall 0.5 --output /private/reports/external-benchmark.json
```

Calibration and threshold tuning are **disabled for synthetic or undersized
corpora**. Even when enabled for sufficiently large external validation/test splits,
exploratory reliability estimates stay in the benchmark output; they **do not
silently change the browser's heuristic risk score**. Metadata flags are assertions
provided by the researcher, not independent proof of licensing or label quality.
See [v7 research design](docs/V7_EVALUATION_SECURITY.md).

QR images are loaded locally using `createImageBitmap`, or a local data-URL
`Image` fallback on browsers that lack it. A native `BarcodeDetector` or a separately
installed, verified jsQR 1.4.0 is still required to decode; unsupported and incomplete
coverage is prominently reported. Vendor from hash-pinned release assets using
`tools/vendor-qr-decoder.py`, then run `tools/verify-qr-vendor.py` and rebuild the
release manifest. No live network requests are made at runtime.


## v8 — read-only PDF/Office attachment triage (your security contribution)

- Upload one PDF, DOCX, XLSX, PPTX or macro-enabled Office Open XML file through the **Analyse** tab, or import an `.eml` containing such attachments. Both are processed **locally in this browser**.
- Cybersteps checks limited visible PDF actions/links, OOXML ZIP relationships and component indicators; extractable images are sent to the existing QR analysis (which needs a supported browser decoder). Extracted links reuse the existing Unicode/IDN/redirect detector.
- Every scan reports its **coverage limitations**. The result is not antivirus, malware sandboxing, complete PDF parsing, proof that a macro is malicious, or evidence that an external URL was visited. The scanner does not open or execute attachments.
- Security limits: 8 MiB per file, ZIP entry/expansion caps and CRC validation, at most four documents per `.eml`, no external requests. Some OOXML parts require local `DecompressionStream('deflate-raw')` support.
- Your browser may still require an independently verified offline jsQR library; it is not silently downloaded or bundled in this release. A `QR unavailable`/`incomplete` result does **not** mean no QR code exists.
- Read [v8 security design](docs/V8_ATTACHMENT_FORENSICS_SECURITY.md) and [v8 release notes](docs/V8_RELEASE_NOTES.md). Run `node tests/v8-attachment-security-tests.js` and the full GitHub Actions test workflow after merging.
- The inherited 20-example synthetic benchmark and v7 split-safe infrastructure **cannot establish real-world detection accuracy**. A genuine, licensed, externally labeled dataset remains future work.

## v9.0 — improving the quality of decisions

The application now distinguishes weak phishing-themed language from more
specific technical or actionable evidence, and shows when an apparent match was
actually a prohibition or a quotation from security training. The evidence
panel and exported JSON explicitly identify what the scanner did **not** verify.

Run `node tools/quality-audit.js --baseline docs/V9_V8_BASELINE_CASE_SCORES.json`
for a reproducible synthetic development-case comparison. **These tests do not
measure real-world accuracy.** See [`docs/V9_DETECTION_QUALITY_STUDY.md`](docs/V9_DETECTION_QUALITY_STUDY.md)
for limitations, the remaining missed scenarios, and the independent evaluation
protocol. Do not interpret a Low/Medium result as clearance to open a link.

## v10 quality evaluation using independent data

Run `node tools/public-corpus-evaluation.js --input evaluation_data/Phishing_validation_emails.csv --output evaluation_data/zenodo-v10-results.json` after independently downloading the published Zenodo file and reviewing its terms. The evaluation is entirely local. It does not transmit email content. Run `node tools/render-public-evaluation.js --input evaluation_data/zenodo-v10-results.json --output evaluation_data/zenodo-v10-summary.md` for a course-report summary. See [`docs/V10_EXTERNAL_QUALITY_EVALUATION.md`](docs/V10_EXTERNAL_QUALITY_EVALUATION.md) for limitations: **this mixed real/generated corpus cannot establish real-world accuracy or justify automatic score calibration**.

## v11 — Verification without false certainty (individual contribution)

Some phishing messages contain a dangerous *request* but no technical evidence (no link destination, sender domain, full headers, or attachment). A Low risk score from these short messages is **not** a reliable safe verdict. Cybersteps now displays a separate **Independent verification recommended** triage result for six evidence-poor action contexts. This is **not a positive phishing classification**, does not alter the numeric score, and recommends using a known contact or independently typed website/app. Safety/awareness guidance and ordinary receipts are excluded by conservative negative controls.

The external-corpus evaluator now measures human-verification queue coverage and benign review burden **separately** from phishing precision, recall and false-positive rate, with optional SHA-256 corpus fingerprint enforcement. These improvements do not establish real-world accuracy or calibrated probabilities; that still requires a licensed, independent held-out corpus. See [`docs/V11_DECISION_QUALITY_STUDY.md`](docs/V11_DECISION_QUALITY_STUDY.md) and `node tests/v11-verification-quality-tests.js`.

## v12 — evidence-based independent study (research only)

The v12 addition provides **two-stage external evaluation** with a frozen validation-only candidate threshold, separate held-out test corpus, source/label declarations, cross-source message/campaign/template leakage checks, a confusion matrix, precision/recall/false-positive-rate confidence intervals, and an opt-in restricted local false-positive/false-negative review file. Production risk scoring is unchanged. No external email corpus is bundled or downloaded by the browser. The mixed real/generated Zenodo validation dataset could not be retrieved from the release environment and has NOT been evaluated here; real-world accuracy remains unknown.

See [`docs/V12_INDEPENDENT_EVIDENCE_PROTOCOL.md`](docs/V12_INDEPENDENT_EVIDENCE_PROTOCOL.md) for the exact commands and scientific constraints. **Never commit evaluation_data/**, private policies, or real emails. Run `node tests/v12-evidence-study-tests.js` for synthetic research-workflow regression checks.

## Offline `.eml` demonstration fixtures (v12.2)

The project includes **48 fictional, SHA-256-verified `.eml` examples** with actual MIME encodings, HTML alternatives, Unicode spoofing, QR-image and document attachments, and legitimate business/security messages. Browse `examples/eml/README.md`, drag an example onto the Analyse page, or run `node tests/example-eml-validation-tests.js`. Results are recorded in `examples/eml/VALIDATION_RESULTS.md`. These are **educational synthetic examples**, not real-world phishing-accuracy evidence.


## QR decoder: Windows one-time installation (v12.2 QR fix)

If `typeof BarcodeDetector` and `typeof window.jsQR` are both `undefined`,
**a QR decoder is not installed**. To enable QR image decoding on Windows:

1. Extract the complete ZIP. An internet connection is needed **only once** for installation.
2. In `phishing-email-analyser/`, double-click `INSTALL_QR_DECODER_WINDOWS.cmd` and follow the console output.
3. It downloads **jsQR 1.4.0** from npm and compares the downloaded `.tgz` archive against a hard-coded published **SHA-512 integrity value** before installing anything. It includes the Apache-2.0 license and an SHA-256 lockfile.
4. Close and reopen `index.html` or hard-reload the Live Server tab.
5. In F12 Console run `typeof window.jsQR` (should be `"function"`). Test the P18 QR example in `examples/eml/01_phishing/`.

If Python is installed, use `python tools/install-qr-decoder.py` instead.
For offline machines, download `https://registry.npmjs.org/jsqr/-/jsqr-1.4.0.tgz`
on a trusted networked computer, then use
`python tools/install-qr-decoder.py --archive /path/to/jsqr-1.4.0.tgz`.
The archive is always checked against the pinned integrity value.

**Privacy**: once installed, the decoder loads from `js/vendor/jsQR.js` and
QR image pixels are processed in the browser; no external QR script or analysis
endpoint is used at runtime. QR decoding does **not** establish whether the URL is
malicious. Local QR processing is bounded, does not navigate, and may inspect
only one QR symbol with jsQR in each image.

**Packaging/CI**: if committing the newly installed `js/vendor` library, also
commit its license and lockfile, then run `python tools/build-release-manifest.py`,
`python tools/verify-qr-vendor.py` and `python tools/verify-release-manifest.py`.
The source ZIP distributed before a verified network install does not itself
contain jsQR; it provides an integrity-pinned installer.
