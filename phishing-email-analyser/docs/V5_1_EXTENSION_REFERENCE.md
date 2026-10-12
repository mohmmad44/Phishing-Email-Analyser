# Cybersteps Phishing Email Analyzer — Security-Hardened Release 5.0

> **Release guide:** This document is the main release and security guide; `phishing-email-analyser/README.md` preserves the original team application guide. It consolidates application setup, original team functionality, individual cybersecurity contribution, threat model, implementation notes, tests, demonstration guide, evaluation protocol, dependency/data provenance, and limitations. The repository contains **one current release**, not a collection of previous version packages.

**Project type:** offline-first cybersecurity awareness and explainable, static phishing investigation.  
**Course contribution:** adversarially hardened domain, URL, HTML, and QR investigations with reproducible security regression testing.  
**Release date:** 9 October 2026.  
**Deployment:** static browser application; Node.js 22 for automated tests; Python 3 for optional development-only utilities.

## Contents

1. [Quick start](#quick-start)
2. [Application features](#application-features)
3. [Individual contribution and original-team boundary](#individual-contribution-and-original-team-boundary)
4. [Security architecture and data flow](#security-architecture-and-data-flow)
5. [Threat coverage and analysis decisions](#threat-coverage-and-analysis-decisions)
6. [Security hardening and bug fixes](#security-hardening-and-bug-fixes)
7. [Verification and CI](#verification-and-ci)
8. [Benchmark methodology and results](#benchmark-methodology-and-results)
9. [Demonstration for cybersecurity assessment](#demonstration-for-cybersecurity-assessment)
10. [Standards data, licensing, and updating](#standards-data-licensing-and-updating)
11. [Privacy, safe deployment, and incident-response boundaries](#privacy-safe-deployment-and-incident-response-boundaries)
12. [Known limitations and future improvements](#known-limitations-and-future-improvements)
13. [File map](#file-map)
14. [Security references](#security-references)

## Quick start

Extract the ZIP. From its repository folder, open `phishing-email-analyser/index.html` in a modern browser. No account, API key, database, package installation, or web server is needed for ordinary local use.

- **Analyse:** paste suspicious email text, a voice-call transcript, or inert HTML source; optionally upload an `.eml` message or a QR image.
- **Challenge / Training:** work through simulated phishing cases and targeted learning activities.
- **Dashboard:** review local training/analysis summaries and import/export team results.
- **Privacy:** review the offline processing behavior and delete local saved summaries.

The program examines supplied text and selected local files **without following links or executing attachments**. It does not fetch remote web pages or query threat-intelligence services. QR decoding **requires browser `BarcodeDetector` support or an optional locally bundled `jsQR` decoder**; unsupported decoding is reported rather than interpreted as a clean scan.

For a hosted deployment, publish the `phishing-email-analyser/` folder as a static site. Ensure your host actually serves the security headers in `_headers` (hosting support differs); the HTML also includes a restrictive CSP. Avoid serving this tool from a different origin alongside apps with broad permissions.

## Application features

### Existing team functionality

The original team's work provides:

- Rule-based detection of coercive language, account suspension threats, password and MFA-code requests, bank/payment fraud, role impersonation, suspicious URLs, attachment filenames, and selected email header claims.
- `.eml` reading and limited MIME content decoding; sender and body extraction.
- A weighted **heuristic** risk score, not a calibrated phishing probability. The score is `round(100 × (1 − exp(−totalWeight / 55)))` with bands Low 0–19, Medium 20–44, High 45–69, Critical 70–100.
- Security findings, example MITRE ATT&CK attack paths, defensive recommendations and extracted indicator candidates (URLs, addresses, hostnames, IP addresses, filenames).
- A 12-scenario phishing awareness challenge, personalized learning topics and a browser-local dashboard with manually imported/exported team summaries.
- Local storage of limited summaries and learning state rather than the original email text.

The original analyzer already contained basic ASCII Levenshtein/typosquat rules and simple Punycode indicators; those are **not** claimed as newly invented individual contributions.

### Security-engineering enhancements

The course contribution extends the existing application with:

| Subsystem | Relevant files | Purpose |
|---|---|---|
| Unicode / IDN impersonation | `js/domain-security.js`, `js/confusables-data.js` | Detect mixed/whole-script visually confusable domains, Punycode-encoded hostnames, and explain code points and brand mismatches. |
| Registered-domain boundaries | `js/public-suffix.js`, `js/psl-data.js` | Parse multi-part, wildcard and exception suffixes, including private hosting suffixes, to avoid naive hostname comparisons. |
| Bounded nested URL investigation | `js/url-security.js` | Inspect selected redirect-like query parameters, repeat encoding, and nested URLs without visiting their destinations. |
| Inert HTML inspection | `js/html-security.js` | Detect suspicious displayed-link/target mismatches, forms and submit overrides, meta-refresh hints, embedded frames/objects, image maps and selected active/hidden-link patterns. |
| QR / image clues | `js/qr-security.js`, `js/eml.js` | Decode supported local QR images and supported MIME image parts, then pass URLs through existing security checks. |
| Benchmark and reproducible tests | `tools/benchmark.js`, `tests/*.js` | Measure held-out detection behavior and prevent regressions using adversarial cases and deterministic mutation tests. |
| Development security policy | `.github/workflows/security-tests.yml`, `_headers` | Run automated checks and restrict runtime permissions; require branch-protection configuration to block merges. |

## Individual contribution and original-team boundary

**Contribution title:** *Explainable Multi-Vector Phishing Investigation, Unicode/IDN Security, and Adversarial DevSecOps Testing*.

**Problem:** attackers exploit domain character confusion, hosted tenant names, malicious destinations hidden in HTML or multi-level URL parameters, and QR codes, while parsers may be manipulated by specially crafted content. Naive string checks miss some attacks and can incorrectly flag ordinary internationalized domains. The individual contribution investigates these cases while preserving existing features and user privacy.

**Scope of work:** domain ownership boundary analysis, Unicode visual-confusable evidence, nested parameter investigation, static HTML and QR analysis, guardrails for untrusted input, cross-module integration fixes, meaningful regression tests, evidence-based documentation, and CI policy checks.

**What remained from the team:** original rule vocabulary, general risk scoring, educational challenges, lessons, dashboard, base `.eml` importer, and general attack guidance. Source changes to `js/analyser.js`, `js/app.js`, and `js/eml.js` are integrations/hardening, not claims to have originally created the whole application.

### Design goals

1. Produce **specific evidence** such as the Unicode code point or the real registrable-domain boundary; avoid unexplained keyword warnings.
2. Prefer conservative results for legitimate IDNs and OAuth-style callbacks; do not treat Punycode or `redirect_uri` as automatic proof of attack.
3. Fail **visibly and safely** on unsupported QR APIs, excessive inputs, untrusted headers, or truncated MIME content.
4. Remain local: do not resolve DNS, navigate to malicious links, run attachments, access email accounts, or phone home.
5. Make changes independently testable and provide a repeatable evaluation process instead of implying perfect coverage.

## Security architecture and data flow

```text
Pasted email, transcript, inert HTML, local .eml, QR image
                 |
     Existing text/MIME input handling
                 |
   +-------------+----------------------+-------------------+
   |             |                      |                   |
Original      IDN / PSL             HTML source          QR image
heuristic      analysis             inspection         decoding*
rules          and typos         (never rendered)   (local support*)
   |             |                      |                   |
   +-------------+----------------------+-------------------+
                 |
      URL parsing / bounded nested-URL checks
                 |
      Evidence-weighted, heuristic risk score
                 |
      Safe report, red flags, IOCs and guidance
```

`*` QR decoding is **not guaranteed** in every browser; unsupported is a coverage limitation.

Relevant source files use a shared `PEA` namespace and are loaded as local scripts from `index.html`. The browser's CSP sets `connect-src 'none'` and `form-action 'none'`; deploy-time `_headers` adds protections when supported by the host. The application never opens the URLs it extracts.

### Unicode / IDN rules

- Normalize the hostname using URL/IDNA mechanisms and decode Punycode labels for inspection.
- Examine scripts **per DNS label**, not by treating different labels or TLDs as automatically suspicious.
- Compare visual-confusable transformations against verified brand-name/domain records; give exact suspicious-code-point evidence when applicable.
- Identify brand names appearing *inside unrelated hostnames* and brand-lookalike tenants on some hosting services.
- Keep the original ASCII lookalike detections. An internationalized domain alone does not imply phishing; all-Cyrillic or all-Greek domains can be legitimate.
- The bundled ICU-derived character transformation table is **not an audited, fully conformant implementation of Unicode 18 UTS #39**. It can miss novel confusables or produce false alarms.

Examples for classroom investigation: `rnicrosoft.com` (ASCII composition), `miсrosoft.com` (Cyrillic `с`, U+0441), `pаypаl.com` (Cyrillic `а`, U+0430), `login.microsoft.com.evil.example` (trusted-name string inside unrelated host), and legitimate `bücher.de`. Sample domains are for analysis demonstrations; do not navigate to them.

### PSL and domain ownership

`paypal.co.uk.attacker.example` has registrable domain `attacker.example`; `accounts.google.com` is under `google.com`. The PSL implementation can distinguish ICANN/private rules including wildcard and exception handling. This determines **structural domain boundaries**, **not actual legal ownership** or proof that a website is uncompromised. Hosted-tenant treatment depends on the snapshot and provider rules.

### Bounded nested-link analysis

The URL investigator interprets only selected parameter keys such as `url`, `next`, `destination`, `target`, `redirect`, and `redirect_uri`. It uses a bounded queue, tracks visited candidates, and evaluates candidate hosts with the domain module.

| Limit | Value |
|---|---:|
| URL / candidate length | 4,096 characters |
| Parameters evaluated per URL | 40 |
| Redirect candidates per URL | 6 |
| Maximum URL visits | 12 |
| Maximum nested query levels | 3 |
| Additional percent-decoding passes | 2 |

A parameter's contents indicate an *advertised candidate destination*. They do **not** prove that a remote server actually redirects there. OAuth or federated authentication can legitimately use redirect parameters; findings reflect corroborating evidence and weights, not certainty.

### Static HTML investigation

The system inspects **source strings**, never inserts untrusted email markup as executable HTML. It checks deceptive anchor text, HTML forms including `formaction` overrides, frames/objects, image-map areas, meta-refresh instructions, duplicate attributes, and relevant resource hints. Comments and scripts are not interpreted as actual visible hyperlinks. Static inspection cannot emulate every browser's parsing or CSS behavior, and it does not load remote images.

### QR-code analysis

The app accepts selected local QR images and supported image attachments extracted from `.eml` messages. Where available, the browser's `BarcodeDetector` or an optionally vendored `jsQR` decoder yields a textual URL for static inspection. No website visit occurs. A browser without either decoder reports **unsupported**, not **safe**.

For broader browser compatibility, on a connected **developer** computer (not at application runtime), review and run:

```bash
python3 phishing-email-analyser/tools/vendor-qr-decoder.py
```

This optionally vendors Apache-2.0-licensed `jsQR` v1.4.0 for local hosting and adjusts the local script include. Audit the downloaded library, license, cryptographic hash, CSP effect, tests, and browser capability before committing; this library is **not included by default**. Two inert QR samples are in `tests/fixtures/`.

## Security hardening and bug fixes

The current release includes corrective changes validated against selected adversarial cases:

| Weakness / evasion | Current countermeasure |
|---|---|
| `From:` / `Authentication-Results:` forged inside email body | Anchor header extraction to the contiguous leading email-header block; do not treat body content as trusted headers. |
| Copied SPF/DKIM/DMARC text claimed to be authoritative | Label results **unverified claims** from the supplied message; independent signature validation is not performed. |
| Duplicate HTML `href` attributes | Use first-attribute-wins semantics in static inspection and add case-variation tests. |
| HTML engine skipped for pasted HTML with empty context | Fall back to user-supplied HTML source; render applicable HTML/QR finding categories in the report. |
| Excessive long tokens / UI stalls | Cap input and token lengths; explicitly warn **analysis incomplete** when coverage is truncated. |
| Excessive MIME part count and decoded body | Enforce 25 MiB input, 250 MIME-part, and 512 KiB decoded-body processing budgets with coverage warning. |
| Submit-destination overrides and non-anchor link sources | Include selected `formaction`, `<area>`, `<iframe>`, and `<object>` sources in static inspection. |
| Old asynchronous file read overwriting newer input | Ignore stale FileReader completions using a generation token. |
| Malformed or extreme team JSON summaries | Validate fields and ranges; cap imports and local storage arrays. |
| Regression in offline policies | Add CI tests for CSP, local script paths, response-header directives and data-file presence. |

These fixes address identified cases; they do not constitute an independent penetration-test certification or comprehensive RFC/HTML parser conformance.

## Verification and CI

Use Node.js 22. In a terminal, start at the `phishing-email-analyser/` directory:

```bash
node tests/run-tests.js
node tests/domain-security-tests.js
node tests/url-security-tests.js
node tests/advanced-security-tests.js
node tests/release-hardening-tests.js
node tests/secure-property-tests.js
node tests/adversarial-tests.js
node tests/deployment-policy-tests.js
node tools/benchmark.js --input tests/fixtures/SYNTHETIC_LABELLED_URLS.csv --dataset-kind synthetic --output docs/synthetic-benchmark-result.json
```

The merge-reviewed release has **1,270 local automated checks passing across nine suites**, including the original 94 tests and 604 deterministic property/fuzz checks. This describes reproducible engineering checks, **not** real-world phishing classification accuracy. Run the commands above in your own checkout and GitHub Actions; any failures must be investigated before merging. See `phishing-email-analyser/docs/merge-review-verification.json` for the latest local results. The earlier `docs/test-results.json` is retained as historical evidence only.

The repository-root `.github/workflows/security-tests.yml` runs JavaScript syntax validation, all suites, the synthetic benchmark smoke test, and Python maintenance-tool syntax validation on pushes and pull requests. It uses read-only permissions and pinned GitHub Actions revisions. **Automatic merging is not blocked by a workflow alone:** repository maintainers must configure the successful job as a required status check in branch protection/rulesets.

The optional `python3 tools/browser_smoke.py` uses a controlled browser harness and creates `docs/browser-preview.png` and `docs/browser-verification.json` (when dependencies are installed). Because its harness may inject HTML using `set_content`, it is **not** equivalent to testing deployed HTTP response headers. Always inspect CSP and `_headers` behavior after actual hosting.

## Benchmark methodology and results

The bundled 20-row CSV in `tests/fixtures/SYNTHETIC_LABELLED_URLS.csv` is an **invented engineering smoke-test dataset**. It is not a contemporary independently labeled phishing corpus. Results at threshold 45:

| Statistic | Synthetic result |
|---|---:|
| True positives | 9 |
| True negatives | 10 |
| False positives | 0 |
| False negatives | 1 |
| Unique synthetic samples | 20 |

Do **not** report these as 95% real-world phishing detection accuracy. The 604 deterministic fuzz checks likewise are not independent real-life phishing campaigns. The benchmark runner emits confusion counts, precision, recall, specificity, false-positive rate, F1, score range, sample counts, duplicate/conflicting-label handling and Wilson 95% binomial intervals. Uncertainty intervals do not correct sampling/label bias.

### Independent real-world evaluation protocol

1. Select a legally reusable and independently labeled corpus of **phishing** and legitimate examples; **spam/ham is not equivalent** to phishing/legitimate. Document collection time, source, license, sampling and labeling policy.
2. Identify whether you are evaluating **email content** or **URLs only**. Make no claims about full-email protection based on a URL-only corpus.
3. Remove exact and near-duplicates; group by domain/campaign to prevent leakage; freeze score threshold and rules before testing.
4. Prefer a time-forward holdout first observed after detector design, plus benign samples from multiple services, scripts, hosted tenants and normal internationalized sites.
5. Do not visit live phishing URLs. Redact personal data; keep licensed raw corpora outside public ZIP and GitHub where redistribution is not authorized.
6. Execute locally with a label-and-text CSV:

   ```bash
   node tools/benchmark.js --input /local/labelled.csv --dataset-kind external-labelled --threshold 45 --output /local/metrics.json
   ```

7. Report population counts, TP/TN/FP/FN, precision, recall, F1, false-positive rate, uncertainties, subgroup differences, representative redacted errors and detection drift. Never tune rules or thresholds on the held-out evaluation split.

The report JSON omits raw URL/email text and includes dataset SHA-256 for reproducibility. A realistic security evaluation needs independently verified labels, contemporary examples, and context beyond synthetic test fixtures.

## Demonstration for cybersecurity assessment

Use a local working copy with DevTools open, and **do not visit demonstration links**:

1. **Trust boundaries:** paste `From:` or `Authentication-Results: spf=fail` *inside the body*, after a blank line; show that it is not misclassified as genuine email headers. Repeat with a leading header block and explain why those results remain unverified.
2. **Unicode spoofing:** paste `https://pаypаl.com/login` (each `а` is Cyrillic U+0430). Show the exact visual-confusable signal, then contrast with `https://bücher.de`.
3. **HTML destination disguise:** paste `<a href="https://evil.example">https://paypal.com</a>` as source. Inspect the mismatch finding, then demonstrate a `<button formaction="https://paypa1.example/login">` override.
4. **Multi-layer parameter:** analyze a synthetic `example.com/?next=...` URL that contains an encoded lookalike destination. Explain why the inner URL is only a *candidate*, not a confirmed redirect.
5. **Resource limits:** paste an oversized uninterrupted token (for example >1,024 characters); show the visible **incomplete analysis** warning instead of a misleading low-risk conclusion.
6. **QR capability:** upload the synthetic QR images in `tests/fixtures/`. Demonstrate decoding *if available* or the explicit unsupported message; do not claim functionality the browser lacks.
7. **DevSecOps:** run the tests and show `.github/workflows/security-tests.yml`. Explain both shift-left testing and the need to configure required status checks after committing the workflow.
8. **Scientific limitations:** show the confusion matrix from the synthetic fixture and explain why the result is not a measured population detection rate.

## Standards data, licensing, and updating

The application bundles derived Unicode/PSL **data snapshots**, so documentation and license notices remain relevant even though separate Markdown data files have been consolidated here.

- **Public Suffix List:** `js/psl-data.js` was generated using an OpenJDK 21 system snapshot of `public_suffix_list.dat` (approximately 9,762 rules including private-hosting entries); exact snapshot date is unknown. The upstream Public Suffix List and its Mozilla Public License 2.0 terms are at <https://publicsuffix.org/list/> and <https://publicsuffix.org/list/public_suffix_list.dat>. Confirm applicable source and license obligations before redistribution; retain notices with generated data. Registrable-domain boundaries never prove legal ownership.
- **Unicode confusables:** `js/confusables-data.js` was generated from **ICU 76** `uspoof_getSkeletonUTF8` transformations over U+0080–U+2FFFF (18,535 differing mappings) supplemented by reviewed overrides. ICU data/software are subject to upstream copyright and license terms: <https://github.com/unicode-org/icu/blob/main/icu4c/LICENSE>. This is **not** the official Unicode 18 confusables data and full UTS #39 conformance has **not** been established.
- **Standards refresh tooling:** on a connected developer machine, `python3 tools/update-standards.py` fetches the official Public Suffix List and Unicode 18.0.0 `confusables.txt`, with TLS and input-size bounds. The generated assets and provenance manifest must be reviewed, version-pinned where appropriate, tested, and tracked. Unicode copyright/license: <https://www.unicode.org/copyright.html>. Upstream security data: <https://www.unicode.org/Public/18.0.0/security/confusables.txt>.
- **Optional jsQR:** `jsQR` 1.4.0 (Cosmo Wolfe and contributors), **Apache License 2.0**, <https://github.com/cozmo/jsQR>. Not bundled by default. If vendored, distribute the appropriate license/NOTICE and keep the browser loading only local scripts.
- **Synthetic QR images:** locally generated course examples, not live phishing sites or a licensed image corpus.

When refreshing the standards data, do not silently replace the data and claim improved performance: record upstream dates, file hashes and license terms, rerun all tests, and re-benchmark false positives. Developers may connect to update upstream data; **browser runtime never downloads these datasets**.

## Privacy, safe deployment, and incident-response boundaries

- Input content is analyzed in the browser. It is not sent to a cloud AI service or threat feed, and suspicious destinations are never fetched, probed or clicked by the analyzer.
- The interface renders untrusted text as text, not executable email HTML. The CSP restricts network connections, script origins, frames, base URLs and form submissions subject to actual host/browser enforcement.
- Stored summaries contain analysis/training metadata; they should not include original message bodies. Imported team JSON is untrusted and validated but must still be reviewed for privacy before sharing.
- The analyzer may identify **indicators worth investigating**, not verified incidents. Header authentication values in supplied `.eml` content are **unverified assertions**; cryptographic DKIM checking and sender infrastructure validation are out of scope.
- Treat a low/zero score or unsupported scan as **not proof of safety**. For suspected real compromise, follow your organization's incident-response procedure through a trusted channel.
- Before production use, perform a separate independent review, cross-browser tests, deployment-header verification, accessibility analysis, licensed dataset benchmarking, maintenance planning, and dependency/standards review.

## Known limitations and future improvements

1. No live reputation feeds, DNS verification, active webpage navigation, safe-browsing lookup, remote redirect confirmation, or malware sandbox.
2. No AI/ML phishing classifier or autonomous inbox monitoring; the engine is rule-based and evidence-weighted.
3. Some MIME / HTML variations, encoded content, deep redirects, right-to-left display tricks, new confusable characters or non-brand phishing can evade inspection.
4. QR image decoding varies by browser and decoder availability; no remote images are fetched.
5. No independent, contemporary real-world detection-accuracy study included.
6. Unicode UTS #39 and Public Suffix List datasets may be incomplete/outdated relative to current upstreams.
7. Pasted or forged authentication headers are not proof of true sender identity.
8. Heuristic thresholds/weights are not calibrated probabilities, and benign workflows can resemble phishing.
9. A local browser demo or successful CI job does not certify security for enterprise deployment.

**Next responsible priorities:** a maintained/provenance-stamped standards update, cross-browser QR decode coverage with offline dependencies, independent real-world benchmark and code review, and systematic benign-IDN/OAuth false-positive analysis.

## File map

```text
Phishing-Email-Analyzer-Cybersteps-main/
├── README.md                    <- main release guide (app README preserved)
├── .github/workflows/security-tests.yml
├── test-phishing-sample.eml
└── phishing-email-analyser/
    ├── index.html
    ├── _headers
    ├── RELEASE_MANIFEST.json     <- current release only
    ├── css/styles.css
    ├── js/                      <- original engine + integrated security modules/data
    ├── data/                    <- generated provenance after explicit standards refresh
    ├── docs/
    │   ├── browser-preview.png
    │   ├── browser-verification.json
    │   ├── test-results.json
    │   ├── synthetic-benchmark-result.json
    │   └── BASELINE_COMPARISON.csv
    ├── tests/                   <- existing, adversarial, policy and fuzz suites
    │   └── fixtures/            <- inert examples
    └── tools/                   <- benchmark, browser tests, standards/QR maintenance
```

No older release-specific README, report, old-version manifest, duplicate screenshot or obsolete-version archive is included. The implementation retains all integrated safeguards from prior development stages; only redundant **documentation/artifacts** are removed.

## Security references

- Unicode Technical Standard #39 (Unicode Security Mechanisms): <https://www.unicode.org/reports/tr39/>
- Unicode Technical Standard #46 (IDNA compatibility): <https://www.unicode.org/reports/tr46/>
- RFC 3492 (Punycode): <https://www.rfc-editor.org/rfc/rfc3492>
- Public Suffix List: <https://publicsuffix.org/>
- MITRE ATT&CK T1566 (Phishing): <https://attack.mitre.org/techniques/T1566/>
- OWASP Unvalidated Redirects and Forwards: <https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html>
- OWASP Input Validation: <https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html>
- GitHub required status checks: <https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches>
- ICU project license: <https://github.com/unicode-org/icu/blob/main/icu4c/LICENSE>
- Optional `jsQR` project license: <https://github.com/cozmo/jsQR>

These upstream sources provide technical background; they do **not** certify this implementation as fully compliant or as having any particular detection accuracy.


## Merge review fixes (2026-10-09)

- Defensive negation and non-action password expiry text no longer count as explicit credential requests.
- Additional German urgency, suspension, credential, MFA and payment cues are detected.
- Hidden Unicode format characters are normalized for keyword analysis and reported as an independent warning.
- Pasted MIME source with normal RFC-like headers is decoded using the offline `.eml` parser.
- Repeated HTML findings are aggregated by ID with a `count` rather than inflated risk.
- `tests/merge-review-tests.js` adds adversarial and benign examples for these changes.
- `.github/workflows/security-tests.yml` is part of the **repository root**, not the published static directory.
- `.gitattributes` enforces LF in tracked source and `.eml` to prevent manifest integrity changes on Windows.
- `.idea/` must stay untracked; if already in your index, run `git rm -r --cached .idea`.
- Vendoring jsQR is fail-closed: optional decoder installation requires SHA-256 pins supplied and reviewed in advance, with matching version-pinned license. No decoder is fetched by the browser.
- Re-run `python3 phishing-email-analyser/tools/verify-release-manifest.py` from the repository root after any changes.

This release does **not** provide real-world sensitivity or false-positive estimates.
The synthetic benchmark is only a unit/smoke test. A published-corpus evaluation
requires independent data acquisition, verified labels, deduplication and a
held-out assessment.
