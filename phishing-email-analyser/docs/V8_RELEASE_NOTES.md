# Cybersteps v8.0 — team release + local document investigation

This release is a **small, additive set of changes** atop the final team v7 ZIP. It does not overwrite baseline learning, challenge, scoring, or dashboard functionality.

### Added

- `js/attachment-security.js`: bounded static PDF and Office Open XML inspection; signature/ZIP metadata checks, CRC, XML `.rels` analysis, limited image extraction.
- New optional PDF/Office file input and status on Analyse tab; same engine examines document attachments extracted from `.eml`.
- Reuses existing v7 URL/IDN/redirect detector on links found in attachments; distinct `Document forensics` findings and explanations.
- Coverage warnings for static/non-exhaustive scans; structured JSON export contains document summary and caveats but no uploaded bytes.
- `tests/v8-attachment-security-tests.js`, `tools/v8-browser-smoke.py`, extended CI suite and detailed security design notes.

### Preserved

The team's original 104 checks and the entire inherited v7 security test collection, Privacy/Challenge/Training/Dashboard, all current release policy assertions, and the offline/no-runtime-network design.

### Limitations

This is **static triage only**. No file detonation, full PDF parser, OCR, cross-browser QR guarantee, signature-authenticated online threat feeds, nor real-world labeled benchmark metrics are claimed. A separate QR decoder is still required in browsers without native QR support. No real-world malicious samples were executed or used for this release.

### Run

```sh
cd phishing-email-analyser
node tests/v8-attachment-security-tests.js
python3 tools/v8-browser-smoke.py  # optional Chromium/Playwright integration smoke test
python3 tools/verify-release-manifest.py
```

GitHub's CodeQL default setup is recommended separately in repository security settings; it is not activated by including this ZIP and requires eligible repository access.

### Verification completed in this environment

- Original team suite: **104/104**.
- All **12 combined regression/security suites: 1,380/1,380 checks** (this includes inherited synthetic/property tests, NOT detection accuracy).
- `tools/v8-browser-smoke.py`: **passed** in controlled local Chromium (inline-content harness, not a deployed CSP test).
- Release provenance: `docs/V8_FILE_PROVENANCE.json`, including hashes of changed inherited files and a list of additions.
- `RELEASE_MANIFEST.json` is generated against the **exact packaged source files** after documentation and tests are finalized.

**Merge guidance:** Preserve `.git` when copying this ZIP into the team repository, stage hidden `.github/workflows/security-tests.yml`, then execute GitHub Actions and inspect its logs before merging. The workflow has not been executed on the team's GitHub repository by this build.
