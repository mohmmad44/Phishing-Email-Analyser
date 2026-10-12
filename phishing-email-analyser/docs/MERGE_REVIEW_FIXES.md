# Security merge review — release 5.1

This is a code-review remediation checklist, **not** a real-world phishing evaluation.

## Merge blockers repaired

1. `.github/workflows/security-tests.yml` belongs at the repository root. Full ZIP contains it. CI invokes all regression suites, the new merge review suite, and a manifest verification gate.
2. The original team's full `phishing-email-analyser/README.md` is restored alongside the longer root release guide; the stub README is not included.
3. `.gitignore` excludes `.idea/` and `.gitattributes` enforces LF for tracked source and `.eml` files. If `.idea/` is already tracked, it must be removed from the Git index manually.
4. Password-expiry notices no longer count as explicit password requests; safety warnings with negation are suppressed in their local clause. Plain invoices are informational with zero standalone risk.
5. German security patterns have been added for urgency, blocked accounts, passwords/PINs, TAN/MFA, payments, and bank detail changes.
6. Unicode `Cf` category is stripped in NFKC-normalized analysis text and independently warned on. Visible report text is normalized; invisible marks are not executed.
7. Raw RFC-like MIME pasted into the analyzer passes through the same `.eml` decoder as uploaded files and retains HTML source for static security checks.
8. Repeated findings sharing an ID are collapsed, with `count` and unique evidence, and the maximal per-finding severity weight.
9. Synthetic metrics are labeled engineering evidence only. We cannot claim real-world detection rates until a permitted public dataset is evaluated. Spam-versus-ham labels are not sufficient for a phishing benchmark.
10. The optional jsQR installer downloads exactly one version (`1.4.0`) and the LICENSE from **the same npm version**, checks externally provided SHA-256 pins BEFORE writing either file, and refuses to operate if pins are missing or incorrect. The script is not run as part of normal user operation.
11. CSP `frame-ancestors` must be sent in HTTP headers; it cannot be enforced from HTML `<meta>` CSP. Host support must be verified in deployment.

## Limitations and security tradeoffs

Negation is conservative and local to a clause; complex quoted, translated or adversarial negation can still defeat a heuristic classifier. The German vocabulary is intentionally limited, and there is no claim of complete internationalization. Base64 decoding relies on MIME structure and parser guardrails; incomplete parsed content is explicitly reported. SHA-256 verification protects the vendoring operation only after trustworthy expected checksums have been established out-of-band. The external QR decoder remains **optional** and is not preinstalled.

## Windows and Git instructions

From the **repository root**, after copying this release, run:

```bash
git rm -r --cached --ignore-unmatch .idea
git add -A
git status --short
git ls-files .github/workflows/security-tests.yml README.md phishing-email-analyser/README.md .gitattributes .gitignore
python3 phishing-email-analyser/tools/verify-release-manifest.py
cd phishing-email-analyser
node tests/merge-review-tests.js
node tests/deployment-policy-tests.js
```

This release requires the correct root directory; placing only the application subfolder into the repository will cause the CI and manifest tests to fail. If you change source files after release, rerun `python3 phishing-email-analyser/tools/build-release-manifest.py` before verification and commit the new manifest together with the edited source.
