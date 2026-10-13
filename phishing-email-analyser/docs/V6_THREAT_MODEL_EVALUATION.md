# Cybersteps v6 — threat model, architecture and evaluation

## Provenance and scope

**Source of truth:** the latest team-final ZIP merged with v5.1. This release adds modules rather than replacing the team's original detector. Baseline behavior is verified with `tests/run-tests.js` (104 tests). This release remains a **static, offline-first, non-production teaching application**.

### New attacker behavior covered

1. **Device code phishing**: a message instructs a user to enter a supplied device/authentication code into a *genuine* sign-in page to authorize a session the user did not initiate. Legitimate OAuth device code workflows exist, so an official Microsoft URL is not proof of maliciousness. Requires code + action + device-authentication context; ordinary mentions and explicit anti-phishing advice are controlled.
2. **OAuth consent phishing**: unsolicited grant/approve instructions plus app and data scope context. This does not check whether an OAuth application is actually malicious or whether a consent grant occurred.
3. **Unexpected MFA approval**: a prompt that the user did not initiate and that the message nevertheless instructs them to approve.
4. **Local indicator matching**: exact-host or normalized exact-URL matching against **user-supplied, unverified** JSON. These are contextual claims, **not live threat-intelligence verification**.

## Trust boundaries and data flows

- Untrusted input: pasted message, MIME HTML, QR image, optionally uploaded local threat-list JSON.
- Parsing in local tab; no network, no fetch, no URL following, no execution of attachments.
- `js/oauth-security.js` inspects bounded, NFKC-normalized text and emits bounded evidence.
- `js/threat-feed.js` validates JSON size, schema, origin label, expiry and indicator types; all matches remain local and ephemeral. Expired feed contributes nothing to risk. It performs exact matches only; false negatives expected. User-supplied source labels are not authenticated.
- `js/analyser.js` merges new findings with existing rule results and retains evidence for each unique finding ID. The existing 0–100 score remains a **heuristic index, NOT a calibrated probability**.
- The page renders user-controlled evidence as text rather than trusted HTML. CSP continues to block external connections and submissions.

## False positives / evasion

Potential false positives: real device sign-in instructions during an authorized support workflow, genuine OAuth app consent, a stale/incorrect custom feed, and educational discussions of authentication requests. Potential false negatives: indirect consent lures, images-only emails with unavailable QR support, encoded natural language, novel token abuse, altered word order, and highly personalized BEC without cue patterns. The module does not verify issuer identity, device code ownership, API scopes or successful account access.

## Benchmark and disclosure protocol

- Use separate positive **verified phishing** and negative **reviewed legitimate** examples; spam/ham cannot substitute automatically. Review license/privacy restrictions for all corpora.
- Document collection dates, origin, exact labeling policy, formats and any pre-processing; keep raw datasets *out* of the repository and avoid publishing user email addresses.
- Remove exact and near duplicates and group by campaign / registrable domain across train-validation-test to control leakage. Prefer a newer temporal holdout for phishing campaigns. `benchmark-audit.js` detects exact conflicts and reports group overlap if a `group` and `split` column are present. It cannot automatically prove that two messages are near duplicates or related campaigns.
- Choose thresholds on validation data; **freeze** threshold before testing. The sweep in the audit is descriptive only.
- Report true positives, true negatives, false positives, false negatives, precision, recall, specificity, F1, false-positive rate and 95% Wilson bounds. Calculate language-level error breakdown with enough samples; disclose when denominators are small or absent.
- Document all false-positive and false-negative examples with personally identifying content redacted. Evaluate each input format (URL-only versus full email) separately; mix only after the task definition is clear.
- The included fixture is **synthetic regression data**. No real-world accuracy claims can be inferred from test count or synthetic results.

## Optional QR browser support

Native BarcodeDetector is not uniformly available. The previously authored install tool supports a locally vendored, hash-pinned jsQR with license verification; because those release assets could not be obtained and independently authenticated in this environment, **cross-browser fallback cannot be represented as shipped**. Never silently label an unscanned QR image safe.

## CI, reproducibility and packaging

- GitHub Actions uses read-only repository permission and pinned checkout/setup actions and runs the original tests, security tests, deployment policy checks and synthetic audit.
- `RELEASE_MANIFEST.json` hashes source files; regenerate it after intentional modifications and verify after extracting the final ZIP.
- Running tests against a small synthetic corpus is validation of expected behavior, not evidence of detection probability in deployment.

## Current references (context, not claims of tested exploit paths)

- Microsoft, [Inside an AI-enabled device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/), April 6 2026.
- Microsoft, [Unmasking EvilTokens](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/), September 22 2026.
- Microsoft, [Storm-2372 conducts device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/), February 13 2025.
- Google Safe Browsing v5 [overview and hash-prefix privacy model](https://developers.google.com/safe-browsing/reference). Real-time lookups are not implemented and would require explicit user opt-in, secure key handling, cache rules, endpoint policies and a compliant deployment environment.
