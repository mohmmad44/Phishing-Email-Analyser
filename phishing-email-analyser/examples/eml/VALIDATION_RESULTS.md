# Cybersteps — Synthetic .eml validation results

> **Demonstration data only.** These 48 fictional examples are **not** a real-world phishing benchmark, and their results cannot establish general precision, recall, or a production false-positive rate.

- 24 simulated phishing messages, 18 simulated legitimate messages, 6 review-only messages.
- High/Critical threshold: 45/100.
- High/Critical among phishing scenarios: 20/24.
- High/Critical among legitimate scenarios: 0/18.
- Phishing scenarios below High: P04, P18, P23, P24.
- Review-only examples with verification cues: 6/6.

**Important:** QR PNG attachments are extracted by the MIME parser, but image QR recognition itself is browser-capability-dependent and was not tested by this Node evaluation. Static PDF/OOXML investigation has known coverage limits. Actual browser results may include QR evidence unavailable in this runner.

| ID | Fictional label | Language | Detector result | Verification cues | Scenario |
|---|---|---|---|---:|---|
| P01 | phishing | en | 98 (Critical) | 0 | Credential harvest, sender spoof and SPF failure |
| P02 | phishing | en | 85 (Critical) | 0 | Executive impersonation and payment redirect |
| P03 | phishing | de | 97 (Critical) | 0 | German bank credential and TAN request |
| P04 | phishing | fr | 20 (Medium) | 0 | French parcel re-delivery fee request |
| P05 | phishing | es | 52 (High) | 0 | Spanish bank verification and credential request |
| P06 | phishing | en | 76 (Critical) | 0 | Shortened phishing destination with urgency |
| P07 | phishing | en | 93 (Critical) | 0 | Cyrillic character visually impersonating PayPal |
| P08 | phishing | en | 95 (Critical) | 0 | rn-to-m typosquatting for Microsoft |
| P09 | phishing | en | 74 (Critical) | 0 | Zero-width obfuscation in credentials request |
| P10 | phishing | en | 94 (Critical) | 0 | HTML visible link differs from destination |
| P11 | phishing | en | 88 (Critical) | 0 | Multipart alternative hides link in HTML |
| P12 | phishing | en | 70 (Critical) | 0 | Base64-encoded plain phishing body |
| P13 | phishing | de | 79 (Critical) | 0 | Quoted-printable German phishing text |
| P14 | phishing | en | 87 (Critical) | 0 | Sender and reply-to diverge; invoice change |
| P15 | phishing | en | 90 (Critical) | 0 | Disguised executable attachment and macros |
| P16 | phishing | en | 52 (High) | 0 | OAuth device authorization code instruction |
| P17 | phishing | en | 68 (High) | 0 | Unexpected MFA push approval request |
| P18 | phishing | en | 39 (Medium) | 0 | Image attachment conceals a QR destination |
| P19 | phishing | en | 53 (High) | 0 | PDF hyperlink to simulated credential collection |
| P20 | phishing | en | 69 (High) | 0 | DOCX external hyperlink to fake login |
| P21 | phishing | en | 50 (High) | 0 | Multi-layer URL encoding and redirect parameter |
| P22 | phishing | en | 81 (Critical) | 0 | Remote access installation request |
| P23 | phishing | de | 33 (Medium) | 0 | German changed IBAN business email compromise |
| P24 | phishing | en | 35 (Medium) | 0 | HTML login form posting credentials to third party |
| L01 | legitimate | en | 37 (Medium) | 0 | Routine team planning invitation |
| L02 | legitimate | en | 0 (Low) | 0 | Plain supplier invoice with no action pressure |
| L03 | legitimate | de | 0 (Low) | 0 | German notice says never share PIN |
| L04 | legitimate | en | 10 (Low) | 0 | English advice forbids sharing verification codes |
| L05 | legitimate | en | 10 (Low) | 0 | Normal Microsoft authentication URL in guidance |
| L06 | legitimate | en | 0 (Low) | 0 | Shipping status notification without action |
| L07 | legitimate | en | 0 (Low) | 0 | Receipt from courier |
| L08 | legitimate | en | 0 (Low) | 0 | Payroll calendar notice |
| L09 | legitimate | en | 39 (Medium) | 0 | Quoted training example with suspicious words |
| L10 | legitimate | de | 37 (Medium) | 0 | German bank security warning |
| L11 | legitimate | en | 0 (Low) | 0 | Passive subscription renewal reminder |
| L12 | legitimate | fr | 0 (Low) | 0 | French newsletter in quoted-printable |
| L13 | legitimate | es | 0 (Low) | 0 | Spanish receipt with Base64 body |
| L14 | legitimate | en | 0 (Low) | 0 | Multipart plain and HTML agree on official action |
| L15 | legitimate | en | 37 (Medium) | 0 | QR image for event room information |
| L16 | legitimate | en | 0 (Low) | 0 | Benign PDF agenda attachment |
| L17 | legitimate | en | 20 (Medium) | 0 | Benign DOCX handbook attachment |
| L18 | legitimate | en | 0 (Low) | 0 | IT MFA training without approval instruction |
| R01 | review | en | 0 (Low) | 1 | Billing failed notice with no independent sender verification |
| R02 | review | en | 0 (Low) | 1 | Account recovery instruction lacking a supplied URL |
| R03 | review | en | 14 (Low) | 1 | Unverified bank-message invitation |
| R04 | review | en | 0 (Low) | 1 | Parcel address confirmation without a link |
| R05 | review | en | 0 (Low) | 1 | Subscription renewal request in isolation |
| R06 | review | de | 0 (Low) | 1 | German account settings prompt without verification |

## Using the examples

1. Open the application in a browser and choose **Analyse**.
2. Drag a sample from the appropriate folder into its **.eml** drop zone.
3. Inspect rule evidence, possible independent-verification advice, and coverage warnings.
4. Compare the actual result with the scenario label (the label is author-created and is not provided to the detector).
5. Record any disagreements; do not reclassify below-High examples as detected phishing.

For an offline integrity + parsing check, run `node tests/example-eml-validation-tests.js`. To recreate this document, run `node tools/evaluate-example-emls.js --write`.
