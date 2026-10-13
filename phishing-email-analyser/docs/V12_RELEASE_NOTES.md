# Cybersteps v12.0 — external evidence study and error investigation

- **Authoritative base:** Cybersteps Team Final Evidence-First v11.0 (no production rules or UI changed).
- **Primary deliverable:** local-only, two-stage validation/test research workflow with duplicate and near-template separation across independently sourced corpora.
- **Error investigation:** opt-in private, defanged false-positive and false-negative excerpts; **not** included in the ZIP.
- **Research results:** aggregate confusion matrices, recall, precision, false-positive rate, Wilson uncertainty intervals, manual verification burden, and frequent rule patterns on errors.
- **Published source support:** HTTPS download helper for Zenodo 13474746 with published MD5 verification; mixed real/generated dataset cannot alone establish operational accuracy.
- **Security:** private policy and error artifacts use restrictive local permissions; data remains out of Git; runtime app makes no outbound requests.
- **Scientific boundary:** No external corpus run here due network restrictions, no claimed new real-world performance, no production threshold or probability changes.
- **Quality assurance:** added synthetic regression tests to existing GitHub Actions (not a substitute for real external-label testing).

See [V12_INDEPENDENT_EVIDENCE_PROTOCOL.md](V12_INDEPENDENT_EVIDENCE_PROTOCOL.md) for commands, labeling requirements, interpretation and limitations.
