# Changelog

All notable changes to this project are recorded here. Versions follow
[Semantic Versioning](https://semver.org/). Schema strings (`bid.evidence/v2`,
`bid.governance/v1`, `bid.projection.<kind>/v1`, ...) change only with a
recorded entry.

## 0.1.0 (2026-11-06)

First public version.

### Pipeline

- Sensors for certificate-transparency logs, look-alike domains, username
  enumeration, Bluesky, the Apple App Store and the Meta Ad Library, plus a
  fixture sensor; all emit one observation type.
- Content-addressed storage of every asset and raw observation; duplicate
  merging.
- Deterministic filters: confusable-folded handle distance, Jaro-Winkler
  similarity, logo pHash with optional CLIP, brand alias in text, official-domain
  mismatch, known-bad domains, popularity allowlist.
- Rule-based offline classifier and hosted multimodal classifier with tagged
  untrusted input, schema-constrained output, semantic injection detection and
  an optional recheck by a model of another family.
- Public-source pivot from a suspect domain (certificates, DNS, RDAP, ASN,
  scan search, block lists).

### Evidence and governance

- One signed receipt schema, `bid.evidence/v2`, for confirm, reject, escalate
  and release, with model trace, prompt template, policy version, policy pack
  and deployment attestation.
- HMAC chain for internal checks and Ed25519/DSSE signatures for public checks;
  chain links use public manifest hashes.
- `bid verify` checks a receipt or a whole chain offline; `--pubkey` pins the
  published key, and a chain must be signed by one key.
- Optional RFC-3161 timestamp over the chain head (`bid run --anchor`).
- Triage policy that rejects clear negatives and escalates the rest; automatic
  confirms off by default.
- Person decisions, releases by declared releasers, queue stop and resume,
  overdue-hold escalation, all in a signed governance journal (`bid governance`).
- Settings file with a fixed load order shared by the console and the command
  line.
- Signed conduct review of the classifier against a supervisor of another
  model family (`bid conduct`).

### Output

- Report projections of a confirmed finding: findings log, platform
  intellectual-property report, registrar abuse report, fraud-desk case and
  STIX 2.1 bundle (`bid project`).
- Policy packs: notice checks and best-effort evidence reports, with an EU
  Digital Services Act Article 16 notice pack, a jurisdiction-neutral evidence
  pack and a template (`bid packs`).

### Operation

- Operator console (`bid console`): runs, ranked queue, decisions, releases,
  queue stop, exports, public-key verification, hold deadlines and calibration.
  Token access beyond loopback, optional identity from an authenticating proxy.
- Deployment profiles with a per-component egress allowlist, PII redaction,
  zero-data-retention routing and a configurable model endpoint; the settings
  in effect are attested into the journal and bound into receipts.
- All runtime state under `$BID_DATA_DIR`; the package directory can be
  read-only. Container image running as a non-root user.
- The console refuses to listen beyond loopback while a signing key is still a
  public development value.
- Evaluation tools: signal ablation, cross-family agreement, scale test,
  prompt-injection battery, model comparison and replay.
