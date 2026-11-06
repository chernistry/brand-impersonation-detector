# Architecture

The detector turns public observations into a ranked queue for an analyst, and
records every decision on every candidate as a signed receipt. It runs on
infrastructure you control. It never files a report, contacts a platform or acts
on an account; an operator does that with the payloads it produces.

## Pipeline

```
sensors -> normalize -> cheap filters -> classify -> rank
        -> triage policy -> person decision -> signed receipt -> offline verify
```

| Stage | Module | What it does |
|---|---|---|
| Sensors | `bid/sensors/` | Emit `RawObservation`s: certificate-transparency logs, look-alike domains (permutations resolved over DNS-over-HTTPS), username enumeration, Bluesky search, the Apple App Store search API, the Meta Ad Library, and a fixture search. Sensors observe; they do not judge. |
| Normalize | `normalize.py` | Stores the raw observation and every asset content-addressed by SHA-256, computes a perceptual hash for images, and merges duplicates into one `Candidate`. |
| Cheap filters | `filters.py` | Deterministic signals with no model call: confusable-folded handle distance, Jaro-Winkler similarity, brand containment, logo pHash (and optional CLIP) distance, brand alias in text, official-domain mismatch, known-bad domains. Obvious noise is dropped here. |
| Classify | `classify.py` | A rule-based offline classifier by default, or a hosted multimodal model (`--live`). Scraped text is untrusted data: it is tagged, the output is schema-constrained, and injection attempts are a signal. An optional recheck by a model of another family can disagree. |
| Rank | `rank.py` | A per-brand queue ordered by label severity, then confidence, with a stable tiebreak. |
| Triage policy | `decisions.py` | Signs a receipt for every classified candidate. It rejects clear negatives and escalates everything else to a person. Automatic confirms are off unless configured. |
| Person decision | `api.py` (console), `governance.py` | A person confirms, rejects or escalates; a declared releaser can reverse a confirm. Each is a signed receipt in the same chain. |
| Signed receipt | `evidence.py` | One receipt format for every outcome: the manifest pins asset hashes, the verdict, the decision, the models and prompt template, the policy versions and the deployment attestation. See [evidence-format.md](evidence-format.md). |
| Offline verify | `verify_receipt.py` | Anyone with the public key and the stored assets checks a receipt or a whole chain. |

Around the pipeline:

| Part | Module | Docs |
|---|---|---|
| Governance: queue stop, releases, hold deadlines, journal | `governance.py` | [governance.md](governance.md) |
| Report payloads from a confirmed finding | `projections.py`, `stix_export.py` | [projections.md](projections.md) |
| Jurisdiction policy packs | `packs.py`, `policy_packs/` | [policy-packs.md](policy-packs.md) |
| Deployment profiles, egress allowlist, PII redaction, attestation | `attestation.py`, `net.py`, `redact.py`, `profiles/` | [deployment.md](deployment.md) |
| Evaluation and the signed conduct review | `eval/`, `conduct.py`, `adversarial.py` | [evaluation.md](evaluation.md) |
| Public-source pivot from a suspect domain | `enrich.py` | best-effort, keyless |
| Operator console | `server.py`, `api.py`, `static/` | [deployment.md](deployment.md#console) |

## Runtime data

All runtime state lives under one directory, `$BID_DATA_DIR` (default `./.bid`).
Nothing is written inside the installed package, so the package directory can be
read-only.

```
$BID_DATA_DIR/
  governance.json          the deployment's governance settings (optional)
  governance.jsonl         governance journal: stop and resume, hold escalations,
                           deployment attestations, conduct reviews
  pipeline/                run directory of `bid run`
  console/
    runs/<run id>/         one run directory per console run
    feedback_labels.jsonl  analyst label ledger
    active_policy.json     applied operating point
  scale/, compare-models/, demo-*/
                           run directories of `bid scale`, `bid compare-models`, `bid demo-*`
  cache/<name>/            disposable caches (model replies, public-source lookups, embeddings)
  eval_report.json         last `bid eval` report
```

A run directory is self-contained:

| File | Content |
|---|---|
| `receipts.jsonl` | signed receipts, one per line, in chain order |
| `cases.jsonl` | the candidate and verdict each receipt was signed over |
| `<sha256>` | assets and raw observations, content-addressed |
| `receipt_sample.json`, `ed25519_pubkey.txt` | one receipt and the signing key, for a quick check |
| `chain_head.rfc3161.json` | optional timestamp over the last receipt (`bid run --anchor`) |
| `run.json` | console runs only: the run summary the console shows |

`bid verify`, `bid project`, `bid governance` and `bid packs report` take a run
directory, so a console run and a command-line run are handled the same way.

## Determinism

With the default settings a run is reproducible: fixture sensors, a fixed clock
(`--clock fixed`), the rule-based classifier, fixed development keys and stable
tiebreaks. Two runs produce byte-identical signed evidence, and `bid replay`
checks that. `--clock utc`, live sensors and hosted models make a run depend on
the outside world; the receipts then record what was seen and which model and
policy decided.

## Interfaces

| Protocol | Defined in | Implement it to |
|---|---|---|
| `Sensor` | `models.py` | add a source; return `RawObservation`s and a `health()` dict |
| `Classifier` | `models.py` | plug in another model; return a `Verdict` |
| `EvidenceSigner` | `models.py` | sign with a key held in a KMS or HSM instead of a seed |

Projections, policy packs and deployment profiles are data: a builder function
per projection kind, and JSON files validated on load.
