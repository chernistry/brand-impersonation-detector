# Brand impersonation detector

A self-hosted pipeline that finds accounts, ads, apps and domains impersonating
a brand, ranks them for an analyst, and records every decision on them as
signed evidence that anyone with the public key can verify offline. It runs on
infrastructure you control.

It detects and documents. It does not file takedowns, contact platforms or act
on any account; it produces report payloads that an operator reviews and files.

All brands, domains, handles and logos in the repository are fictional
(reserved `.test` domains, synthetic logos drawn from basic shapes).

## Why

Finding look-alike domains and accounts is the easy part. The questions come
afterwards: who decided that a candidate was impersonation, what they were
shown, which model and thresholds ranked it, and whether the record has changed
since. A platform, a registrar or an internal reviewer asking them should not
have to take the operator's database on trust.

The project is built around those questions:

- **A model ranks; a person decides.** The triage policy rejects only clear
  negatives and sends everything else to a person. Automatic confirms are off
  unless you turn them on, and even then they stay open until a person looks.
- **Every decision is a signed receipt**, rejects and reversals included. A
  receipt pins the bytes that were seen, the model and prompt template, the
  thresholds, the person and the authority they acted under. Receipts form a
  chain; `bid verify` checks one receipt or the whole chain with the public key
  alone.
- **People stay in charge of the queue.** Declared people can stop it at any
  time, reversals need a declared releaser, and overdue holds are escalated. Each
  of these is a signed record too.
- **It runs where your data is.** A deployment profile limits which hosts each
  component may reach, removes personal data before model calls, and the
  settings actually in effect are attested into the record.
- **It is open source under Apache-2.0**, so the detection rules, the evidence
  format and the verifier can be read, audited and changed by the people who
  rely on them.

## How it works

```
sensors -> normalize -> cheap filters -> classify -> rank
        -> triage policy -> person decision -> signed receipt -> offline verify
```

| Stage | What it does |
|---|---|
| Sensors | Public sources: certificate-transparency logs, look-alike domains (dnstwist permutations resolved over DNS-over-HTTPS), username enumeration, Bluesky, the Apple App Store, the Meta Ad Library, and a fixture search. |
| Normalize | Stores every observation and asset under its SHA-256, computes perceptual hashes, merges duplicates. |
| Cheap filters | Deterministic signals with no model call: confusable-folded handle distance, Jaro-Winkler similarity, logo pHash (optional CLIP), brand alias in text, official-domain mismatch, known-bad domains. |
| Classify | Rule-based offline classifier by default; a hosted multimodal model with `--live`. Scraped text is treated as untrusted data, and injection attempts count as a signal. Optional recheck by a model of another family. |
| Triage and decisions | Every verdict gets a signed receipt. A person confirms, rejects or escalates in the console; a declared releaser can reverse a confirm. |
| Output | Report payloads from a confirmed finding (platform report, registrar abuse report, fraud-desk case, findings log, STIX 2.1), checked against policy packs. |

Details: [architecture](docs/architecture.md) · [evidence format](docs/evidence-format.md) ·
[governance](docs/governance.md).

## Quickstart

Python 3.11 or later.

```bash
git clone https://github.com/chernistry/brand-impersonation-detector
cd brand-impersonation-detector
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[console]"

bid run          # whole pipeline on the bundled fixtures: no keys, no accounts, no network
bid verify .bid/pipeline/receipts.jsonl --pubkey "$(cat .bid/pipeline/ed25519_pubkey.txt)"
bid console      # operator console on http://127.0.0.1:8799
```

`bid run` exits 0 only when the HMAC chain and the public-key check pass, both
tamper checks (an asset byte and a manifest field) are caught, and every
candidate has a receipt. Fixture runs are deterministic: two runs produce
byte-identical signed evidence (`bid replay` checks this).

Fixture runs use public development keys, so their receipts prove nothing.
Set your own keys before real use ([deployment](docs/deployment.md#keys)).

### Tamper check

Change one byte of a stored asset and verify again:

```bash
cp -R .bid/pipeline /tmp/bid-copy
python - <<'EOF'
import json, pathlib
d = pathlib.Path("/tmp/bid-copy")
h = json.loads((d / "receipt_sample.json").read_text())["manifest"]["asset_hashes"][0]
b = bytearray((d / h).read_bytes()); b[-1] ^= 1; (d / h).write_bytes(bytes(b))
EOF
bid verify /tmp/bid-copy/receipts.jsonl --pubkey "$(cat /tmp/bid-copy/ed25519_pubkey.txt)"
# RESULT: REJECTED  (package 0 failed: asset ... bytes tampered (hash no longer matches))   exit 2
```

### Container

```bash
for v in BID_CONSOLE_TOKEN BID_HMAC_KEY BID_ED25519_SEED BID_LEDGER_KEY; do
  export "$v=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
done
docker compose up --build              # console on http://127.0.0.1:8000
docker compose run --rm console run    # one pipeline run in the same image
```

The image runs as a non-root user with a read-only root filesystem and all
state in `/data`.

## Commands

`bid <command> --help` shows the options of each command.

| Command | Purpose |
|---|---|
| `bid run` | run the pipeline and verify the evidence it signs (`--brands`, `--sensors broad`, `--live`, `--recheck`, `--profile`, `--policy-pack`, `--anchor`, `--embeddings`) |
| `bid verify` | verify a receipt or a chain with the public key only |
| `bid console` | operator console (needs the `console` extra) |
| `bid governance` | stop or resume the queue, release a confirm, escalate overdue holds, show status, verify the journal |
| `bid project` | project a confirmed finding into a report payload |
| `bid packs` | check a notice against a policy pack; best-effort report over receipts |
| `bid conduct` | signed conduct review of the classifier on the labelled set |
| `bid replay` | prove two runs are byte-identical; show which policy produced a receipt |
| `bid eval`, `bid agreement`, `bid scale`, `bid adversarial`, `bid compare-models` | evaluation ([docs](docs/evaluation.md)) |
| `bid brand-kb` | draft brand aliases and official domains from Wikidata |
| `bid demo-sensors`, `bid demo-enrich`, `bid demo-itunes` | run one live sensor or the public-source pivot |

## Configuration

Environment variables; the full list is in [deployment](docs/deployment.md).

| Variable | Effect |
|---|---|
| `BID_DATA_DIR` | where all runtime state goes (default `./.bid`) |
| `BID_HMAC_KEY`, `BID_ED25519_SEED`, `BID_LEDGER_KEY` | signing keys; default to public development values |
| `BID_CONSOLE_TOKEN` | required for the console to listen beyond loopback |
| `BID_CONSOLE_ACTOR_HEADER` | take the acting person from an authenticating proxy's header |
| `BID_LLM_BASE_URL`, `BID_LLM_API_KEY` | model endpoint and its key, for example a self-hosted model |
| `OPENROUTER_API_KEY` | hosted model via OpenRouter; sent to `openrouter.ai` only |
| `META_AD_LIBRARY_TOKEN`, `SHODAN_API_KEY` | optional live sources |
| `BID_CONTACT` | contact appended to the User-Agent of outbound requests |

With `--live` or `--sensors broad`, a `.env` file in the working directory is
read for API keys; it never overrides a variable that is already set.

## Documentation

| Page | Covers |
|---|---|
| [Architecture](docs/architecture.md) | stages, modules, runtime data layout, interfaces |
| [Evidence format](docs/evidence-format.md) | receipt fields, hashing, chain, verification |
| [Governance](docs/governance.md) | triage, holds, decisions, release, queue stop, settings |
| [Deployment](docs/deployment.md) | keys, container, console access, profiles, egress, model endpoint |
| [Projections](docs/projections.md) | report payloads from a confirmed finding |
| [Policy packs](docs/policy-packs.md) | notice checks and evidence reports per rule or jurisdiction |
| [Evaluation](docs/evaluation.md) | what the measurements show and what they do not |
| [Threat model](docs/threat-model.md) | assets, boundaries, threats, controls, residual risk |

## Limits

- Detection and evidence only. A person reviews every finding; the tool does
  not perform takedowns or contact platforms.
- Coverage is only as broad as the enabled sensors. There is no native
  ingestion from the large social networks, the Meta Ad Library API returns
  commercial ads only for the EU and UK, and Bluesky is a small slice of social
  media. Sensors are subject to each service's terms and rate limits; set
  `BID_CONTACT`.
- A registered look-alike handle or domain is a lead, not proof of abuse.
- The offline classifier is a rule table, not a trained model. The bundled
  labelled set is small and synthetic: it checks consistency and regressions,
  not accuracy on real traffic.
- Prompt-injection defences reduce risk; they do not cover adaptive attacks.
- Receipts are tamper-evident and verifiable offline. They are not a statement
  about legal sufficiency or admissibility in any jurisdiction, and the policy
  packs are unreviewed mappings, not legal advice.
- The console token admits people but does not tell them apart; per-person
  identity needs an authenticating proxy.

## Development

```bash
pip install -e ".[dev,console]"
python -m pytest -q
ruff check bid tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the ground rules and
[SECURITY.md](SECURITY.md) to report a vulnerability.

## Author

Built by [Alex Chernysh](https://alexchernysh.com). Help with deploying or
adapting it: [alexchernysh.com/consulting](https://alexchernysh.com/consulting).
Also by the author: [Bernstein](https://github.com/sipyourdrink-ltd/bernstein),
an open-source governance layer for AI agents.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
