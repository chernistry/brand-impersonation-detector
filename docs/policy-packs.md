# Policy packs

A policy pack maps the requirements of one rule, or of one jurisdiction, to the
fields this tool records. Packs are JSON files; the bundled ones live in
[`bid/policy_packs/`](../bid/policy_packs/). Code: [`bid/packs.py`](../bid/packs.py).

A pack never states that a notice or a record is sufficient, compliant or
admissible. Whether a mapping is complete for a given organisation is a legal
question; every pack declares a `review_status`, and every output carries a
notice saying it is not legal advice.

## Bundled packs

| Pack | Kind | Jurisdiction | Review status | Purpose |
|---|---|---|---|---|
| `eu-dsa-art16` | notice | EU | unreviewed | the four elements of a notice to a hosting service under Article 16(2) of Regulation (EU) 2022/2065, mapped to `platform_ip_report` |
| `generic-best-effort` | evidence | any | unreviewed | a jurisdiction-neutral record of how impersonation was detected, decided and acted on |
| `template` | evidence | XX | template | starting point for your own pack |

```bash
bid packs list
```

## Two kinds

**Notice packs** describe one outgoing notice. `check-notice` compares a
projection with the pack and marks each requirement:

| Status | Meaning |
|---|---|
| `met` | the projection carries the fields |
| `gap` | a field the projection should carry is empty |
| `operator` | only the person filing can supply it (for example their name and a good-faith statement) |

```bash
bid project <candidate id> --kind platform_ip_report > notice.json
bid packs check-notice notice.json --pack eu-dsa-art16
```

**Evidence packs** describe the record an organisation keeps of its own
handling. `report` goes through the signed receipts and the governance journal
and lists, per requirement, what they show:

```bash
bid packs report <run-dir>/receipts.jsonl --pack generic-best-effort \
  --store <run-dir> --pubkey <hex> \
  --journal "$BID_DATA_DIR/governance.jsonl" \
  --governance "$BID_DATA_DIR/governance.json" \
  --now 2026-11-30T12:00:00Z
```

| Status | Meaning |
|---|---|
| `met` | every metric the requirement names is satisfied |
| `gap` | at least one metric is not satisfied |
| `partial` | some metrics are satisfied and the others were not checked |
| `not_checked` | an input the metrics need was not given (store, journal, settings or time) |
| `operator` | only the organisation can show it, outside this tool |

Metrics a requirement can name:

| Metric | What the records show |
|---|---|
| `receipts.signed` | signed receipts in the period |
| `receipts.sourced` | receipts that name the sensor and the stored raw observation |
| `decisions.accountable` | receipts that name who decided and under what authority |
| `decisions.outcomes` | receipts per outcome, and how many were automated |
| `model.trace` | receipts that name the model, its family and the prompt template |
| `model.independent_recheck` | rechecks run by a different model family than the classifier |
| `integrity.public_signature` | receipts whose signature and chain verify with the public key alone (pinned with `--pubkey`) |
| `holds.escalated` | held findings past the review deadline that were escalated |
| `releases.accountable` | reversals that name the person, their authority and the reversed receipt |
| `deployment.attested` | receipts bound to a recorded deployment attestation |
| `queue.stop_authority` | people declared able to halt the queue |
| `detection.time_to_decision` | hours from first sighting to the first signed decision |

## Binding a pack to receipts

`--policy-pack` on `bid run` or `bid console` puts the pack's identity (id,
version, SHA-256 of its canonical JSON) into every receipt signed in that run,
so each receipt names the rule set it was produced under.

## Writing a pack

Copy [`template.json`](../bid/policy_packs/template.json) and fill in:

| Field | Meaning |
|---|---|
| `id`, `version`, `title` | identity; the SHA-256 is computed |
| `kind` | `notice` or `evidence` |
| `jurisdiction`, `source` | where the rule applies and which text it comes from |
| `review_status` | `unreviewed`, `template`, or `reviewed` once counsel has reviewed the mapping |
| `applies_to` | notice packs: the projection kind |
| `requirements[]` | `id`, `text`, `basis` (the provision), and either `fields` or `"supplied_by": "operator"` |

For a notice pack, `fields` are projection field paths; `a|b` accepts either.
For an evidence pack, `fields` are metric names from the table above; an
unknown metric is refused when the pack loads. Pass a path instead of a bundled
name to use your own file: `--pack ./packs/my-pack.json`.
