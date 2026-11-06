# Governance

The model ranks; a person decides. This page covers who may decide what, how
each action is recorded, and how to configure it. Code:
[`bid/decisions.py`](../bid/decisions.py), [`bid/governance.py`](../bid/governance.py),
[`bid/api.py`](../bid/api.py).

## Triage policy

Every classified candidate gets a receipt signed by the triage policy:

| Verdict | Receipt |
|---|---|
| `legit` or `fan` at confidence ≥ 0.8 | `reject`, automated |
| anything else (`suspicious`, `impersonation`, `fraud`, or low confidence) | `escalate`, automated: waits for a person |

Automated receipts record the policy version as `decided_by` (the policy id plus
a short hash of its thresholds, for example `bid-triage-v1+1a2b3c4d`) and the
authority `triage-policy`. Positive labels and `suspicious` never get an
automatic reject.

Automatic confirms are off. They can be enabled in Python with
`TriagePolicy(auto_confirm_min_confidence=...)`; an automatic confirm is still
an open hold until a person decides.

## Holds

A candidate is an open hold while its latest receipt is an `escalate`, or a
`confirm` the policy made alone. A person closes it with a decision of their
own. Holds are listed oldest first.

`hold_sla_hours` (default 24) sets how long a hold may wait. A hold is overdue
at `created_at + hold_sla_hours`. The console shows overdue holds;
`bid governance escalate` records one `hold_sla_escalation` per overdue hold
receipt in the journal. Running it again records nothing new for the same hold,
so it can run on a schedule:

```bash
# every 15 minutes
bid governance escalate --run-dir "$BID_DATA_DIR/console/runs/<run id>"
```

Without `--run-dir` it reads `$BID_DATA_DIR/pipeline`.

## Person decisions

In the console a person confirms, rejects or escalates a candidate. Each is a
signed receipt with `automated: false`, the person as `decided_by` and the
authority `brand-protection analyst`.

| Rule | Behaviour |
|---|---|
| Confirm and reject feed calibration | they are appended to the signed label ledger (`feedback_labels.jsonl`) |
| A repeated confirm | returns the existing receipt; nothing new is signed |
| Reversing a person's confirm | refused in the decision controls; it takes a release |
| Escalate | always available; it is the expected choice when in doubt |

## Release

A release reverses a confirm. Only a declared releaser may sign one, under the
authority declared for them. The release receipt names the confirm it reverses
in `supersedes` (the confirm's manifest hash) and carries the reason as its note.

```bash
bid governance release --candidate <id> --actor counsel-01 --reason "rights holder confirmed the account"
```

## Queue stop

Anyone listed under `stop_authority` may stop or resume the queue at any time,
with a reason. Each call is a signed `queue_halt` or `queue_resume` record.

While the queue is stopped:

- new runs are refused, model calls included (the console answers 409;
  `bid run` exits with code 3);
- report exports are refused (console export, `bid project`);
- decisions and releases on existing receipts remain possible, so open holds can
  still be worked.

A journal that cannot be read counts as stopped. One that reads but fails
verification is flagged in the console and by `bid governance verify`.

```bash
bid governance halt --actor duty-manager-01 --reason "classifier drift after model update"
bid governance resume --actor duty-manager-01 --reason "rolled back to the previous model"
bid governance status
bid governance verify --pubkey <hex>
```

## Settings

`governance.json` declares the people and limits:

```json
{
  "usable_default": "Not sure? Escalate. Escalating is the expected choice when in doubt.",
  "ask_contact": "brand-protection on-call (#brand-protection)",
  "releasers": [
    {"id": "analyst-lead-01", "authority": "brand-protection lead"},
    {"id": "counsel-01", "authority": "legal counsel"}
  ],
  "stop_authority": ["duty-manager-01", "analyst_01"],
  "stop_statement": "Calling stop is part of the job and is never held against the person who calls it.",
  "hold_sla_hours": 24
}
```

| Key | Meaning |
|---|---|
| `usable_default` | guidance shown next to the decision controls |
| `ask_contact` | who to ask when a case is unclear |
| `releasers` | people who may release a confirm, each with the authority recorded on the release |
| `stop_authority` | actor ids that may stop and resume the queue |
| `stop_statement` | shown next to the stop control |
| `hold_sla_hours` | review deadline for open holds, positive number |

Unknown keys, duplicate releasers and invalid values are errors, so a misspelt
setting fails at load instead of falling back to a default.

Load order, used by the console and every command alike:

1. `--config <file>` (`--governance` on `bid console`), which must exist;
2. `$BID_DATA_DIR/governance.json`;
3. the bundled example, whose people are placeholders. The console and
   `bid governance status` say when this one is in use.

## Identity in the console

By default the person acting is the name typed into the page. It is recorded
on every receipt and journal record; it is not authenticated. `BID_CONSOLE_TOKEN`
admits people to the console; it does not tell them apart.

Behind an authenticating reverse proxy, set `BID_CONSOLE_ACTOR_HEADER` to the
header the proxy sets (for example `X-Forwarded-User`). The console then takes
the actor from that header only and refuses actions without it. Use this only
when the console is reachable through the proxy alone.

## Journal

`$BID_DATA_DIR/governance.jsonl` holds the records that are not a decision on
one candidate:

| Kind | Written by |
|---|---|
| `queue_halt`, `queue_resume` | console Stop and Resume, `bid governance halt` and `resume` |
| `hold_sla_escalation` | `bid governance escalate` |
| `deployment_attestation` | `bid run --profile`, `bid console --profile` |
| `conduct_scorecard` | `bid conduct` |

Records are chained and signed like receipts (see
[evidence-format.md](evidence-format.md#governance-records)). The console and
the command line write to the same journal.

## Conduct review

`bid conduct` classifies the labelled golden set with the classifier under
review and, independently, with a supervisor model of a different family, then
signs a `conduct_scorecard` into the journal: precision@k, recall, thresholds,
cross-family agreement and drift against the previous scorecard. Same-family
supervision is refused. See [evaluation.md](evaluation.md#conduct-review).

```bash
bid conduct --period 2026-11 --reviewer analyst-lead-01
```
