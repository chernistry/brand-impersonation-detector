# Evaluation

What the bundled measurements show, and what they do not. Every command runs
offline on the bundled fixtures unless `--live` is given.

## The bundled fixtures are small

The labelled set is a handful of fictional brands and candidates written to
cover the attack shapes the pipeline targets: look-alike handles, confusable
characters, copied logos, links to non-official domains, known-bad domains,
fan accounts and legitimate regional accounts. It is a regression and
sensitivity check, not a measure of recall on real traffic. Confidence
intervals over it are wide. Before relying on the numbers, label a sample of
your own traffic and run the same commands on it.

## Commands

| Command | Measures |
|---|---|
| `bid eval` | signal ablation: AUPRC, precision@k and recall as signal groups are added (handle/text, logo pHash, CLIP, domain intention, known-bad domains and confusables); writes `$BID_DATA_DIR/eval_report.json` |
| `bid agreement` | agreement between models of the same family and of different families on the labelled set |
| `bid scale` | a generated corpus (200 candidates by default) through the whole pipeline: per-attack-family recall, confusion matrix, precision, cut ratio, cost and throughput |
| `bid adversarial` | prompt-injection robustness of the hosted classifier: attack success rate on obvious fakes carrying injection payloads, and false positives on legitimate accounts carrying them |
| `bid compare-models` | several hosted models on the same labelled set: precision@k, recall, injection flips, cost and latency |
| `bid replay` | that two runs produce byte-identical signed evidence, and which policy version produced a given receipt |
| `bid conduct` | signed periodic review of the classifier (below) |

Read the results as follows:

- **Ablation.** The ordering is the result: adding signals should not lower
  separation. On the fixtures the handle/text arm scores lower than the full
  signal set; with so few items the absolute values carry little weight. CLIP
  needs the embeddings extra and a model download, so offline it adds nothing.
- **Scale.** The corpus is labelled by construction, one attack family per
  generated candidate. It measures whether the rules and classifier separate the
  families at volume and how fast, not field accuracy.
- **Adversarial.** "Held N of N" holds against a fixed battery of known payloads
  only. Adaptive or optimised attacks are not covered. Report the attack
  success rate per payload class, not one number. The defence under test is
  layered: instruction hierarchy, tagging of untrusted text, a constrained
  output schema, and deterministic signals computed outside the model.
- **Agreement.** Two models of one family share training data and blind
  spots, so their agreement overstates reliability. Cross-family agreement is
  the more informative number.

## Conduct review

`bid conduct` classifies every labelled item twice: with the classifier under
review and, independently, with a supervisor model of a different family.
Same-family supervision is refused. The scorecard is signed into the governance
journal as a `conduct_scorecard` record with:

| Field | Content |
|---|---|
| `subject`, `supervisor` | model id and family of the classifier under review and of the supervisor; `independent` is true because the families differ |
| `metrics` | precision@k and recall of the classifier, the supervisor's recall, and how often the two agree |
| `disagreements` | the items on which the two put the verdict on different sides |
| `golden_set` | label set version, items, positives, items evaluated |
| `thresholds`, `policy_version` | the routing thresholds and policy version in force |
| `drift` | change against the previous scorecard for the same classifier, including a changed label set or policy version |
| `period`, `reviewed_by` | review period and the person who ran it |

```bash
bid conduct --period 2026-11 --reviewer analyst-lead-01
bid conduct --period 2026-11 --reviewer analyst-lead-01 --live \
  --model <classifier model> --supervisor <model of another family>
```

Offline, the classifier under review is the rule-based classifier and the
supervisor is a signal-score classifier.

## Calibration from analyst decisions

Confirms and rejects in the console go to a signed label ledger. From three
labels on, the console can recompute the operating point: one cutoff on the
fused signal score that reaches a precision target on the labelled items (best
F1 when it cannot). The operating point is versioned by hash. It orders the
queue and marks which findings clear the cutoff; it never changes a signed
decision. No model is trained.
