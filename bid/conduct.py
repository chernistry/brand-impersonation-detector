"""
Conduct review of a classifier on the frozen golden set.

A review classifies every labelled fixture item twice: with the classifier
under review and, independently, with a supervisor model from a different model
family. The scorecard records detection quality (precision@k, recall), the
thresholds and label set in force, how often the two families agree, and drift
against the previous scorecard for the same classifier. It is signed into the
governance journal as a conduct_scorecard record, so each review has a
signature and a place in the chain.

Same-family supervision is refused: two models of one family share training
data and blind spots, so their agreement says little about either.

    bid conduct --period 2026-11 --reviewer brand-protection-lead \
        --journal .bid/governance.jsonl --now 2026-11-30T12:00:00Z

Offline, the classifier under review is the rule-based classifier and the
supervisor is the signal-score classifier; --model and --supervisor select
hosted models (with --live and an API key for the endpoint).
"""
from __future__ import annotations

import argparse
import json
import tempfile
from datetime import datetime
from pathlib import Path

from .classify import label_side
from .evidence import _hash
from .families import model_family
from .filters import stage_a
from .metrics import POSITIVE_LABELS, precision_at_k, recall
from .models import Brand, Candidate, GovernancePackage
from .policy import current_thresholds, policy_version
from .rank import rank

SCORECARD_SCHEMA = "bid.conduct_scorecard/v1"
METRIC_KEYS = ("precision_at_5", "precision_at_10", "recall")


def golden_set(store) -> tuple[list[tuple[Candidate, Brand]], dict[str, bool], str]:
    """The labelled fixture items, their labels, and a version hash of both.

    The version changes when any labelled candidate or any label changes, so a
    scorecard says exactly which golden set it was measured on.
    """
    from .eval.dataset import enumerate_candidates
    from .run_pipeline import load_labels

    labels = load_labels()
    candidates, brand_by_id = enumerate_candidates(store)
    items = [(c, brand_by_id[c.brand_id]) for c in candidates if c.id in labels]
    version = _hash({c.id: [labels[c.id], _hash(c.model_dump(mode="json", exclude={"first_seen"}))]
                     for c, _ in items})[:16]
    return items, {c.id: labels[c.id] for c, _ in items}, version


def _quality(verdicts, truth: dict[str, bool]) -> dict:
    ranked = rank(verdicts)
    return {
        "precision_at_5": round(precision_at_k(ranked, truth, 5), 3),
        "precision_at_10": round(precision_at_k(ranked, truth, 10), 3),
        "recall": round(recall(verdicts, truth), 3),
    }


def _previous(journal: list[GovernancePackage], model_id: str) -> dict | None:
    for g in reversed(journal):
        if g.record.kind == "conduct_scorecard" and g.record.subject == model_id:
            from .governance import record_hash
            return {"record_hash": record_hash(g), "payload": g.record.payload}
    return None


def _drift(card: dict, previous: dict | None) -> dict | None:
    if previous is None:
        return None
    before = previous["payload"]
    old_thr = before.get("thresholds", {})
    return {
        "previous_record_hash": previous["record_hash"],
        "previous_period": before.get("period"),
        **{k: round(card["metrics"][k] - before.get("metrics", {}).get(k, 0.0), 3) for k in METRIC_KEYS},
        "thresholds_changed": sorted(k for k in set(card["thresholds"]) | set(old_thr)
                                     if card["thresholds"].get(k) != old_thr.get(k)),
        "label_set_changed": card["golden_set"]["label_set_version"]
        != before.get("golden_set", {}).get("label_set_version"),
        "policy_version_changed": card["policy_version"] != before.get("policy_version"),
    }


def scorecard(classifier, supervisor, items: list[tuple[Candidate, Brand]], truth: dict[str, bool],
              *, label_set_version: str, period: str, reviewed_by: str,
              cti: set[str], previous: dict | None = None) -> dict:
    """Measure `classifier` on the golden set and have `supervisor` check it.

    Raises ValueError when both come from the same model family.
    """
    fam_c, fam_s = model_family(classifier.model_id), model_family(supervisor.model_id)
    if fam_c == fam_s:
        raise ValueError(f"supervisor {supervisor.model_id!r} is in the same model family ({fam_c}) "
                         f"as the classifier {classifier.model_id!r}; use a different family")
    survivors = [(c, b) for c, b in items if stage_a(c, b, cti)[1]]
    mine = [classifier.classify(c, b) for c, b in survivors]
    theirs = {v.candidate_id: v for v in (supervisor.classify(c, b) for c, b in survivors)}
    disagreements = sorted(v.candidate_id for v in mine
                           if label_side(v.label) != label_side(theirs[v.candidate_id].label))
    template = next((v.prompt_template for v in mine if v.prompt_template), "")
    card = {
        "schema": SCORECARD_SCHEMA,
        "period": period,
        "reviewed_by": reviewed_by,
        "subject": {"model_id": classifier.model_id, "family": fam_c, "prompt_template": template},
        "supervisor": {"model_id": supervisor.model_id, "family": fam_s},
        "independent": True,
        "golden_set": {
            "label_set_version": label_set_version,
            "items": len(items),
            "positives": sum(1 for v in truth.values() if v),
            "evaluated": len(survivors),
        },
        "policy_version": policy_version(classifier.model_id),
        "thresholds": current_thresholds(),
        "metrics": {
            **_quality(mine, truth),
            "supervisor_recall": round(recall(list(theirs.values()), truth), 3),
            "supervisor_agreement": round(1 - len(disagreements) / len(mine), 3) if mine else None,
            "flagged_positive": sum(1 for v in mine if v.label in POSITIVE_LABELS),
        },
        "disagreements": disagreements,
    }
    card["drift"] = _drift(card, previous)
    return card


def run_review(journal, *, period: str, reviewer: str, now: datetime,
               classifier=None, supervisor=None, store=None) -> GovernancePackage:
    """Score the classifier, then sign the scorecard into the governance journal
    as a conduct_scorecard record (actor = the reviewer)."""
    from .classify import MockClassifier, SignalScoreClassifier
    from .run_pipeline import load_cti_badlist
    from .storage import ContentStore

    cti = load_cti_badlist()
    classifier = classifier or MockClassifier(cti)
    supervisor = supervisor or SignalScoreClassifier(cti)
    with tempfile.TemporaryDirectory() as tmp:
        items, truth, version = golden_set(store or ContentStore(Path(tmp)))
        card = scorecard(classifier, supervisor, items, truth, label_set_version=version,
                         period=period, reviewed_by=reviewer, cti=cti,
                         previous=_previous(journal.packages(), classifier.model_id))
    return journal.append("conduct_scorecard", reviewer, now, authority="conduct-review",
                          subject=classifier.model_id, payload=card)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Signed conduct review of a classifier on the golden set")
    ap.add_argument("--period", required=True, help="review period, for example 2026-11")
    ap.add_argument("--reviewer", required=True, help="who owns and signs the review")
    ap.add_argument("--journal", type=Path, help="governance journal (default: $BID_DATA_DIR/governance.jsonl)")
    ap.add_argument("--now", help="review time, ISO 8601 (default: now, UTC)")
    ap.add_argument("--hmac-key", default=None, help="journal HMAC key (default: the built-in demo key)")
    ap.add_argument("--live", action="store_true", help="review hosted models (needs an API key for the endpoint)")
    ap.add_argument("--model", default=None, help="hosted classifier under review (with --live)")
    ap.add_argument("--supervisor", default=None, help="hosted supervisor model (with --live)")
    args = ap.parse_args(argv)

    from .evidence import DEFAULT_HMAC_KEY, Ed25519Dsse
    from .governance import GovernanceJournal

    classifier = supervisor = None
    if args.live:
        from .classify import OpenRouterClassifier
        from .run_pipeline import load_cti_badlist, load_dotenv
        load_dotenv()
        cti = load_cti_badlist()
        classifier = OpenRouterClassifier(cti, model=args.model) if args.model else None
        supervisor = OpenRouterClassifier(cti, model=args.supervisor) if args.supervisor else None
    from . import paths
    from .governance import _cli_now

    journal = GovernanceJournal(args.journal or paths.data_dir() / "governance.jsonl",
                                hmac_key=args.hmac_key or DEFAULT_HMAC_KEY, dsse=Ed25519Dsse())
    now = _cli_now(args.now)
    pkg = run_review(journal, period=args.period, reviewer=args.reviewer, now=now,
                     classifier=classifier, supervisor=supervisor)
    print(json.dumps(pkg.record.payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
