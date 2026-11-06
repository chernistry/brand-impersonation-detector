"""
Cross-family agreement on the labelled fixtures.

Two models of one family tend to agree because they share training data and
blind spots, so same-family agreement overstates how reliable a check is. This
report puts the two numbers side by side.

    python -m bid.eval.agreement
"""
from __future__ import annotations

import json
import tempfile
from itertools import combinations
from pathlib import Path

from ..classify import MockClassifier, SignalScoreClassifier, label_side
from ..families import model_family
from ..models import Brand, Candidate
from ..run_pipeline import load_cti_badlist
from ..storage import ContentStore
from .dataset import enumerate_candidates


def _mean(xs: list[float]) -> float | None:
    return round(sum(xs) / len(xs), 3) if xs else None


def agreement_report(classifiers: list, items: list[tuple[Candidate, Brand]]) -> dict:
    """Pairwise side agreement (positive / negative / uncertain) of every
    classifier pair on the same items, with the same-family flag per pair."""
    sides: dict[str, dict[str, str]] = {}
    for clf in classifiers:
        sides[clf.model_id] = {c.id: label_side(clf.classify(c, b).label) for c, b in items}

    pairs = []
    for a, b in combinations(classifiers, 2):
        shared = sorted(set(sides[a.model_id]) & set(sides[b.model_id]))
        agree = sum(1 for cid in shared if sides[a.model_id][cid] == sides[b.model_id][cid])
        fa, fb = model_family(a.model_id), model_family(b.model_id)
        pairs.append({
            "a": a.model_id, "b": b.model_id,
            "family_a": fa, "family_b": fb, "same_family": fa == fb,
            "agreement": round(agree / len(shared), 3) if shared else 0.0,
            "n": len(shared),
        })
    pairs.sort(key=lambda p: (p["a"], p["b"]))
    return {
        "pairs": pairs,
        "same_family_mean": _mean([p["agreement"] for p in pairs if p["same_family"]]),
        "cross_family_mean": _mean([p["agreement"] for p in pairs if not p["same_family"]]),
    }


def main(argv: list[str] | None = None) -> int:
    cti = load_cti_badlist()
    with tempfile.TemporaryDirectory() as d:
        candidates, brand_by_id = enumerate_candidates(ContentStore(Path(d)))
        items = [(c, brand_by_id[c.brand_id]) for c in candidates]
        report = agreement_report([MockClassifier(cti), SignalScoreClassifier(cti)], items)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
