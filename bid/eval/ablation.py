"""
Ordered ablation arms.

Each arm progressively ADDS a signal group. An arm is expressed as the set of
fields it EXCLUDES (its `mask`); scoring fuses everything not excluded, so arm A
sees the fewest signals and arm E sees them all.

    A = handle/text distance only
    B = A + pHash (logo_phash_hamming)
    C = B + CLIP (logo_clip_cosine)
    D = C + domain-intention (domain_intention_mismatch)
    E = D + CTI domain join (domain_in_cti_badlist) + homoglyph (mixed_script_handle)

Because included(A) subset of included(B) ... subset of included(E), every
candidate's fused score is monotone non-decreasing A -> E (max-fusion). The
empirical question the metrics answer is whether that added signal SEPARATES
positives from negatives better, not merely raises everyone.

All arm metrics are computed on the TEST split only.
"""
from __future__ import annotations

from .metrics_eval import average_precision
from .scoring import SCORED_FIELDS, imp_score

# (key, human label, fields this arm ADDS on top of the previous arm)
_ARM_ADDS: list[tuple[str, str, set[str]]] = [
    ("A", "handle/text distance", {"handle_edit_distance", "alias_in_text"}),
    ("B", "+ pHash", {"logo_phash_hamming"}),
    ("C", "+ CLIP", {"logo_clip_cosine"}),
    ("D", "+ domain-intention", {"domain_intention_mismatch"}),
    ("E", "+ CTI join + homoglyph", {"domain_in_cti_badlist", "mixed_script_handle"}),
]


def build_arms() -> list[dict]:
    """Resolve each arm to its cumulative included set and its exclusion mask."""
    all_fields = set(SCORED_FIELDS)
    included: set[str] = set()
    arms = []
    for key, label, adds in _ARM_ADDS:
        included = included | adds
        arms.append(
            {
                "key": key,
                "label": label,
                "included": sorted(included),
                "mask": sorted(all_fields - included),
            }
        )
    return arms


ARMS = build_arms()


def _precision_at_k(scored: list[tuple[float, bool, str]], k: int) -> float:
    """scored: (score, truth, candidate_id). Sorted desc, stable tiebreak on id."""
    if not scored:
        return 0.0
    ordered = sorted(scored, key=lambda x: (-x[0], x[2]))
    topk = ordered[: max(0, k)]
    if not topk:
        return 0.0
    return sum(1 for _, t, _ in topk if t) / len(topk)


def _best_f1(scores: list[float], truths: list[bool]) -> dict:
    """Sweep 0..1 (0.01 steps, same grid shape as recalibrate) for best F1.

    Returns precision / recall / f1 / threshold at the best-F1 operating point.
    """
    total_pos = sum(1 for t in truths if t) or 1
    best = {"threshold": 1.0, "precision": 0.0, "recall": 0.0, "f1": 0.0}
    for i in range(0, 101):
        thr = i / 100.0
        tp = sum(1 for s, t in zip(scores, truths, strict=True) if s >= thr and t)
        fp = sum(1 for s, t in zip(scores, truths, strict=True) if s >= thr and not t)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / total_pos
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        if f1 > best["f1"]:
            best = {
                "threshold": round(thr, 2),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(f1, 4),
            }
    return best


def run_ablation(rows: list[dict], split: str = "test", k: int = 5) -> list[dict]:
    """Score every arm on `split` and return per-arm metrics + A->E deltas.

    rows: output of dataset.load_labeled (each has signals, truth, split).
    """
    subset = [r for r in rows if r["split"] == split]
    results = []
    prev_auprc = None
    baseline_auprc = None
    for arm in ARMS:
        mask = set(arm["mask"])
        scored = [
            (imp_score(r["signals"], mask), r["truth"], r["candidate_id"])
            for r in subset
        ]
        scores = [s for s, _, _ in scored]
        truths = [t for _, t, _ in scored]

        auprc = average_precision(scores, truths)
        if baseline_auprc is None:
            baseline_auprc = auprc
        f1pt = _best_f1(scores, truths)
        results.append(
            {
                "key": arm["key"],
                "label": arm["label"],
                "included": arm["included"],
                "auprc": round(auprc, 4),
                "delta_prev": round(auprc - prev_auprc, 4) if prev_auprc is not None else 0.0,
                "lift_vs_A": round(auprc - baseline_auprc, 4),
                "precision_at_k": round(_precision_at_k(scored, k), 4),
                "recall": f1pt["recall"],
                "f1": f1pt["f1"],
                "best_f1_threshold": f1pt["threshold"],
            }
        )
        prev_auprc = auprc
    return results
