"""
Metrics the pipeline prints.

precision@k    - of the top-k ranked candidates, the fraction that are truly
                 impersonations (per the hand-labeled fixture set).
recall         - of all truly-impersonating candidates, the fraction the pipeline
                 surfaced above the "flag" threshold. A check on how much the
                 configured sensor set can see.
cut_ratio      - fraction of candidates the cheap filters dropped before any LLM
                 call. Shows how much work the cascade removes.

Ground truth lives in fixtures/labels.json: {candidate_id: is_impersonation}.
"""
from __future__ import annotations

from .models import Verdict

# Labels the pipeline treats as a positive impersonation call.
POSITIVE_LABELS = {"impersonation", "fraud"}


def precision_at_k(ranked: list[Verdict], truth: dict[str, bool], k: int) -> float:
    # Only labeled candidates count: in broad mode live sensors emit candidates
    # that have no ground-truth label, and silently scoring them as False would
    # corrupt the metric in both directions.
    labeled = [v for v in ranked if v.candidate_id in truth]
    topk = labeled[:k]
    if not topk:
        return 0.0
    hits = sum(1 for v in topk if truth[v.candidate_id])
    # Strict p@k divides by k, not len(topk): with fewer than k labeled
    # candidates the metric degrades instead of silently inflating.
    return hits / k


def recall(verdicts: list[Verdict], truth: dict[str, bool]) -> float:
    positives = [cid for cid, is_imp in truth.items() if is_imp]
    if not positives:
        return 0.0
    flagged = {
        v.candidate_id for v in verdicts if v.label in POSITIVE_LABELS
    }
    found = sum(1 for cid in positives if cid in flagged)
    return found / len(positives)


def cut_ratio(total_in: int, survivors: int) -> float:
    if total_in == 0:
        return 0.0
    return 1.0 - (survivors / total_in)
