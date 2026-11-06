"""
Dependency-free evaluation metrics: average precision + seeded bootstrap CI.

No sklearn, no numpy. Pure Python so the eval runs anywhere the pipeline runs and is
byte-reproducible.
"""
from __future__ import annotations

import random
from typing import Callable, Sequence


def average_precision(scores: Sequence[float], truths: Sequence[bool]) -> float:
    """Area under the precision-recall curve (standard step sum).

    AP = sum_n (R_n - R_{n-1}) * P_n over predictions sorted by score desc,
    which equals (1/P) * sum over positives of precision-at-their-rank.

    Ties: items with equal score are ordered by original index, so the result
    is deterministic. Returns 0.0 when there are no positives.
    """
    if len(scores) != len(truths):
        raise ValueError("scores and truths must be the same length")
    n = len(scores)
    total_pos = sum(1 for t in truths if t)
    if total_pos == 0:
        return 0.0

    # Sort by score desc, stable on original index for reproducible tie handling.
    order = sorted(range(n), key=lambda i: (-scores[i], i))

    tp = 0
    fp = 0
    prev_recall = 0.0
    ap = 0.0
    for i in order:
        if truths[i]:
            tp += 1
        else:
            fp += 1
        recall = tp / total_pos
        precision = tp / (tp + fp)
        ap += (recall - prev_recall) * precision
        prev_recall = recall
    return ap


def bootstrap_ci(
    scores: Sequence[float],
    truths: Sequence[bool],
    seed: int,
    n_boot: int = 2000,
    alpha: float = 0.05,
    metric: Callable[[Sequence[float], Sequence[bool]], float] = average_precision,
) -> tuple[float, float]:
    """Seeded bootstrap percentile CI for a metric (default 2000 draws).

    Uses Python's random.Random(seed) only -> two calls with the same seed give
    byte-identical bounds. Resamples row indices with replacement.
    """
    m = len(scores)
    if m == 0:
        return (0.0, 0.0)
    rng = random.Random(seed)
    vals = []
    for _ in range(n_boot):
        idx = [rng.randrange(m) for _ in range(m)]
        s = [scores[i] for i in idx]
        t = [truths[i] for i in idx]
        vals.append(metric(s, t))
    vals.sort()
    lo_i = int((alpha / 2.0) * n_boot)
    hi_i = min(n_boot - 1, int((1.0 - alpha / 2.0) * n_boot))
    return (vals[lo_i], vals[hi_i])
