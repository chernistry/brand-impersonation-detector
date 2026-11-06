"""
Ranking: turn scored candidates into a top-k analyst queue per brand.

The analyst never scrolls thousands of rows. They see a short, high-precision
queue ordered by how likely each item is a real impersonation. Ordering is
deterministic: label severity first, then classifier confidence, then a stable
tiebreak on candidate id so replays are byte-identical.
"""
from __future__ import annotations

from .models import Verdict

# Higher = more urgent for an analyst to look at.
_LABEL_RANK = {
    "fraud": 4,
    "impersonation": 3,
    "suspicious": 2,
    "fan": 1,
    "legit": 0,
}


def rank(verdicts: list[Verdict], k: int | None = None) -> list[Verdict]:
    ordered = sorted(
        verdicts,
        key=lambda v: (_LABEL_RANK.get(v.label, 0), v.confidence, v.candidate_id),
        reverse=True,
    )
    return ordered[:k] if k else ordered
