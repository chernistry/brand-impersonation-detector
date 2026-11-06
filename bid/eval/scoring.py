"""
Fused impersonation score, ablatable by signal group.

`imp_score(signals, mask)` returns a value in [0, 1]. It fuses ONLY the signal
fields NOT listed in `mask`, so an arm can exclude ("ablate") whole signal
groups and we can measure what each group is worth.

The fusion SHAPE is the same one already used by
`bid.feedback.recalibrate` (per-field evidence in [0,1], combined with max):

    handle_edit_distance -> max(0, 1 - ed/6)
    logo_phash_hamming   -> max(0, 1 - ham/32)
    logo_clip_cosine     -> the cosine itself
    domain_intention_mismatch -> 0.9
    domain_in_cti_badlist     -> 1.0

recalibrate does not weigh two boolean tells that the pipeline also computes,
so we extend the SAME boolean-weight shape to them (kept here, not in the
shipped recalibrate, so nothing existing changes):

    alias_in_text        -> 0.6   (brand keyword present in handle/name/bio)
    mixed_script_handle  -> 0.7   (homoglyph / mixed-script tell)

`domain_is_legit` is deliberately not scored: it is evidence AGAINST
impersonation, never a positive contribution.
"""
from __future__ import annotations

from typing import Iterable, Optional

# Every field the fused score can draw on, in a fixed order (determinism).
SCORED_FIELDS: tuple[str, ...] = (
    "handle_edit_distance",
    "alias_in_text",
    "logo_phash_hamming",
    "logo_clip_cosine",
    "domain_intention_mismatch",
    "domain_in_cti_badlist",
    "mixed_script_handle",
)


def _contribution(field: str, signals: dict) -> Optional[float]:
    """Per-field evidence in [0,1], or None when the field says nothing.

    Mirrors bid.feedback.recalibrate's `score()` for the numeric fields and
    extends the same boolean-weight shape to the two extra tells.
    """
    v = signals.get(field)
    if field == "handle_edit_distance":
        return None if v is None else max(0.0, 1.0 - v / 6.0)
    if field == "logo_phash_hamming":
        return None if v is None else max(0.0, 1.0 - v / 32.0)
    if field == "logo_clip_cosine":
        return None if v is None else float(v)
    if field == "domain_intention_mismatch":
        return 0.9 if v else None
    if field == "domain_in_cti_badlist":
        return 1.0 if v else None
    if field == "alias_in_text":
        return 0.6 if v else None
    if field == "mixed_script_handle":
        return 0.7 if v else None
    return None


def imp_score(signals: dict, mask: Iterable[str] = ()) -> float:
    """Fused impersonation score in [0,1] over the signals NOT in `mask`.

    `signals` is a DetSignals.model_dump(). `mask` is the set of field names to
    EXCLUDE. With max-fusion, a strictly smaller mask (more signals included)
    can only raise or hold each candidate's score, never lower it.
    """
    masked = set(mask)
    parts = []
    for field in SCORED_FIELDS:
        if field in masked:
            continue
        c = _contribution(field, signals)
        if c is not None:
            parts.append(c)
    return max(parts) if parts else 0.0
