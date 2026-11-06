"""
Deterministic labeled dataset for the ablation.

We enumerate candidates the SAME way run_pipeline does so the eval measures the
real pipeline surface, not a parallel toy:

    sensors (LocalSearch, MetaAdLibrary) over every brand
        -> normalize (content-address assets, compute pHash)
        -> dedup
        -> stage_a() to compute the Stage-A DetSignals
        -> pair with hand-labeled ground truth (load_labels)

Train/test split is a pure function of the candidate id, so it is byte-stable
and needs no RNG:

    sha256(candidate_id) % 100 < 40   -> "test"   (else "train")

The split is a hash over the id, which spreads both brands across both sides
(the ids embed the brand), so neither side collapses to a single brand.
"""
from __future__ import annotations

import hashlib

from ..filters import stage_a
from ..normalize import dedup, normalize
from ..run_pipeline import (
    FIXED_NOW,
    load_brands,
    load_cti_badlist,
    load_labels,
)
from ..sensors.local_search import LocalSearchSensor
from ..sensors.meta_ad_library import MetaAdLibrarySensor
from ..storage import ContentStore

# Fraction (percent) of the id-hash space routed to the held-out test split.
TEST_SPLIT_PCT = 40


def split_of(candidate_id: str) -> str:
    """Deterministic split: hash the id, route < TEST_SPLIT_PCT %% to test."""
    h = int(hashlib.sha256(candidate_id.encode("utf-8")).hexdigest(), 16)
    return "test" if (h % 100) < TEST_SPLIT_PCT else "train"


def enumerate_candidates(store: ContentStore):
    """Rebuild the exact candidate set the pipeline classifies, in order.

    Same sensors, same normalize + dedup as bid.run_pipeline.run().
    Returns (candidates, brand_by_id).
    """
    brands = load_brands(embeddings=False)  # offline: no CLIP model download
    sensors = [LocalSearchSensor(), MetaAdLibrarySensor()]
    candidates = []
    for brand in brands:
        for sensor in sensors:
            for obs in sensor.scan(brand, since=FIXED_NOW):
                candidates.append(normalize(obs, brand, store))
    candidates = dedup(candidates)
    brand_by_id = {b.id: b for b in brands}
    return candidates, brand_by_id


def load_labeled(store: ContentStore) -> list[dict]:
    """Labeled rows for the ablation.

    Each row: {candidate_id, brand, signals(DetSignals.model_dump()),
               truth(bool positive), split}.

    `signals` is the frozen Stage-A DetSignals, exactly what the classifier and
    the feedback recalibration see. `truth` is True iff the fixture ground truth
    marks the candidate as a real impersonation.
    """
    cti = load_cti_badlist()
    labels = load_labels()  # {candidate_id: bool}
    candidates, brand_by_id = enumerate_candidates(store)

    rows: list[dict] = []
    for c in candidates:
        brand = brand_by_id[c.brand_id]
        signals, _keep = stage_a(c, brand, cti)
        rows.append(
            {
                "candidate_id": c.id,
                "brand": c.brand_id,
                "signals": signals.model_dump(),
                "truth": bool(labels.get(c.id, False)),
                "split": split_of(c.id),
            }
        )
    return rows
