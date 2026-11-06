"""
Model comparison harness: cheap vs mid vs expensive on the SAME labeled set.

Answers "is the expensive model worth it here?" empirically. For each model it
runs the real multimodal classifier over the Stage-A survivors and reports:
precision@k, recall vs the frozen labels, injection-flip rate, real USD cost
(measured as the OpenRouter budget delta), and latency.

    python -m bid.compare_models              # default 3-model panel
    python -m bid.compare_models --models google/gemini-2.5-flash-lite,google/gemini-2.5-pro

Cost is tiny (dozens of images x a few models = fractions of a cent). Cache makes
re-runs free; the first run per model is the real spend the table reports.
"""
from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from . import net, paths
from .classify import OpenRouterClassifier, api_key
from .filters import stage_a
from .metrics import precision_at_k, recall
from .models import Verdict
from .normalize import dedup, normalize
from .rank import _LABEL_RANK
from .run_pipeline import (
    FIXED_NOW,
    load_brands,
    load_cti_badlist,
    load_labels,
    load_dotenv,
)
from .sensors.local_search import LocalSearchSensor
from .sensors.meta_ad_library import MetaAdLibrarySensor
from .storage import ContentStore

DEFAULT_MODELS = [
    "google/gemini-2.5-flash-lite",  # cheap
    "google/gemini-2.5-flash",       # mid
    "google/gemini-2.5-pro",         # expensive
]


def _budget_used() -> float:
    """OpenRouter credit used so far; NaN unless the model endpoint is OpenRouter,
    so no other endpoint's key is ever sent there."""
    from . import classify

    key = os.environ.get("OPENROUTER_API_KEY")
    if not key or not classify.is_openrouter_url(classify.base_url):
        return float("nan")
    try:
        j = net.get(
            "classifier",
            "https://openrouter.ai/api/v1/key",
            headers={"Authorization": f"Bearer {key}"},
            timeout=30,
        ).json()["data"]
        return float(j["usage"])
    except Exception:
        return float("nan")


def _score_key(v: Verdict):
    return (_LABEL_RANK.get(v.label, 0), v.confidence, v.candidate_id)


def build_survivors(store: ContentStore):
    brands = load_brands()
    cti = load_cti_badlist()
    brand_by_id = {b.id: b for b in brands}
    sensors = [LocalSearchSensor(), MetaAdLibrarySensor()]
    cands = []
    for brand in brands:
        for sensor in sensors:
            for obs in sensor.scan(brand, since=FIXED_NOW):
                cands.append(normalize(obs, brand, store))
    cands = dedup(cands)
    survivors = [c for c in cands if stage_a(c, brand_by_id[c.brand_id], cti)[1]]
    return survivors, brand_by_id, cti


def evaluate(model: str, survivors, brand_by_id, cti, store) -> dict:
    clf = OpenRouterClassifier(
        cti_badlist=cti, model=model, store=store,
        cache_dir=paths.cache_dir("compare-models"),
    )
    before = _budget_used()
    t0 = time.perf_counter()
    verdicts = [clf.classify(c, brand_by_id[c.brand_id]) for c in survivors]
    dt = time.perf_counter() - t0
    after = _budget_used()
    labels = load_labels()
    ranked = sorted(verdicts, key=_score_key, reverse=True)
    inj_seen = sum(1 for v in verdicts if v.injection_flagged)
    inj_flip = sum(1 for v in verdicts if v.injection_flagged and v.label == "legit")
    return {
        "model": model,
        "p5": precision_at_k(ranked, labels, 5),
        "p10": precision_at_k(ranked, labels, 10),
        "recall": recall(verdicts, labels),
        "inj_seen": inj_seen,
        "inj_flip": inj_flip,
        "cost": (after - before) if after == after and before == before else float("nan"),
        "latency_s": dt,
        "n": len(verdicts),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Compare classifier models on the labeled set")
    ap.add_argument("--models", default=",".join(DEFAULT_MODELS))
    ap.add_argument("--store", default=str(paths.store_dir("compare-models")))
    args = ap.parse_args(argv)
    load_dotenv()
    if not api_key():
        print("No API key for the model endpoint (BID_LLM_API_KEY or OPENROUTER_API_KEY); "
              "cannot compare live models.")
        return 1

    store = ContentStore(Path(args.store))
    survivors, brand_by_id, cti = build_survivors(store)
    models = [m.strip() for m in args.models.split(",") if m.strip()]

    print(f"Comparing {len(models)} models on {len(survivors)} survivors "
          f"(positive labels = impersonation|fraud)\n")
    rows = []
    for m in models:
        print(f"  running {m} ...", flush=True)
        rows.append(evaluate(m, survivors, brand_by_id, cti, store))

    print("\n" + "=" * 96)
    hdr = f"{'model':34s} {'P@5':>5} {'P@10':>5} {'recall':>7} {'inj_flip':>9} {'cost$':>10} {'lat_s':>7}"
    print(hdr)
    print("-" * 96)
    for r in rows:
        print(f"{r['model']:34s} {r['p5']:5.2f} {r['p10']:5.2f} {r['recall']:7.2f} "
              f"{r['inj_flip']:>3}/{r['inj_seen']:<5} {r['cost']:10.6f} {r['latency_s']:7.2f}")
    print("=" * 96)
    # verdict
    best = max(rows, key=lambda r: (r["recall"], r["p10"]))
    cheap = rows[0]
    print(f"\nCheapest: {cheap['model']}  recall {cheap['recall']:.2f}  cost ${cheap['cost']:.6f}")
    print(f"Best recall: {best['model']}  recall {best['recall']:.2f}  cost ${best['cost']:.6f}")
    lift = best["recall"] - cheap["recall"]
    print(f"Recall lift from cheapest -> best: {lift:+.2f} for "
          f"${best['cost'] - cheap['cost']:+.6f} extra on this set.")
    print("Takeaway: on the account-free vector the cheap model is usually enough; "
          "reserve the expensive model for the top-k recheck, not the whole queue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
