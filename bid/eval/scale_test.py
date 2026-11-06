"""
Scale / stress test: run a 200-candidate synthetic corpus through the WHOLE
pipeline and report per-attack-family recall, a confusion matrix, precision,
cut-ratio, cost and throughput.

    python -m bid.eval.scale_test                 # mock classifier (deterministic, free)
    python -m bid.eval.scale_test --live --n 20   # spot-check N with the real model
    python -m bid.eval.scale_test --per-brand 100 # corpus size (per brand)

Interpretation: the corpus is SELF-LABELLED by construction -
each candidate is generated from a known attack family, so this measures whether
the pipeline's rules + classifier correctly separate the families AT VOLUME and
how fast, NOT field accuracy on real traffic. It is a throughput + coverage +
regression stress test, the complement to the live broad-discovery run (which
finds real lookalikes but has no ground truth). Two runs are byte-identical.
"""
from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from pathlib import Path

from .. import paths
from ..classify import build_classifier
from ..filters import stage_a
from ..normalize import normalize
from ..run_pipeline import load_brands, load_cti_badlist
from ..storage import ContentStore
from .corpus import FRAUD_FAMILIES, POSITIVE_FAMILIES, generate_corpus

_POS_LABELS = {"impersonation", "fraud"}


def run_scale(store_dir: Path, per_brand: int = 100, live: bool = False,
              live_n: int = 0, model: str | None = None) -> dict:
    store = ContentStore(store_dir)
    brands = load_brands()
    brand_by_id = {b.id: b for b in brands}
    cti = load_cti_badlist()
    corpus = generate_corpus(per_brand=per_brand, brands=brands)

    classifier = build_classifier(cti, store=store, model=model, live=live)

    per_family = defaultdict(lambda: {"n": 0, "kept": 0, "flagged": 0, "fraud": 0, "correct_gran": 0})
    tp = fp = tn = fn = 0
    total_cost = 0.0
    n_classified = 0
    t0 = time.perf_counter()

    for obs, brand_id, family, is_pos in corpus:
        cand = normalize(obs, brand_by_id[brand_id], store)
        signals, keep = stage_a(cand, brand_by_id[brand_id], cti)
        fam = per_family[family]
        fam["n"] += 1
        # A dropped candidate is a hard negative prediction (not surfaced).
        pred_pos = False
        if keep:
            fam["kept"] += 1
            do_live = live and (live_n == 0 or n_classified < live_n)
            if do_live:
                v = classifier.classify(cand, brand_by_id[brand_id])
                total_cost += v.cost_usd
                n_classified += 1
                label = v.label
            else:
                # deterministic mock rubric (free) - the default for the full sweep
                from ..classify import MockClassifier
                v = MockClassifier(cti).classify(cand, brand_by_id[brand_id])
                label = v.label
            pred_pos = label in _POS_LABELS
            if pred_pos:
                fam["flagged"] += 1
                if label == "fraud":
                    fam["fraud"] += 1
                # ideal granularity: fraud families should be labelled fraud
                want_fraud = family in FRAUD_FAMILIES
                if (label == "fraud") == want_fraud:
                    fam["correct_gran"] += 1
        # confusion
        if is_pos and pred_pos:
            tp += 1
        elif is_pos and not pred_pos:
            fn += 1
        elif not is_pos and pred_pos:
            fp += 1
        else:
            tn += 1

    elapsed = time.perf_counter() - t0
    total = len(corpus)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    fam_rows = {}
    for fam_name, d in per_family.items():
        pos_family = fam_name in POSITIVE_FAMILIES
        # recall for a positive family = fraction flagged; specificity for benign = fraction NOT flagged
        rate = (d["flagged"] / d["n"]) if d["n"] else 0.0
        fam_rows[fam_name] = {
            "n": d["n"], "kept": d["kept"], "flagged": d["flagged"],
            "positive_family": pos_family,
            "recall" if pos_family else "false_positive_rate": round(rate, 3),
            "fraud_granularity": round(d["correct_gran"] / d["flagged"], 3) if (fam_name in FRAUD_FAMILIES and d["flagged"]) else None,
        }

    return {
        "total": total, "per_brand": per_brand, "brands": [b.id for b in brands],
        "classifier": classifier.model_id, "live_classified": n_classified,
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
        "cut_ratio": round(1.0 - sum(d["kept"] for d in per_family.values()) / total, 3),
        "throughput_per_s": round(total / elapsed, 1) if elapsed else None,
        "elapsed_s": round(elapsed, 3),
        "cost_usd": round(total_cost, 6),
        "per_family": fam_rows,
    }


def _print(rep: dict) -> None:
    print("=" * 70)
    print(f"SCALE / STRESS TEST  -  {rep['total']} synthetic candidates, {len(rep['brands'])} brands")
    print("=" * 70)
    c = rep["confusion"]
    print(f"classifier      : {rep['classifier']}  (live-classified: {rep['live_classified']})")
    print(f"precision/recall: {rep['precision']:.3f} / {rep['recall']:.3f}   F1 {rep['f1']:.3f}")
    print(f"confusion       : TP={c['tp']}  FP={c['fp']}  TN={c['tn']}  FN={c['fn']}")
    print(f"cut ratio       : {rep['cut_ratio']:.0%} dropped by cheap filters before any classify")
    print(f"throughput      : {rep['throughput_per_s']}/s  ({rep['elapsed_s']}s total)   cost ${rep['cost_usd']:.5f}")
    print("-" * 70)
    print(f"{'family':16s}{'n':>4}{'kept':>6}{'flagged':>9}{'rate':>7}  role")
    for fam, d in sorted(rep["per_family"].items(), key=lambda kv: (not kv[1]["positive_family"], kv[0])):
        rate = d.get("recall", d.get("false_positive_rate"))
        role = "recall (want high)" if d["positive_family"] else "FPR (want low)"
        gran = f"  fraud-gran {d['fraud_granularity']}" if d.get("fraud_granularity") is not None else ""
        print(f"{fam:16s}{d['n']:>4}{d['kept']:>6}{d['flagged']:>9}{rate:>7.2f}  {role}{gran}")
    print("=" * 70)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Pipeline scale / stress test")
    ap.add_argument("--per-brand", type=int, default=100)
    ap.add_argument("--live", action="store_true", help="classify (a sample of) survivors with the real model")
    ap.add_argument("--n", type=int, default=0, help="with --live, cap live classifications (0 = all)")
    ap.add_argument("--model", default=None)
    ap.add_argument("--store", default=None, help="run directory (default: $BID_DATA_DIR/scale)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    if args.live:
        from ..run_pipeline import load_dotenv
        load_dotenv()
    store_dir = Path(args.store) if args.store else paths.store_dir("scale")
    rep = run_scale(store_dir, per_brand=args.per_brand, live=args.live, live_n=args.n, model=args.model)
    (store_dir / "scale_report.json").write_text(json.dumps(rep, indent=1))
    if args.json:
        print(json.dumps(rep, indent=1))
    else:
        _print(rep)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
