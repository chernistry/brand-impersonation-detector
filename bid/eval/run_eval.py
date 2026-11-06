"""
Run the ablation and emit a compact report.

    python -m bid.eval.run_eval

Prints a scannable table (arm, AUPRC, delta, precision@k, recall) and the
headline shallow->multi-signal lift line, then writes a deterministic
$BID_DATA_DIR/eval_report.json (no timestamps, byte-reproducible).

Note: this is sensitivity on a small curated battery, not field
recall. n is tiny, so bootstrap CIs are wide. The number that matters is the
ORDERING (multi-signal >= shallow), not the absolute AUPRC.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from .. import paths
from ..storage import ContentStore
from .ablation import run_ablation
from .dataset import TEST_SPLIT_PCT, load_labeled
from .metrics_eval import average_precision, bootstrap_ci
from .scoring import imp_score

# Fixed seed so the bootstrap is byte-reproducible on re-run.
BOOTSTRAP_SEED = 20260712
BOOTSTRAP_DRAWS = 2000

CAVEAT = (
    "Sensitivity on a small curated battery, not field recall. "
    "n is tiny at this stage, so bootstrap CIs are wide; the load-bearing "
    "result is the ORDERING (multi-signal >= handle/text-only), not the "
    "absolute AUPRC. CLIP (arm C) is inactive in the offline path because the "
    "embeddings tier needs a model download; arm C therefore equals arm B here."
)


def _split_counts(rows: list[dict]) -> dict:
    def count(split):
        sub = [r for r in rows if r["split"] == split]
        return {"n": len(sub), "positives": sum(1 for r in sub if r["truth"])}

    return {"train": count("train"), "test": count("test")}


def _arm_ci(rows: list[dict], mask_included_key: str, arms: list[dict]) -> tuple[float, float]:
    """Bootstrap CI on the test-split AUPRC for the arm with the given key."""
    from .ablation import ARMS  # resolve the exclusion mask for this arm

    mask = set(next(a for a in ARMS if a["key"] == mask_included_key)["mask"])
    test = [r for r in rows if r["split"] == "test"]
    scores = [imp_score(r["signals"], mask) for r in test]
    truths = [r["truth"] for r in test]
    lo, hi = bootstrap_ci(
        scores, truths, seed=BOOTSTRAP_SEED, n_boot=BOOTSTRAP_DRAWS, metric=average_precision
    )
    return (round(lo, 4), round(hi, 4))


def build_report(rows: list[dict]) -> dict:
    arms = run_ablation(rows, split="test")
    a = arms[0]
    e = arms[-1]
    report = {
        "dataset": {
            "n_total": len(rows),
            "test_split_pct": TEST_SPLIT_PCT,
            "split_counts": _split_counts(rows),
        },
        "arms": arms,
        "headline": {
            "shallow_arm": a["key"],
            "shallow_auprc": a["auprc"],
            "full_arm": e["key"],
            "full_auprc": e["auprc"],
            "lift": round(e["auprc"] - a["auprc"], 4),
        },
        "bootstrap": {
            "seed": BOOTSTRAP_SEED,
            "draws": BOOTSTRAP_DRAWS,
            "auprc_ci95": {
                a["key"]: _arm_ci(rows, a["key"], arms),
                e["key"]: _arm_ci(rows, e["key"], arms),
            },
        },
        "caveat": CAVEAT,
    }
    return report


def _print_table(report: dict) -> None:
    dc = report["dataset"]["split_counts"]
    print("=" * 66)
    print("MULTI-SIGNAL ABLATION  (test split only)")
    print("=" * 66)
    print(
        f"dataset: {report['dataset']['n_total']} candidates | "
        f"train n={dc['train']['n']} (pos {dc['train']['positives']}) | "
        f"test n={dc['test']['n']} (pos {dc['test']['positives']})"
    )
    print("-" * 66)
    print(f"{'arm':>3}  {'signals added':<24} {'AUPRC':>6} {'Δ':>6} {'P@5':>5} {'rec':>5}")
    print("-" * 66)
    for a in report["arms"]:
        print(
            f"{a['key']:>3}  {a['label']:<24} "
            f"{a['auprc']:>6.2f} {a['delta_prev']:>+6.2f} "
            f"{a['precision_at_k']:>5.2f} {a['recall']:>5.2f}"
        )
    print("-" * 66)
    h = report["headline"]
    ci = report["bootstrap"]["auprc_ci95"]
    print(
        f"HEADLINE: A(shallow)={h['shallow_auprc']:.2f} -> "
        f"E(multi-signal)={h['full_auprc']:.2f}, "
        f"Δ{h['lift']:+.2f}"
    )
    print(
        f"  95% CI ({report['bootstrap']['draws']} draws, seed "
        f"{report['bootstrap']['seed']}):  "
        f"A={ci[h['shallow_arm']]}  E={ci[h['full_arm']]}"
    )
    print("-" * 66)
    print("NOTE:", report["caveat"])
    print("=" * 66)


def main(argv: list[str] | None = None) -> int:
    with tempfile.TemporaryDirectory() as d:
        store = ContentStore(Path(d))
        rows = load_labeled(store)
    report = build_report(rows)
    _print_table(report)
    report_path = paths.data_dir() / "eval_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"report -> {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
