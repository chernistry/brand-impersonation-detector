"""
Ablation-eval invariants. Run: pytest -q  (from the repo root).

Pins the empirical property and the determinism discipline of the eval package:
the split is byte-stable and covers both sides, AUPRC stays in range, the full
multi-signal arm is at least as good as the shallow handle/text arm, the AP
implementation matches a hand calculation, and the seeded bootstrap replays
identically.
"""
import tempfile
from pathlib import Path

from bid.eval.ablation import run_ablation
from bid.eval.dataset import load_labeled, split_of
from bid.eval.metrics_eval import average_precision, bootstrap_ci
from bid.eval.run_eval import build_report
from bid.eval.scoring import imp_score
from bid.storage import ContentStore


def _rows():
    with tempfile.TemporaryDirectory() as d:
        return load_labeled(ContentStore(Path(d)))


def test_split_is_deterministic_and_nonempty_both_sides():
    rows = _rows()
    # deterministic: split_of is a pure function of the id
    for r in rows:
        assert split_of(r["candidate_id"]) == r["split"]
        assert r["split"] in {"train", "test"}
    # loading twice yields identical splits (no RNG, no wall-clock)
    rows2 = _rows()
    assert {r["candidate_id"]: r["split"] for r in rows} == {
        r["candidate_id"]: r["split"] for r in rows2
    }
    train = [r for r in rows if r["split"] == "train"]
    test = [r for r in rows if r["split"] == "test"]
    assert len(train) > 0
    assert len(test) > 0
    # both sides carry at least one positive, so the eval is meaningful
    assert any(r["truth"] for r in train)
    assert any(r["truth"] for r in test)


def test_rows_have_expected_shape():
    rows = _rows()
    assert len(rows) == 15  # same candidate set the pipeline classifies
    r = rows[0]
    assert set(r) == {"candidate_id", "brand", "signals", "truth", "split"}
    assert isinstance(r["signals"], dict)
    assert isinstance(r["truth"], bool)


def test_auprc_in_unit_interval_for_every_arm():
    rows = _rows()
    for arm in run_ablation(rows, split="test"):
        assert 0.0 <= arm["auprc"] <= 1.0
        assert 0.0 <= arm["precision_at_k"] <= 1.0
        assert 0.0 <= arm["recall"] <= 1.0


def test_full_arm_is_at_least_as_good_as_shallow_arm():
    """Core property: the multi-signal cascade (E) does not do worse than
    the shallow handle/text-only baseline (A) at separating impersonation."""
    rows = _rows()
    arms = run_ablation(rows, split="test")
    shallow = arms[0]
    full = arms[-1]
    assert shallow["key"] == "A"
    assert full["key"] == "E"
    assert full["auprc"] >= shallow["auprc"]


def test_auprc_is_monotone_non_decreasing_A_to_E():
    """Adding signal groups never lowers AUPRC on this battery (max-fusion)."""
    rows = _rows()
    auprcs = [a["auprc"] for a in run_ablation(rows, split="test")]
    for earlier, later in zip(auprcs, auprcs[1:], strict=False):
        assert later >= earlier


def test_imp_score_respects_mask_and_stays_in_range():
    sig = {
        "handle_edit_distance": 0,
        "logo_phash_hamming": 40,
        "domain_in_cti_badlist": True,
    }
    # unmasked: CTI badlist (1.0) dominates
    assert imp_score(sig, mask=()) == 1.0
    # mask out CTI -> handle distance 0 gives 1.0 too
    assert imp_score(sig, mask={"domain_in_cti_badlist"}) == 1.0
    # mask both strong signals -> only the far pHash contributes
    only_phash = imp_score(sig, mask={"domain_in_cti_badlist", "handle_edit_distance"})
    assert 0.0 <= only_phash <= 1.0
    assert only_phash < 1.0


def test_average_precision_matches_hand_example():
    # scores desc [0.9,0.8,0.7,0.6] with truths [1,0,1,0]:
    #   positive@rank1 precision 1/1, positive@rank3 precision 2/3
    #   AP = (1.0 + 2/3) / 2 = 5/6
    ap = average_precision([0.9, 0.8, 0.7, 0.6], [True, False, True, False])
    assert abs(ap - 5.0 / 6.0) < 1e-12
    # perfect ranking -> 1.0 ; no positives -> 0.0
    assert average_precision([0.9, 0.8, 0.1], [True, True, False]) == 1.0
    assert average_precision([0.9, 0.1], [False, False]) == 0.0


def test_bootstrap_ci_is_reproducible_with_same_seed():
    scores = [0.9, 0.2, 0.7, 0.1, 0.8, 0.3]
    truths = [True, False, True, False, True, False]
    a = bootstrap_ci(scores, truths, seed=123, n_boot=500)
    b = bootstrap_ci(scores, truths, seed=123, n_boot=500)
    assert a == b  # byte-identical bounds
    lo, hi = a
    assert 0.0 <= lo <= hi <= 1.0
    # a different seed is allowed to differ; bounds still valid
    c = bootstrap_ci(scores, truths, seed=999, n_boot=500)
    assert 0.0 <= c[0] <= c[1] <= 1.0


def test_report_is_byte_reproducible():
    rows = _rows()
    import json

    r1 = json.dumps(build_report(rows), sort_keys=True)
    r2 = json.dumps(build_report(rows), sort_keys=True)
    assert r1 == r2
    report = build_report(rows)
    assert report["headline"]["full_auprc"] >= report["headline"]["shallow_auprc"]
