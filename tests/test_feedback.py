"""
Feedback-loop invariants. Run: pytest -q  (from the repo root).

Pins the things that would break reproducible learning if they
regressed: the label ledger is HMAC-chained and tamper-evident, active learning
surfaces the most-uncertain case first, recalibration is deterministic and
versioned, drift fires on a sustained precision drop, and the api glue signs a
chained evidence receipt on a live analyst confirm.
"""
import tempfile
from pathlib import Path

from bid.feedback import (
    FeedbackLabel,
    LabelLedger,
    drift_check,
    rank_for_review,
    recalibrate,
    uncertainty,
)


def _label(cid, label="impersonation", decision="confirm", model_label="impersonation"):
    return FeedbackLabel(candidate_id=cid, brand_id="b", label=label, decision=decision,
                         analyst_id="a", decided_at="2026-01-01T00:00:00Z",
                         signals={"domain_intention_mismatch": True}, model_label=model_label)


def test_ledger_chains_and_verifies():
    with tempfile.TemporaryDirectory() as d:
        led = LabelLedger(Path(d) / "l.jsonl")
        led.append(_label("x1"))
        led.append(_label("x2", label="legit", decision="reject"))
        ok, reason = led.verify()
        assert ok is True
        assert "2 record" in reason
        # genesis-chained: second record's prev_hash is the first record's hmac
        recs = led.labels()
        assert recs[0].prev_hash == "0" * 64
        assert recs[1].prev_hash == recs[0].record_hmac


def test_ledger_survives_reload():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "l.jsonl"
        LabelLedger(p).append(_label("x1"))
        # a fresh instance reads the append-only file back and still verifies
        assert LabelLedger(p).verify()[0] is True


def test_ledger_detects_tamper():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "l.jsonl"
        led = LabelLedger(p)
        led.append(_label("x1"))
        led.append(_label("x2"))
        # flip a stored label after the fact -> chain must break
        lines = p.read_text().splitlines()
        lines[0] = lines[0].replace('"impersonation"', '"legit"', 1)
        p.write_text("\n".join(lines) + "\n")
        ok, reason = LabelLedger(p).verify()
        assert ok is False
        assert "broken at record 0" in reason


def test_active_learning_orders_by_uncertainty():
    items = [
        {"candidate_id": "sure", "confidence": 0.98, "model_label": "fraud",
         "signals": {"domain_intention_mismatch": True}},         # confident + agreeing -> low
        {"candidate_id": "boundary", "confidence": 0.5, "model_label": "legit",
         "signals": {}},                                          # right on the boundary -> high
        {"candidate_id": "disagree", "confidence": 0.9, "model_label": "legit",
         "signals": {"domain_intention_mismatch": True}},         # signals scream, model says legit -> high
    ]
    ordered = [i["candidate_id"] for i in rank_for_review(items)]
    assert ordered[0] in {"boundary", "disagree"}
    assert ordered[-1] == "sure"


def test_uncertainty_bounds():
    # exactly on the boundary with a disagreement is the max-uncertainty case
    u = uncertainty(0.5, "legit", {"domain_intention_mismatch": True})
    assert 0.99 <= u <= 1.0


def test_recalibrate_is_deterministic_and_versioned():
    labeled = [
        {"signals": {"handle_edit_distance": 1, "domain_intention_mismatch": True}, "truth": True},
        {"signals": {"logo_phash_hamming": 2}, "truth": True},
        {"signals": {"handle_edit_distance": 8}, "truth": False},
        {"signals": {}, "truth": False},
    ]
    a = recalibrate(labeled, precision_target=0.9)
    b = recalibrate(labeled, precision_target=0.9)
    assert a == b                                   # byte-for-byte reproducible
    assert a["achieved"]["precision"] >= 0.9
    assert len(a["version_hash"]) == 16


def test_drift_fires_on_sustained_drop():
    hot = drift_check([0.95, 0.94, 0.93, 0.70, 0.68, 0.66], window=3, drop=0.1)
    assert hot["alert"] is True
    calm = drift_check([0.9, 0.9, 0.9, 0.9, 0.9, 0.9], window=3, drop=0.1)
    assert calm["alert"] is False


def test_console_decisions_feed_the_label_ledger(tmp_path):
    from bid.api import decide, feedback_summary, run_pipeline_api

    view = run_pipeline_api(tmp_path, k=10)
    queue = [c for b in view["brands"] for c in b["queue"]]
    for c in queue[:4]:
        r = decide(tmp_path, c["candidate_id"], "reject" if c["label"] == "legit" else "confirm", "analyst_01")
        assert r["feedback"]["ledger_verified"] is True
    s = feedback_summary(tmp_path)
    assert s["chain_ok"] is True
    assert s["stats"]["total"] == 4
    assert s["recalibration"] is not None
    assert len(s["recalibration"]["version_hash"]) == 16
