"""
Label ledger and threshold calibration from analyst decisions. No model
training is involved: decisions only move thresholds and review order.

Three mechanisms, all keyless / no-GPU:

  1. SIGNED LABEL LEDGER. Every analyst confirm/reject is appended to an HMAC-
     chained, append-only ledger (same substrate as the evidence chain). So the
     training set itself is tamper-evident and independently verifiable - the loop
     is reproducible, so a change in behaviour can be traced to the labels that
     caused it.

  2. ACTIVE LEARNING. Rank not-yet-reviewed candidates by UNCERTAINTY (distance of
     the model confidence from the decision boundary + disagreement between the
     cheap deterministic signals and the LLM verdict). The analyst reviews the most
     informative cases first.

  3. THRESHOLD RE-CALIBRATION. From accumulated labels, sweep one cutoff on the
     fused signal score to hit a precision target on the labeled set (best F1 when
     the labels cannot reach it), and emit a versioned, hash-anchored operating
     point. The operating point orders and marks findings; it never changes a
     signed decision.

  + DRIFT DETECTION: precision@k over label batches; alert on a sustained drop.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

# Public development placeholder; set BID_LEDGER_KEY (secret store / KMS) for real use.
DEV_LEDGER_KEY = "dev-ledger-key-not-for-production"  # public placeholder
_LEDGER_KEY = os.environ.get("BID_LEDGER_KEY") or DEV_LEDGER_KEY
_GENESIS = "0" * 64


class FeedbackLabel(BaseModel):
    candidate_id: str
    brand_id: str
    label: str  # "impersonation" | "fraud" | "legit" | "fan" | "suspicious"
    decision: str  # "confirm" | "reject" | "relabel"
    analyst_id: str
    decided_at: str
    signals: dict = Field(default_factory=dict)  # frozen DetSignals at decision time
    model_label: Optional[str] = None  # what the classifier said (for disagreement stats)
    prev_hash: str = _GENESIS
    record_hmac: str = ""


def _canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


class LabelLedger:
    """Append-only, HMAC-chained ledger of analyst labels. Tamper-evident training set."""

    def __init__(self, path: Path, key: str = _LEDGER_KEY):
        self.path = Path(path)
        self._key = key
        self._records: list[FeedbackLabel] = []
        if self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    self._records.append(FeedbackLabel.model_validate_json(line))

    def _mac(self, body: dict, prev: str) -> str:
        return hmac.new(self._key.encode(), _canon(body) + prev.encode(), hashlib.sha256).hexdigest()

    def append(self, label: FeedbackLabel) -> FeedbackLabel:
        prev = self._records[-1].record_hmac if self._records else _GENESIS
        body = label.model_dump(exclude={"prev_hash", "record_hmac"})
        label.prev_hash = prev
        label.record_hmac = self._mac(body, prev)
        self._records.append(label)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as f:
            f.write(label.model_dump_json() + "\n")
        return label

    def verify(self) -> tuple[bool, str]:
        prev = _GENESIS
        for i, r in enumerate(self._records):
            body = r.model_dump(exclude={"prev_hash", "record_hmac"})
            if r.prev_hash != prev or self._mac(body, prev) != r.record_hmac:
                return False, f"ledger broken at record {i}"
            prev = r.record_hmac
        return True, f"label ledger of {len(self._records)} record(s) verified"

    def labels(self) -> list[FeedbackLabel]:
        return list(self._records)

    def stats(self) -> dict:
        confirms = sum(1 for r in self._records if r.decision == "confirm")
        disagree = sum(1 for r in self._records
                       if r.model_label and r.model_label != r.label)
        return {"total": len(self._records), "confirms": confirms,
                "rejects": len(self._records) - confirms,
                "model_analyst_disagreements": disagree}


# --- active learning -------------------------------------------------------

_POSITIVE = {"impersonation", "fraud"}


def uncertainty(confidence: float, model_label: str, signals: dict) -> float:
    """Higher = more informative to review next. Combines (a) closeness of the model
    confidence to the 0.5 boundary and (b) disagreement between the cheap deterministic
    signals and the model verdict."""
    boundary = 1.0 - abs(confidence - 0.5) * 2.0  # 1.0 at 0.5, 0.0 at 0/1
    # deterministic "vote": do the cheap signals scream impersonation?
    det_positive = bool(
        signals.get("domain_intention_mismatch")
        or signals.get("domain_in_cti_badlist")
        or (signals.get("logo_phash_hamming") is not None and signals["logo_phash_hamming"] <= 10)
        or (signals.get("handle_edit_distance") is not None and signals["handle_edit_distance"] <= 2)
    )
    model_positive = model_label in _POSITIVE
    disagreement = 1.0 if det_positive != model_positive else 0.0
    return round(0.6 * boundary + 0.4 * disagreement, 4)


def rank_for_review(items: list[dict]) -> list[dict]:
    """items: [{candidate_id, confidence, model_label, signals}] -> sorted most-informative first."""
    for it in items:
        it["uncertainty"] = uncertainty(it["confidence"], it.get("model_label", ""), it.get("signals", {}))
    return sorted(items, key=lambda x: (-x["uncertainty"], x["candidate_id"]))


# --- threshold re-calibration ----------------------------------------------


def fused_score(sig: dict) -> float:
    """A single fused evidence score in [0,1]; higher = more impersonation-like.
    The operating point (auto-file vs route-to-analyst) is a threshold on THIS
    score, so recalibrate() and the live pipeline share one definition."""
    parts = []
    if sig.get("handle_edit_distance") is not None:
        parts.append(max(0.0, 1.0 - sig["handle_edit_distance"] / 6.0))
    if sig.get("handle_similarity") is not None:
        parts.append(float(sig["handle_similarity"]))
    if sig.get("handle_contains_brand"):
        parts.append(0.85)
    if sig.get("logo_phash_hamming") is not None:
        parts.append(max(0.0, 1.0 - sig["logo_phash_hamming"] / 32.0))
    if sig.get("logo_clip_cosine") is not None:
        parts.append(float(sig["logo_clip_cosine"]))
    if sig.get("domain_intention_mismatch"):
        parts.append(0.9)
    if sig.get("domain_in_cti_badlist"):
        parts.append(1.0)
    return max(parts) if parts else 0.0


def recalibrate(labeled: list[dict], precision_target: float = 0.9) -> dict:
    """labeled: [{signals, truth(bool positive)}]. Sweep a single fused visual/handle
    cutoff and pick the operating point that hits the precision target at max recall.
    Returns a versioned, hash-anchored threshold config (reproducible learning)."""
    score = fused_score
    rows = [(score(x["signals"]), bool(x["truth"])) for x in labeled]
    total_pos = sum(1 for _, t in rows if t) or 1
    at_target = {"threshold": None, "precision": 0.0, "recall": 0.0, "f1": 0.0}
    best_f1 = {"threshold": 0.5, "precision": 0.0, "recall": 0.0, "f1": -1.0}
    for i in range(0, 101):
        thr = i / 100.0
        tp = sum(1 for s, t in rows if s >= thr and t)
        fp = sum(1 for s, t in rows if s >= thr and not t)
        prec = tp / (tp + fp) if (tp + fp) else 1.0
        rec = tp / total_pos
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        point = {"threshold": round(thr, 3), "precision": round(prec, 3),
                 "recall": round(rec, 3), "f1": round(f1, 3)}
        if prec >= precision_target and rec > at_target["recall"]:
            at_target = point
        if f1 > best_f1["f1"]:
            best_f1 = point
    # Prefer the max-recall point at the precision target; if the data is too weak to
    # hit it (common with a handful of labels), fall back to the best-F1 operating
    # point instead of a sterile default, and say so via met_target.
    met = at_target["threshold"] is not None
    best = at_target if met else best_f1
    cfg = {"decision_threshold": best["threshold"], "precision_target": precision_target,
           "met_target": met,
           "achieved": {"precision": best["precision"], "recall": best["recall"], "f1": best["f1"]},
           "n_labels": len(labeled)}
    cfg["version_hash"] = hashlib.sha256(_canon(cfg)).hexdigest()[:16]
    return cfg


# --- drift detection -------------------------------------------------------


def drift_check(precision_history: list[float], window: int = 3, drop: float = 0.1) -> dict:
    """Alert if the recent mean precision fell by `drop` vs the earlier mean."""
    if len(precision_history) < 2 * window:
        return {"alert": False, "reason": "not enough history"}
    early = sum(precision_history[:window]) / window
    recent = sum(precision_history[-window:]) / window
    return {"alert": (early - recent) >= drop, "early_mean": round(early, 3),
            "recent_mean": round(recent, 3), "delta": round(recent - early, 3)}
