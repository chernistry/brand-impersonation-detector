"""
Quantitative evaluation package (fully additive, offline, deterministic).

Purpose: a reproducible ablation
that measures whether a multi-signal cascade actually separates impersonation
from benign better than a shallow single-signal (handle/text only) baseline.

Everything here is read-only against the existing pipeline seams:
  - enumerate candidates exactly as run_pipeline does (sensors -> normalize -> dedup)
  - reuse the Stage-A signal fields (bid.filters.stage_a -> DetSignals)
  - reuse the fused-score shape from bid.feedback.recalibrate

No wall-clock, no RNG without a fixed seed, no network. Two runs are
byte-identical.
"""
from __future__ import annotations

__all__ = ["dataset", "scoring", "metrics_eval", "ablation", "run_eval"]
