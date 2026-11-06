"""
Policy identity - the hash that makes learning reproducible.

Every verdict already binds `model_id`, `prompt_hash` and the input asset hashes
(see models.Verdict). The one thing that was NOT yet a single anchored value is
the DECISION POLICY: the thresholds that route a candidate and the classifier
identity behind it. `policy_version()` folds those into one short, canonical hash
and the signer binds it into the HMAC-chained manifest.

Why this matters (reproducible learning): the feedback loop
(feedback.recalibrate) emits new thresholds over time. If every signed decision
carries the `policy_version` that produced it, you can replay any past decision
under its exact policy and prove which configuration made it - determinism is not
in tension with learning, it is what makes the learning auditable. A drift in the
policy shows up as a hash change, not as a silently different verdict.

Deterministic: no wall-clock, no environment beyond the pinned constants and the
classifier model id. Two processes on the same config compute the same version.
"""
from __future__ import annotations

import hashlib
import json

from . import filters
from .injection import _THRESHOLD as _INJ_THRESHOLD

# Bumped by hand when the decision LOGIC (not the thresholds) changes shape, so a
# threshold-identical policy on a different code revision still versions apart.
CODE_REV = "bid-policy-v1"


def current_thresholds() -> dict:
    """The live routing/decision knobs, read from their source of truth."""
    return {
        "handle_keep_max": filters.HANDLE_KEEP_MAX,
        "handle_sim_min": filters.HANDLE_SIM_MIN,
        "logo_keep_max": filters.LOGO_KEEP_MAX,
        "clip_keep_min": filters.CLIP_KEEP_MIN,
        "injection_threshold": _INJ_THRESHOLD,
    }


def data_versions() -> dict:
    """Version identity of the reference DATA a verdict silently depends on: the
    homoglyph fold table and the Public Suffix List. A monthly PSL refresh or a
    confusable-table bump can change a verdict while the thresholds stay put; by
    hashing these into policy_version, that drift surfaces as a hash change instead
    of a silent, unreproducible verdict flip."""
    # fold table (our leet + strip + fallback confusables) - a stable local hash
    fold = json.dumps({
        "leet": getattr(filters, "_LEET", {}),
        "strip": sorted(getattr(filters, "_STRIP", set())),
        "fallback": getattr(filters, "_FALLBACK_HOMOGLYPHS", {}),
    }, sort_keys=True, ensure_ascii=True)
    fold_h = hashlib.sha256(fold.encode()).hexdigest()[:12]
    versions = {"fold_table": fold_h}
    for lib in ("confusable_homoglyphs", "tldextract"):
        try:
            from importlib.metadata import version as _v
            versions[lib] = _v(lib)
        except Exception:
            versions[lib] = "unknown"
    return versions


def policy_bundle(model_id: str, thresholds: dict | None = None) -> dict:
    """The full, canonical policy identity: thresholds + classifier + reference-data
    versions + code rev. Everything a verdict is a deterministic function of."""
    return {
        "code_rev": CODE_REV,
        "model_id": model_id,
        "thresholds": thresholds if thresholds is not None else current_thresholds(),
        "data_versions": data_versions(),
    }


def policy_version(model_id: str, thresholds: dict | None = None) -> str:
    """Short canonical hash of the policy bundle. Stable across processes."""
    bundle = policy_bundle(model_id, thresholds)
    canon = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canon).hexdigest()[:16]
