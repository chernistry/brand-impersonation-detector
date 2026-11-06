"""
Reproducible-learning proof: replay a decision under its pinned policy.

    python -m bid.replay                       # prove two runs are byte-identical
    python -m bid.replay --receipt r.json       # check a receipt's policy identity

What this backs: determinism is not in tension with the feedback loop - it is what
makes the loop auditable. Every signed decision carries the `policy_version` (hash of
thresholds + classifier + code rev) that produced it. So you can:

  1. Re-run the pipeline and prove the signed evidence bundle is byte-identical
     (`bundle_digest` matches). Any non-determinism surfaces as a HASH DIVERGENCE,
     not a flaky test.
  2. Take any past receipt and prove which policy configuration produced it, and
     whether that policy still matches the live one (policy drift = hash change).

No wall-clock, no network, no RNG: FIXED_NOW + a rule-based mock classifier + a
stable ranking tiebreak make the whole pipeline reproducible.
"""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .evidence import DEFAULT_HMAC_KEY
from .models import EvidencePackage
from .policy import current_thresholds, policy_version


def _run_digest(k: int = 10) -> dict:
    from .run_pipeline import run
    with tempfile.TemporaryDirectory() as d:
        # run() prints its own report; we only need the returned anchors.
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            r = run(Path(d), DEFAULT_HMAC_KEY, k=k)
        return {"policy_version": r["policy_version"], "bundle_digest": r["bundle_digest"],
                "packages": r["packages"]}


def replay_selftest(k: int = 10) -> dict:
    """Run the pipeline twice and assert byte-identical signed evidence."""
    a = _run_digest(k)
    b = _run_digest(k)
    ok = (a["bundle_digest"] == b["bundle_digest"]) and (a["policy_version"] == b["policy_version"])
    return {"ok": ok, "policy_version": a["policy_version"],
            "bundle_digest_run1": a["bundle_digest"], "bundle_digest_run2": b["bundle_digest"],
            "packages": a["packages"],
            "divergence": None if ok else "hash divergence between two runs (non-determinism)"}


def check_receipt(path: Path) -> dict:
    """Report a receipt's pinned policy and whether it matches the live policy."""
    pkg = EvidencePackage.model_validate_json(Path(path).read_text(encoding="utf-8"))
    receipt_policy = pkg.manifest.policy_version
    # The live policy is recomputed under the receipt's own primary classifier,
    # read from the signed model trace.
    primary = next((t.model_id for t in pkg.manifest.model_trace if t.role == "primary"), None)
    live_policy = policy_version(primary) if primary else None
    return {
        "candidate_id": pkg.manifest.candidate_id,
        "model_id": primary,
        "receipt_policy_version": receipt_policy,
        "live_policy_version": live_policy,
        "same_policy": receipt_policy is not None and receipt_policy == live_policy,
        "live_thresholds": current_thresholds(),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Replay / prove reproducible decisions")
    ap.add_argument("--receipt", default=None, help="a signed receipt.json to inspect")
    ap.add_argument("--k", type=int, default=10)
    args = ap.parse_args(argv)

    print("=" * 64)
    print("REPRODUCIBLE-LEARNING REPLAY")
    print("=" * 64)

    if args.receipt:
        r = check_receipt(Path(args.receipt))
        print(f"receipt candidate : {r['candidate_id']}")
        print(f"classifier        : {r['model_id']}")
        print(f"receipt policy    : {r['receipt_policy_version']}")
        print(f"live policy       : {r['live_policy_version']}")
        print(f"same policy?      : {'YES' if r['same_policy'] else 'NO (policy drifted)'}")
        print(f"live thresholds   : {json.dumps(r['live_thresholds'])}")
        return 0

    r = replay_selftest(args.k)
    print(f"policy_version    : {r['policy_version']}")
    print(f"bundle (run 1)    : {r['bundle_digest_run1']}")
    print(f"bundle (run 2)    : {r['bundle_digest_run2']}")
    print(f"packages          : {r['packages']}")
    print(f"result            : {'REPLAY OK - byte-identical' if r['ok'] else 'DIVERGENCE: ' + r['divergence']}")
    print("=" * 64)
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
