"""
Reproducible-learning invariants: policy identity + byte-identical replay.

Pins: same config -> same policy_version, same inputs ->
byte-identical signed evidence bundle, and a changed threshold -> a changed
policy_version (drift is a hash change, not a silent verdict change).
"""
import tempfile
from pathlib import Path

from bid import policy
from bid.evidence import DEFAULT_HMAC_KEY
from bid.models import EvidencePackage
from bid.replay import check_receipt, replay_selftest
from bid.run_pipeline import run


def test_policy_version_is_stable_and_sensitive():
    base = policy.policy_version("mock-deterministic-v1")
    # same inputs -> identical
    assert base == policy.policy_version("mock-deterministic-v1")
    # a different classifier -> different policy
    assert base != policy.policy_version("gemini-2.5-flash")
    # a threshold change -> different policy (drift shows up as a hash change)
    drifted = dict(policy.current_thresholds())
    drifted["handle_keep_max"] = drifted["handle_keep_max"] + 1
    assert base != policy.policy_version("mock-deterministic-v1", drifted)


def test_replay_is_byte_identical():
    r = replay_selftest(k=10)
    assert r["ok"] is True
    assert r["bundle_digest_run1"] == r["bundle_digest_run2"]
    assert len(r["policy_version"]) == 16


def test_receipt_carries_policy_version():
    with tempfile.TemporaryDirectory() as d:
        store = Path(d)
        run(store, DEFAULT_HMAC_KEY, k=10)
        receipt = store / "receipt_sample.json"
        assert receipt.exists()
        pkg = EvidencePackage.model_validate_json(receipt.read_text())
        assert pkg.manifest.policy_version  # non-empty
        r = check_receipt(receipt)
        # the receipt was produced under the live mock policy
        assert r["same_policy"] is True
