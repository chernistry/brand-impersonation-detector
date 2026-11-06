"""
Pins prompt and metric fixes (root causes confirmed by an audit):

1. Null-link candidates must NOT expose vacuous link-domain signals to the live
   model (the confirmed cause of spurious link-domain reasoning on null links), and the prompt
   must carry the label rubric + calibration instruction.
2. precision_at_k is strict (divides by k) and scores ONLY labeled candidates,
   so broad-mode live candidates cannot silently pollute the metric.
"""
from datetime import datetime, timezone

from bid.classify import _build_prompt
from bid.metrics import precision_at_k
from bid.models import Brand, Candidate, DetSignals, Verdict

_NOW = datetime(2026, 7, 3, 12, 0, 0, tzinfo=timezone.utc)


def _brand():
    return Brand(id="b", name="Bank X", official_handles=["bankx"],
                 official_logo_hashes=[], regions=["US"],
                 aliases=["Bank X"], official_domains=["bankx.test"])


def _cand(link=None):
    return Candidate(id="cand_t_1", brand_id="b", sensor_name="s", platform="p",
                     platform_uid="u", handle="bank_x_promo", display_name="Bank X Promo",
                     bio="Special offer", link_in_bio_url=link, dedup_key="dk",
                     raw_observation_ref="r" * 64, first_seen=_NOW)


def test_prompt_hides_link_signals_when_no_link():
    p = _build_prompt(_cand(link=None), _brand(), DetSignals())
    assert "NOT APPLICABLE" in p and "NO link_in_bio_url" in p
    # the vacuous booleans must not be shown at all
    assert "candidate_link_domain_is_official" not in p
    assert "domain_in_cti_badlist" not in p
    assert "link_in_bio_url: (none)" in p


def test_prompt_shows_link_signals_when_link_present():
    sig = DetSignals(domain_in_cti_badlist=True, domain_is_legit=False,
                     domain_intention_mismatch=True)
    p = _build_prompt(_cand(link="https://bankx-verify.test/x"), _brand(), sig)
    assert "domain_in_cti_badlist: True" in p
    assert "candidate_link_domain_is_official: False" in p
    assert "NOT APPLICABLE" not in p


def test_prompt_carries_rubric_and_calibration():
    p = _build_prompt(_cand(), _brand(), DetSignals())
    assert "LABEL RUBRIC" in p
    assert "apply ONLY when a link is present" in p
    assert "Do NOT default to 0.9" in p
    # injection defenses intact
    assert "untrusted" in p and "<data_" in p


def _verdict(cid, label="impersonation", conf=0.9):
    return Verdict(candidate_id=cid, label=label, confidence=conf,
                   signals=DetSignals(), reasoning="", model_id="m",
                   prompt_hash="p", input_hashes=[])


def test_precision_at_k_is_strict_and_labeled_only():
    truth = {"a": True, "b": True, "c": False}
    ranked = [_verdict("a"), _verdict("unlabeled_1"), _verdict("b"),
              _verdict("unlabeled_2"), _verdict("c")]
    # unlabeled candidates are skipped entirely: labeled order is a, b, c
    assert precision_at_k(ranked, truth, 2) == 1.0          # a, b -> 2/2
    assert precision_at_k(ranked, truth, 3) == 2 / 3        # a, b, c -> 2/3
    # strict: fewer labeled than k degrades instead of inflating
    assert precision_at_k(ranked, truth, 5) == 2 / 5
    assert precision_at_k([], truth, 5) == 0.0
