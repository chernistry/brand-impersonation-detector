"""
Scale-test invariants: the synthetic corpus is deterministic and the pipeline
separates every attack family from the benign controls at volume, and the
deterministic rubric labels credential-solicitation as fraud (parity with the
live-model rubric).
"""
import tempfile
from pathlib import Path

from bid.classify import _solicits_credentials
from bid.eval.corpus import BENIGN_FAMILIES, POSITIVE_FAMILIES, generate_corpus
from bid.eval.scale_test import run_scale


def test_corpus_is_deterministic_and_sized():
    from bid.run_pipeline import load_brands
    n_brands = len(load_brands())
    a = generate_corpus(per_brand=100)
    b = generate_corpus(per_brand=100)
    assert len(a) == 100 * n_brands
    # same ids + same payloads on a re-run (byte-reproducible)
    ka = [(o.platform_uid, o.payload) for o, *_ in a]
    kb = [(o.platform_uid, o.payload) for o, *_ in b]
    assert ka == kb
    fams = {fam for _, _, fam, _ in a}
    assert POSITIVE_FAMILIES <= fams
    assert BENIGN_FAMILIES <= fams


def test_pipeline_separates_families_at_volume():
    from bid.run_pipeline import load_brands
    n_brands = len(load_brands())
    with tempfile.TemporaryDirectory() as d:
        rep = run_scale(Path(d), per_brand=100)
    assert rep["total"] == 100 * n_brands
    # every positive attack family is fully recalled; benign families never flagged
    for fam, row in rep["per_family"].items():
        if row["positive_family"]:
            assert row["recall"] == 1.0, f"{fam} recall {row['recall']}"
        else:
            assert row["false_positive_rate"] == 0.0, f"{fam} FPR {row['false_positive_rate']}"
    assert rep["confusion"]["fp"] == 0 and rep["confusion"]["fn"] == 0
    # fraud families are labelled fraud, not merely impersonation
    assert rep["per_family"]["cti_link"]["fraud_granularity"] == 1.0
    assert rep["per_family"]["cred_phish"]["fraud_granularity"] == 1.0


def test_credential_solicitation_detector():
    assert _solicits_credentials("DM us your account number to unlock your card.")
    assert _solicits_credentials("Security team. Confirm your card details now.")
    assert _solicits_credentials("Verify your identity here to avoid suspension.")
    assert not _solicits_credentials("Limited promotion. Tap to claim your reward now.")
    assert not _solicits_credentials("Unofficial fan account. Not affiliated.")
